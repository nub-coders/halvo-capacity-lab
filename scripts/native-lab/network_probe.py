#!/usr/bin/env python3
"""Synthetic dual-stack packet-policy experiment, only in the disposable QEMU guest.

Run after probe.py prepares its sandbox mounts. Public/admin destinations are
guest-only benchmark/documentation addresses, never real endpoints. This does
not prove production firewall policy, DNS/rebinding handling, or build egress.
Trusted servers are canaries; only connection clients execute inside NsJail.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

from guard import require_lab
from probe import APP, LAB, OUT, configuration

PORT = 18080
SERVER = r'''
import json, selectors, socket, sys
selector = selectors.DefaultSelector()
for address, port in json.loads(sys.argv[1]):
    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port)); sock.listen(64)
    selector.register(sock, selectors.EVENT_READ)
while True:
    for key, _ in selector.select(1):
        client, _ = key.fileobj.accept()
        with client:
            client.settimeout(1)
            try: client.sendall(b'halvo-packet-canary')
            except OSError: pass
'''
CLIENT = r'''
import json, socket, sys
from pathlib import Path
if sys.argv[2] == 'jailed':
    status = Path('/proc/self/status').read_text()
    assert 'CapEff:\t0000000000000000' in status
    assert 'NoNewPrivs:\t1' in status
    assert 'Seccomp:\t2' in status
results = []
for name, address, port in json.loads(sys.argv[1]):
    result = dict(name=name, address=address, port=port, connected=False, banner=False)
    with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET) as sock:
        sock.settimeout(0.7)
        try:
            sock.connect((address, port)); result['connected'] = True
            result['banner'] = sock.recv(64) == b'halvo-packet-canary'
        except OSError as error: result['error'] = type(error).__name__
    results.append(result)
print('NETWORK_RESULT=' + json.dumps(results))
'''


def call(*args, check=True, input=None, timeout=15):
    return subprocess.run(args, check=check, input=input, text=True, capture_output=True, timeout=timeout)


def result_rows(output):
    rows = [line.removeprefix("NETWORK_RESULT=") for line in output.splitlines()
            if line.startswith("NETWORK_RESULT=")]
    if len(rows) != 1:
        raise RuntimeError("Client produced no unique result; refusing an isolation pass")
    return json.loads(rows[0])


def main():
    if os.geteuid() != 0 or require_lab() != "qemu":
        raise SystemExit("Packet experiment requires root in the disposable QEMU lab")
    if not all(path.is_dir() for path in (LAB / "root", APP, Path("/quota/app-a"))):
        raise SystemExit("Run the default smoke setup before the packet experiment")
    tag = uuid.uuid4().hex[:8]
    table = f"halvo_lab_{tag}"
    namespaces, links, units, saved = [], [], [], {}
    installed = False
    config = LAB / f"network-{tag}.cfg"
    report = {"passed": False, "scope": __doc__, "checks": [], "cleanup_errors": []}

    def unit(label, command, wait=False):
        name = f"halvo-net-{tag}-{label}.service"
        units.append(name)
        args = ["systemd-run", "--quiet", "--collect", f"--unit={name}",
                "--property=Type=exec", "--property=MemoryMax=128M", "--property=MemorySwapMax=0",
                "--property=CPUQuota=50%", "--property=TasksMax=16", "--property=LimitNOFILE=256",
                "--property=KillMode=control-group", "--property=TimeoutStopSec=3s",
                f"--property=RuntimeMaxSec={'25s' if wait else '180s'}"]
        return call(*args, *(["--wait", "--pipe"] if wait else []), *command, timeout=30).stdout

    def client(label, targets, namespace=None):
        command = ["/usr/bin/python3", "-c", CLIENT, json.dumps(targets), "jailed" if namespace else "trusted"]
        if namespace:
            command = ["ip", "netns", "exec", namespace, "/usr/local/bin/nsjail",
                       "--config", str(config), "--", *command]
            return result_rows(unit(label, command, True))
        return result_rows(call(*command, timeout=20).stdout)

    def record(phase, origin, rows, allowed):
        for row in rows:
            expected = row["name"] in allowed
            row.update(phase=phase, origin=origin, expected_allowed=expected,
                       passed=(row["connected"] and row["banner"]) if expected else not row["connected"])
        report["checks"].extend(rows)
        if not all(row["passed"] for row in rows):
            raise RuntimeError(f"{phase} failed for {origin}; see per-case results")

    def deadline(_signal, _frame):
        raise TimeoutError("Packet experiment exceeded 180 seconds")

    try:
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(180)
        config.write_text(configuration(25) + "clone_newnet: false\n")
        for name in ("ipv4/ip_forward", "ipv6/conf/all/forwarding"):
            path = Path("/proc/sys/net") / name
            saved[path] = path.read_text()
            path.write_text("1\n")
        fixture = {}
        for index, name in enumerate(("a", "b", "ingress", "public", "platform"), 1):
            namespace, host, peer = f"halvo-{tag}-{name}", f"hn{tag}{index}", f"pn{tag}{index}"
            call("ip", "netns", "add", namespace); namespaces.append(namespace)
            call("ip", "link", "add", host, "type", "veth", "peer", "name", peer); links.append(host)
            call("ip", "link", "set", peer, "netns", namespace)
            v4, gateway4 = f"10.231.{index}.2", f"10.231.{index}.1"
            v6, gateway6 = f"fd42:231:{index}::2", f"fd42:231:{index}::1"
            for prefix, interface, addresses in (([], host, (gateway4, gateway6)),
                                                 (["-n", namespace], peer, (v4, v6))):
                call("ip", *prefix, "addr", "add", addresses[0] + "/30", "dev", interface)
                call("ip", *prefix, "-6", "addr", "add", addresses[1] + "/64", "dev", interface, "nodad")
                call("ip", *prefix, "link", "set", interface, "up")
            call("ip", "-n", namespace, "link", "set", "lo", "up")
            call("ip", "-n", namespace, "route", "add", "default", "via", gateway4)
            call("ip", "-n", namespace, "-6", "route", "add", "default", "via", gateway6)
            fixture[name] = dict(ns=namespace, host=host, v4=v4, v6=v6, gateway4=gateway4, gateway6=gateway6)

        addresses = {
            "public": ("198.18.0.2", "2001:db8:100::2"),
            "admin": ("198.19.0.2", "2001:db8:200::2"),
            "private": ("10.254.254.254", "fd42:feed::254"),
            "metadata": ("169.254.169.254", "fd00:ec2::254"),
            "cross-tenant": (fixture["b"]["v4"], fixture["b"]["v6"]),
            "guest-host": (fixture["a"]["gateway4"], fixture["a"]["gateway6"]),
        }
        endpoints = {name: [] for name in (*fixture, "host")}
        outgoing = []
        for name, pair in addresses.items():
            destination = "public" if name == "public" else "platform"
            if name == "cross-tenant": destination = "b"
            if name == "guest-host": destination = "host"
            for family, address in zip((4, 6), pair):
                outgoing.append((f"{name}-v{family}", address, PORT))
                endpoints[destination].append((address, PORT))
                if destination in ("public", "platform"):
                    item = fixture[destination]
                    flags, suffix, gateway = (["-6"], "/128", item["v6"]) if ":" in address else ([], "/32", item["v4"])
                    call("ip", "-n", item["ns"], *flags, "addr", "add", address + suffix, "dev", "lo")
                    call("ip", *flags, "route", "add", address + suffix, "via", gateway, "dev", item["host"])
        ingress = [(f"ingress-{port}-v{family}", fixture["a"][f"v{family}"], port)
                   for port in (PORT, PORT + 1) for family in (4, 6)]
        endpoints["a"] = [(address, port) for _, address, port in ingress]
        for name, listeners in endpoints.items():
            if not listeners: continue
            command = ["/usr/bin/python3", "-c", SERVER, json.dumps(listeners)]
            if name != "host": command = ["ip", "netns", "exec", fixture[name]["ns"], *command]
            unit(f"server-{name}", command)
        all_targets = outgoing + ingress
        ready_until = time.monotonic() + 15
        while True:
            ready = client("ready", all_targets)
            if all(row["connected"] and row["banner"] for row in ready): break
            if time.monotonic() >= ready_until: raise RuntimeError("Not all canaries became reachable")
            time.sleep(0.2)
        record("baseline", "app-a", client("before-a", outgoing, fixture["a"]["ns"]), {x[0] for x in outgoing})
        record("baseline", "ingress", client("before-ingress", ingress, fixture["ingress"]["ns"]), {x[0] for x in ingress})

        app_links = ', '.join(json.dumps(fixture[name]["host"]) for name in ("a", "b"))
        call("nft", "create", "table", "inet", table); installed = True
        rules = f'''table inet {table} {{
counter blocked_forward {{ }}
counter blocked_input {{ }}
chain forward {{ type filter hook forward priority -50; policy accept;
 iifname {{ {app_links} }} ct state established,related accept
 oifname {{ {app_links} }} ct state established,related accept
 iifname {{ {app_links} }} ip daddr 198.18.0.2 tcp dport {PORT} accept
 iifname {{ {app_links} }} ip6 daddr 2001:db8:100::2 tcp dport {PORT} accept
 iifname "{fixture['ingress']['host']}" oifname "{fixture['a']['host']}" tcp dport {PORT} accept
 iifname {{ {app_links} }} counter name blocked_forward drop
 oifname {{ {app_links} }} counter name blocked_forward drop
}}
chain input {{ type filter hook input priority -50; policy accept;
 iifname {{ {app_links} }} ct state established,related accept
 iifname {{ {app_links} }} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept
 iifname {{ {app_links} }} counter name blocked_input drop
}}
}}'''
        call("nft", "-f", "-", input=rules)
        report["policy"] = rules
        record("filtered", "app-a", client("after-a", outgoing, fixture["a"]["ns"]), {"public-v4", "public-v6"})
        record("filtered", "ingress", client("after-ingress", ingress, fixture["ingress"]["ns"]),
               {f"ingress-{PORT}-v4", f"ingress-{PORT}-v6"})
        record("canaries-still-live", "trusted-guest", client("live", all_targets), {x[0] for x in all_targets})
        counters = json.loads(call("nft", "-j", "list", "table", "inet", table).stdout)["nftables"]
        report["drop_packets"] = {item["counter"]["name"]: item["counter"]["packets"]
                                  for item in counters if "counter" in item}
        report["passed"] = all(report["drop_packets"].get(name, 0) > 0 for name in ("blocked_forward", "blocked_input"))
    except Exception as error:
        report["passed"] = False
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        report["error"] = f"{type(error).__name__}: {detail}"
    finally:
        signal.alarm(0)
        cleanup_deadline = time.monotonic() + 90
        def cleanup_call(*args, check=True):
            remaining = cleanup_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Packet cleanup exceeded its 90 second budget")
            return call(*args, check=check, timeout=min(15, remaining))
        def cleanup(*args):
            try: cleanup_call(*args); return True
            except Exception as error: report["cleanup_errors"].append(str(error)); return False
        for name in units:
            # --collect already removed successfully completed client units.
            try: loaded = cleanup_call("systemctl", "show", name, "--property=LoadState", "--value", check=False).stdout.strip()
            except Exception as error:
                report["cleanup_errors"].append(str(error)); loaded = "unknown"
            if loaded != "not-found" and not cleanup("systemctl", "stop", name):
                cleanup("systemctl", "kill", "--kill-whom=all", "--signal=KILL", name)
                cleanup("systemctl", "stop", name)
        if installed: cleanup("nft", "delete", "table", "inet", table)
        for namespace in reversed(namespaces): cleanup("ip", "netns", "delete", namespace)
        for link in links:
            try: exists = cleanup_call("ip", "link", "show", link, check=False).returncode == 0
            except Exception as error:
                report["cleanup_errors"].append(str(error)); exists = True
            if exists: cleanup("ip", "link", "delete", link)
        for path, value in saved.items():
            try: path.write_text(value)
            except OSError as error: report["cleanup_errors"].append(str(error))
        try: config.unlink(missing_ok=True)
        except OSError as error: report["cleanup_errors"].append(str(error))
        report["passed"] = report["passed"] and not report["cleanup_errors"]
        OUT.mkdir(exist_ok=True)
        (OUT / "network.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
