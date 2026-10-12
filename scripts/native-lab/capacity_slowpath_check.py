#!/usr/bin/env python3
"""Host loopback qualification with delayed/stalled HTTP, never capacity evidence.

Uses the exact external client and scheduler against asynchronous synthetic
servers. No VM, tenant, cgroup, Docker daemon or non-loopback listener is used.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time

import capacity
import capacity_async_client
import capacity_external as external
import capacity_preflight


class Canary:
    def __init__(self, mode):
        self.mode = mode
        self.loop = None
        self.ports = {}
        self.servers = []
        self.writers = set()
        self.tasks = set()
        self.error = None
        self.ready = threading.Event()
        self.requests = {route: 0 for route in capacity.ROUTE_ORDER}
        self.peak_connections = 0
        self.thread = threading.Thread(target=self._thread, daemon=True)

    async def _handle(self, reader, writer, route):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.peak_connections = max(self.peak_connections, len(self.writers))
        try:
            while True:
                await reader.readuntil(b"\r\n\r\n")
                self.requests[route] += 1
                if self.mode == "stall":
                    await reader.read()  # Only client deadline/EOF releases it.
                    return
                if route == "python":
                    await asyncio.sleep(8)
                body = capacity.FIXTURES[route]["response"].encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                             + b"\r\n\r\n" + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def _start(self):
        for route in capacity.ROUTE_ORDER:
            async def handle(reader, writer, route=route):
                await self._handle(reader, writer, route)
            server = await asyncio.start_server(handle, "127.0.0.1", 0,
                                                limit=16384, backlog=4096)
            self.servers.append(server)
            self.ports[route] = server.sockets[0].getsockname()[1]

    async def _close(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for writer in tuple(self.writers):
            writer.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _thread(self):
        self.loop = asyncio.new_event_loop()
        try:
            self.loop.run_until_complete(self._start())
            self.ready.set()
            self.loop.run_forever()
        except Exception as error:
            self.error = type(error).__name__
            self.ready.set()
        finally:
            self.loop.run_until_complete(self._close())
            self.loop.close()

    def start(self):
        self.thread.start()
        if not self.ready.wait(5) or self.error:
            raise capacity.GeneratorBottleneck("synthetic slowpath server startup failed")

    def close(self):
        if self.loop is not None and self.loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self._close(), self.loop)
            future.result(timeout=5)
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        return {"passed": not self.thread.is_alive() and not self.writers and not self.tasks and not self.error,
                "server_thread_stopped": not self.thread.is_alive(),
                "remaining_connections": len(self.writers), "remaining_tasks": len(self.tasks)}


def qualify(mode, rate, duration):
    canary = Canary(mode)
    pool = None
    result = {"mode": mode, "rate_per_second": rate, "duration_seconds": duration,
              "synthetic": True, "passed": False, "errors": []}
    try:
        canary.start()
        manager = capacity_preflight.SyntheticSupervisor()
        pool = external.ExternalPool(manager, canary.ports)
        pool.start()
        rows, summary = capacity.run_phase(manager, pool, rate, duration, "slowpath-" + mode, 0)
        result.update(summary=summary, raw_outcomes=rows)
        if len(rows) != rate * duration or any(row["client_queue_lag_ms"] > 2000 for row in rows):
            raise capacity.GeneratorBottleneck("slowpath count/queue evidence differs")
        if mode == "delay" and summary["failed"]:
            raise capacity.GeneratorBottleneck("delayed requests did not all complete successfully")
        if mode == "stall" and any(row["error"] != "timeout" or row["ok"]
                                   or not 30000 <= row["latency_ms"] <= 30500 for row in rows):
            raise capacity.GeneratorBottleneck("stalled request deadlines/outcomes differ")
        if mode == "stall" and canary.peak_connections < 3800:
            raise capacity.GeneratorBottleneck("stall test did not exercise the declared concurrency")
        result["passed"] = True
    except Exception as error:
        result["errors"].append(capacity.describe_error(error))
        result["partial_phase"] = getattr(error, "phase_evidence", None)
    finally:
        if pool is not None:
            result["client_cleanup"] = pool.close()
        result["server_cleanup"] = canary.close()
        result["requests_received"] = dict(canary.requests)
        result["peak_connections"] = canary.peak_connections
        if result.get("client_cleanup", {}).get("passed") is not True or not result["server_cleanup"]["passed"]:
            result["passed"] = False
    return result


def collect():
    external._check_affinity(external._affinity(), external.HOST_CPUS)
    capacity_async_client.ensure_descriptor_limit()  # Synthetic server process only.
    report = {"scope": "load-generator-slow-response-selfcheck", "production": False,
              "capacity_evidence": False, "phase0_complete": False,
              "started_at": datetime.now(timezone.utc).isoformat(), "passed": False,
              **capacity_preflight.CLIENT_PROFILE,
              "source_sha256": {name: capacity.file_digest(Path(__file__).with_name(name))
                  for name in (*external.SOURCE_FILES, "capacity_slowpath_check.py")},
              "stages": []}
    for mode, rate, duration in (("delay", 16, 12), ("stall", 128, 35)):
        result = qualify(mode, rate, duration)
        report["stages"].append(result)
        if not result["passed"]:
            break
    report["passed"] = len(report["stages"]) == 2 and all(case["passed"] for case in report["stages"])
    report["ended_at"] = datetime.now(timezone.utc).isoformat()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        parser.error("output must name a new file in an existing directory")
    # Claim a new result before running, retaining failures under their own name.
    with args.output.open("x", encoding="utf-8") as stream:
        report = collect()
        json.dump(report, stream, allow_nan=False, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "passed": report["passed"],
                      "scope": report["scope"], "capacity_evidence": False}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
