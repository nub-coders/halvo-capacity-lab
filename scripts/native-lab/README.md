# Docker-free Phase 0 lab

This is an isolated experiment for [the migration plan](../../docs/docker-free-migration-plan.md), not a production runner or a backend switch. It never connects to Halvo's database, starts its schedulers, or changes its routes. The current app stays on Docker until the user explicitly requests cutover. Results and remaining gates belong in [the experiment report](../../docs/docker-free-phase0-report.md).

## Run

On an Ubuntu 24.04 or 26.04 x86-64 host with root access, network access, and several GB of free disk:

```sh
# Read-only host information; --strict intentionally fails on the existing Docker host.
python3 scripts/native-preflight.py --strict

# Download/extract tools locally and prepare a pinned Ubuntu cloud image, without booting.
sudo bash scripts/native-lab/vm.sh --prepare /var/tmp/halvo-native-vm-phase0

# Boot, provision, run the bounded checks, verify reboot, and collect results.
sudo bash scripts/native-lab/vm.sh /var/tmp/halvo-native-vm-phase0

# Repeat checks in the same already-provisioned guest (verifies fixtures/runtime first).
sudo bash scripts/native-lab/vm.sh --resume /var/tmp/halvo-native-vm-phase0

# Repeat only packet checks after a completed smoke setup, keeping their result separate.
sudo bash scripts/native-lab/vm.sh --network-only /var/tmp/halvo-native-vm-phase0

# Build the checksum-pinned python runtime tree from runtime-tree-manifest.json
# inside the already-provisioned guest (idempotent: a completed build is reused).
sudo bash scripts/native-lab/vm.sh --runtime-tree-only /var/tmp/halvo-native-vm-phase0
```

The launcher downloads QEMU and its missing libraries into its own directory; it does not install host packages or modify host services/firewall rules. It uses software emulation because nested KVM is unavailable on the inspected host. The guest has 2 vCPUs, 2.5 GiB RAM, a sparse 16 GiB disk, a bounded lifetime, no shared host directories, and SSH bound only to a random loopback port. The generated SSH keys belong solely to this disposable lab; host keys are verified. Each run keeps timestamped results and serial/provision logs under the lab directory. Guest diagnostic archives are retained without extracting guest-controlled paths as host root.

Provisioning and probes verify both the disposable marker and the guest's QEMU DMI UUID before changing anything. Quota filesystems and systemd units are created **inside the guest**. Use `vm.sh` for current experiments; `run.sh` is the earlier nspawn experiment, which shares the host kernel and is not evidence of an independent clean workload host.

`--network-only` verifies the provisioned guest and runs only the packet experiment. Earlier smoke/reboot files may remain inside its diagnostic archive; they are historical, not fresh results for that run.

## What is exercised

- NsJail at commit `f100fd917c6d3ed0fd15d868528b735cb5fb1a1a`, Node.js `22.23.3` with a verified archive checksum, and Ubuntu's Python 3.12 packages. Exact resolved guest package versions are saved with each run; Ubuntu security-package updates may change between runs.
- A React/Vite build using the committed npm lockfile, Node and Python HTTP fixtures, a worker, and offline installation/compilation of the checksum-pinned MarkupSafe 2.1.5 test dependency. Package lifecycle/build hooks execute inside NsJail.
- Read-only runtime mounts, isolated process/filesystem/network namespaces, dropped capabilities, `no_new_privileges`, and the experimental syscall policy.
- Reachable IPv4/IPv6 guest canaries that must be unreachable inside the sandbox, XFS project quotas, bounded temporary files, memory/CPU/PID limits, and cancellation of descendants.
- A real guest reboot with bounded systemd worker supervision and a persistent checkpoint. This does not establish production route/release reconstruction.

The policy exposes the guest's build-tool installation read-only to the fixtures; a separate minimal production runtime tree remains to be validated. A passing smoke report does not pass Phase 0. The launcher also runs a synthetic dual-stack TCP packet-policy experiment with reachable canaries and drop counters. That experiment does not establish DNS handling, build egress or a production public-address policy. The two-site origin smoke uses fixed fixtures and does not establish safe artifact publication. Software-emulated timings are diagnostics, not production-capacity benchmarks.

The metadata classifier reads an explicitly supplied limited JSON snapshot without querying Docker or the database. Keep its output private; workload labels and names are unverified identities. It identifies storage review needs and never declares native compatibility from container metadata:

```sh
python3 scripts/native-lab/inventory.py --snapshot /path/to/legacy-workload-metadata.json
```

The separate `tenant_runtime_review.py` marker review accepts an optional full
40-hex `source_commit` per exported app. All marker and root-listing reads use
that pin; invalid or unavailable pins never fall back to the default branch.
Without a pin, the output explicitly describes default-branch evidence. A pin
must come from independently verified release records; the helper does not
establish deployed provenance or migration compatibility. Its native-dependency
scan covers only an npm package-name allowlist; Python requirements remain
unknown. The 22 focused review tests pass offline with mocked HTTP responses.

## Measurement and checks

Capture **both** the control and workload hosts for each backend. Select all owned storage paths, including shared runtimes, package caches, logs, data and retained releases. Use identical source/lockfiles, resources, concurrency and retention. Do not compare image virtual sizes with native allocated blocks.

```sh
python3 scripts/native-lab/measure.py \
  --backend native --role workload --label steady-state \
  --path /srv/halvo --path /opt/halvo-runtimes --path /var/log/halvo \
  --cgroup /sys/fs/cgroup/system.slice/halvo-example.service > workload.json

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/native-lab -p 'test_*.py' -v
bash -n scripts/native-lab/vm.sh scripts/native-lab/provision.sh
```

Replace the example directories and cgroup with the actual owned paths. The collector is read-only, rejects overlapping paths and cgroup traversal/symlinks, uses allocated disk blocks, and bounds each scan. Missing counters remain unknown. It does not infer savings or clear caches. Do not aggregate bind/overlay aliases of storage already measured.

## Dedicated idle-memory comparison

The smoke tests exercise behavior and limits; their short-lived test harnesses
are not steady-state app benchmarks. Use the separate fixed Node, Python,
worker and single-worker Nginx fixtures for process-memory measurements:

```sh
sudo bash scripts/native-lab/vm.sh --benchmark-only /var/tmp/halvo-native-vm-phase0
```

This mode reuses a provisioned disposable guest and skips smoke, reboot and
packet tests. It runs the fixtures through NsJail in separate bounded systemd
units, verifies actual limits (256 MiB RAM, no swap, half a CPU, 128 PIDs),
warms up for five seconds and saves ten timestamped memory samples per app.
Health clients enter only the app's network namespace and remain outside its
cgroup. A worker must keep advancing its atomic checkpoint. Missing counters,
OOM, process restarts and failed cleanup invalidate the run. The fresh report
is `benchmark.json` in the printed results directory; older smoke files in
the diagnostic archive are not new results.

The fixed Python fixtures use isolated mode with site initialization disabled
(`-I -S`). They import only the standard library, so distro/user startup hooks
and packages outside the fingerprinted runtime tree do not alter the workload.

Build the Docker reference image from only the allowlisted fixture files:

```sh
benchmark_context=$(mktemp -d)
cp scripts/native-lab/{benchmark.Dockerfile,benchmark.py,probe.py,guard.py} "$benchmark_context/"
docker build -f "$benchmark_context/benchmark.Dockerfile" \
  --iidfile "$benchmark_context/image-id" -t halvo-memory-benchmark:local "$benchmark_context"
sudo python3 scripts/native-lab/benchmark_docker.py \
  --image "$(cat "$benchmark_context/image-id")" > docker-memory.json
python3 scripts/native-lab/benchmark_compare.py /path/to/benchmark.json docker-memory.json
```

The Docker collector requires an existing exact image ID on the local daemon;
it cannot pull or build images. Its generated containers have no network,
published ports or host mounts, run without capabilities, and use a read-only
root with bounded temporary storage and logs. It verifies the image's actual
fixture bytes and runtime identities and removes only its labeled containers.
The baseline image remains available for another measurement; remove that
specific image when finished, without pruning shared images or caches.

Both reports capture kernel, OS, libc, runtime binary/library digests, fixture
bytes, configuration, actual cgroup limits, sampling windows and cleanup.
The comparator refuses incomplete or mismatched reports. Ubuntu packages are
resolved at image build time and identified in the report; a moving package
version must not be silently treated as matching an older guest.

## Request-load capacity gate

The approved revision uses `vm-capacity.sh` and `capacity_external.py`: host
generator CPUs2–3, guest CPUs0–1, pinned loopback-only SSH and namespace relays.
Run `--external-preflight-native` / `--external-preflight-docker` first, each in
a fresh clone of the appropriate reference. Neither is a capacity trial.
Full trials use `--external-capacity-native` / `--external-capacity-docker` only
after the new path is verified. `capacity_external_validate.py --preflight`
checks a completed preflight and its launcher cleanup receipt; without that
flag it requires six valid reports and runs the fixed capacity thresholds
after the additional raw/transport checks. Use the validator from
the same frozen lineage. Preserve the original idle/build benchmark files.

The request-capacity experiment is a separate, guarded payload. It must not be
added to payload 11 in place. The earlier preserved execution lineage on `paisa` is
`source-validation-27-saturation-stop-20261005` (49 files), manifest
`ad9427d0a8c8bb9cd3003f89b2f874bf196aee2e8249f22832b9b91701703193`.
Native27 and Docker27 instrument preflights pass and were independently
revalidated on October 6. Use this complete frozen lineage to collect and
validate its reports. The continuation controller is at
`/var/tmp/halvo-capacity-trials-27-20261006-attempt2/run_suite.py`; its plan, per-trial
acceptance receipts and final `suite-result.json` record execution status.
That attempt stopped-invalid on October 6 at 04:06:59 UTC: native1's 32-RPS
warmup exceeded the resident-health deadline before a completed rejected window.
Accepted lower-rate windows are not valid trial capacity. The launcher shut down
gracefully, later trials did not start, and no capacity retry is queued.

The later payload28 lineage is
`source-validation-28-health-budget-20261006`, manifest
`c808549a617716ca01a35ff8bec091721a9984f404985862fc1d752eb138f178`.
It uses a 90-second host health budget and fresh preflights; the guest command
bound remains five seconds. Native1 passed at 8 RPS, but Docker1 failed health
control at 16 RPS and the suite stopped before trials3–6. No matched capacity
comparison is valid. Preserve `/var/tmp/halvo-capacity-trials-28-20261006` and
the original reports; never combine its trials with payload27's 30-second lineage.

Payload27 stops after the first fully measured rate rejected by the error
budget. A valid marked schedule must contain the ordered frozen-rate prefix,
with all earlier rates accepted and the final rate rejected. Unmarked trials
still require all eight rates. Aborted windows, health/generator failures,
continuity loss and incomplete cleanup invalidate the trial. Comparisons cover
only rates measured in all six trials; capacity and latency thresholds stay
fixed, and no report can declare Phase 0 complete.

The working source now fixes a payload27 reporting bug: errors occurring after
saturation could leave its collection flags true. The frozen external validator
already rejects those errors and failed cleanup independently, so accepted
preflights need no repeat. For this cohort the controller requires that frozen
validator plus a separately pinned copy of the corrected comparator, which
also rejects earlier rejections, reordered rates and malformed markers. Seven
controller checks cover this acceptance boundary, finalization and cancellation.
The frozen collector and original reports remain unchanged; never accept collector flags
alone or validate its source fingerprints with a different lineage.

The working source also makes the resident health monitor sample through the
cgroup and procfs directly instead of a `docker inspect` or `systemctl show`
round-trip per check. Inside the two-vCPU guest those subprocesses competed with
the residents under load and tripped the resident-health deadline before the
error budget could score a window — the invalidation that stopped payloads 27
and 28. Liveness now comes from the held main process and its container/unit
cgroup, OOM from the cgroup's own `memory.events`, and a restart from a changed
pid identity; the Docker ownership label and systemd invocation are still
re-verified at capture and cleanup, not on the per-sample path. This lowers the
monitor's cost symmetrically on both backends without weakening its identity or
OOM evidence; the health budget, limits, fixtures, relay and gates are unchanged.
Freeze it as a new payload lineage and re-verify both revised path preflights
before any matched suite.

Earlier failed lineages are retained for evidence, not further measurements.
Payload21 was frozen as `source-validation-21-known-host-fix-20261005`, manifest
`d1ca62340f7867c4ee689bff4996b088bd1375451fea53d5740d52228838251a`
(45 files, 133 inherited/frozen lab tests pass). Payload21 reached the native
external path but four client workers per route hit the unchanged 2-second
queue guard on slow TCG responses; its report is invalid evidence. Payload22
uses32 bounded workers per route, still queue512 and with all guards
unchanged. Payload22's32-worker preflight removed queue lag but the synthetic
Python fixture's16-handler cap manufactured transport errors under slow TCG.
Payload23 changes that cap to32 to match the relay; all gates remain unchanged.
The earlier worker-pool payload22 is frozen as
`source-validation-22-worker-pool-20261005`, manifest
`5c7d5fc3472ff05563d89ffafdac0064fb86190a2bd95f5dfc83a3d714f7c71b`.
Payload23 freezes the synthetic Python semaphore at32 to match the relay:
`source-validation-23-fixture-bound-20261005`, manifest
`8061ff48a2be7773885d6976de51abbccafd36300d2cb97e211339ca329c4a2b`.
Payload19 could not boot
because its lab tools lacked FUSE3; the guarded `prepare-qemu-fuse.py` extracts
a signed compatible dependency into lab tools only, without host installation.
Use the same verified QEMU/tools fingerprints for all native and Docker clones.
New path preflights are still
required; this pin alone is not accepted capacity evidence.
It runs the fixed Python/static/Node request mix (70/20/10 percent), keeps the
worker resident, and uses the eight open-loop rates from 1 through 128
requests/second with 60 seconds of warm-up and 120 seconds of measurement at
each rate. The collector writes `capacity-external.json`; it never connects to the
production Docker daemon.

Use one fresh capacity guest clone at a time and the host-wide lab lock. Run
three native/Docker matched pairs in the predeclared alternating order, then
compare all six reports with the read-only comparator:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -W error::ResourceWarning -m unittest \
  discover -s scripts/native-lab -p 'test_capacity*.py' -v
python3 -B scripts/native-lab/capacity_preflight.py --output /path/to/new-selfcheck.json
python3 /path/to/frozen-lineage/capacity_external_validate.py \
  /path/native-1/capacity-external.json /path/native-2/capacity-external.json /path/native-3/capacity-external.json \
  /path/docker-1/capacity-external.json /path/docker-2/capacity-external.json /path/docker-3/capacity-external.json
```

Retained operational notes from the payload25 preparation, still binding: the
matched Docker trials reuse the exact retained capacity image
`sha256:da38db8b3347ab4f61eaa54bd09cd6601fb8f42a31a43ad1767d25262dd9e2f8`
(not a rebuild); run every check with `/usr/bin/python3` because this host's
pyenv interpreter lacks `lzma`; and the suite controller stops on invalid
collection or cleanup, preserves all raw reports, and invokes the six-report
comparator only after all six validate.

The preflight uses only a synthetic HTTP/1.1 loopback canary at 256 rps for
60 seconds. It tests the real client/pipes/scheduler, not a tenant application.
Its report has `scope: load-generator-selfcheck` and `capacity_evidence: false`.
That canary now runs on the generator host. The separate path preflight checks
actual guest fixtures through the revised transport at1rps/60s/120s; it is not
the old in-guest256rps canary. Main's older `vm.sh` is not the new launcher; use
`vm-capacity.sh` from the frozen lineage, a newly verified
lineage, a detached wrapper and a watchdog at least every five minutes. Never
run the README's older local-daemon Docker example against production.

The comparator requires exactly three valid reports per backend, the same
payload and fixture identities, the fixed limits and cleanup evidence. It
applies the approved 95% capacity, 1% error-budget, and p50/p95/p99 latency
non-regression rules. If Docker has not saturated by 128 requests/second, the
result is retained as a lower bound and does not close the gate. TCG timings
remain lab-relative; this experiment makes no RAM or production-latency claim.

`memory.current` includes charged file cache and, on the native side, NsJail.
Raw anonymous/file/kernel counters are retained. The reported lifetime peak
also includes startup/readiness, while the median uses the post-warmup samples.
Even a matching pair covers idle fixture process memory only: Docker daemon
costs, both whole hosts, builds, retained releases, disk allocation, request
load and production latency remain outside this comparison. No result from
these tools passes Phase 0 or authorizes a backend switch.

## Approved nonblocking generator revision (2026-10-05)

The frozen25 suite stopped-invalid at16RPS:32 blocking Python clients exhausted
their worker pool before the strict2s queue guard. The replacement external
path uses `capacity_async_client.py`, identified as
`bounded-nonblocking-http11-v1`, with the existing4096 global outstanding-request
ceiling and at most32 idle keepalive sockets per route. It performs no uncertain
request retries and counts every backend error/timeout. Legacy client, fixtures,
relay32, Docker25 capacity image, quotas and all comparison gates stay unchanged.

Only instrument children get sufficient descriptor capacity: client soft limit
at least8192 and owned host SSH-forward child at least16384; hard limits and host
configuration are unchanged. Insufficient limits or client overflow invalidate
the instrument. The fast256RPS selfcheck uses the same engine, not old workers.
Before new guest preflights, run the host-only `capacity_slowpath_check.py` on
CPUs2,3 from the frozen lineage with `--output` naming a new file. It exercises
16RPS/8s synthetic Python delay and128RPS/30s stalled requests (roughly3840
simultaneous requests). Its output is never backend-capacity evidence.
Freeze new hashes, preserve failed lineages, and verify both revised path
preflights/cleanup before restarting a matched suite. Never boot a reference
disk, rebuild the retained Docker image, or operate on the production daemon.

## Docker inspect health diagnostic harness

`docker_inspect_diagnostic.py`, `docker_inspect_trace_guest.py` and
`vm-docker-inspect.sh` are diagnostic-only source for a separately frozen
lineage. The tracer emits a fixed `startup_ready` marker only after all four
fixture identities pass; the host adapter gates load on that marker. Missing,
invalid or late readiness prevents load. Generate and verify the lineage
manifests in the disposable staging directory before any guest run. This
harness never produces capacity evidence or authorizes a production change.
The current repaired v3 staging record is retained outside the repository at
`/var/tmp/halvo-native-vm-validation-20260930/source-diagnostic-docker-inspect-v3-20261006`;
its one approved guest attempt timed out before startup readiness and dispatched
no load. Its fixed profile remains 16 RPS for 180 seconds,
with 200 seconds of five-second inspect sampling and the unchanged five-second
inspect command bound. Preserve the invalid result and do not retry
automatically.
