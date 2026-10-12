# Payload29 capacity runbook — validating the cheap-health-sampling instrument fix

Purpose: freeze the resident-health instrument fix as payload29, re-verify both
path preflights, and run **one** matched native/Docker pair to decide whether the
fix resolves the health-control invalidation that stopped payloads 27 and 28 —
before spending the full six-trial suite.

Boundaries (read first):
- Every step below runs on the lab host (`paisa`), not on a dev checkout. It
  needs root in the guest path, the prepared QEMU/FUSE tools, and the retained
  Docker capacity image. None of it runs here.
- Run every Python check with `/usr/bin/python3` (this host's pyenv interpreter
  lacks `lzma`).
- One guest at a time, under the host-wide lab lock. Preserve every failed
  report. Never auto-retry, never rebuild the retained image, never touch the
  production Docker daemon.
- The fix is instrument-only. Nothing here closes a Phase 0 gate or authorizes a
  backend switch; `phase0_complete` stays false.

## 0. Get the fix onto the lab host

On the dev checkout, commit (see the two commit commands already provided) and
push `docker-free-tests`. On `paisa`, check out that branch / commit so the
changed `capacity.py` and `test_capacity.py` are present. The behavioral change
is the two resident `_state` methods plus the new `pid_unified_cgroup` helper.

## 1. Freeze payload29

`freeze_lineage.py` copies payload28's exact file set, overlays only the changed
files, regenerates the manifest in payload28's byte format, and refuses to
proceed unless exactly those files differ — so the freeze is reproducible and
self-checking instead of hand-run.

```sh
P28=/var/tmp/halvo-native-vm-validation-20260930/source-validation-28-health-budget-20261006
P29=/var/tmp/halvo-native-vm-validation-20260930/source-validation-29-cheap-health-20261011

/usr/bin/python3 /path/to/halvo/scripts/native-lab/freeze_lineage.py \
  --from "$P28" --to "$P29" \
  --overlay /path/to/halvo/scripts/native-lab \
  --changed capacity.py test_capacity.py
# Prints payload_sha256 (== sha256 of SHA256SUMS) — RECORD it as the payload29
# manifest hash. The helper fails loudly if any other file differs, a declared
# file is unchanged, or a file is present but unlisted.

# Independently confirm the manifest the launcher verifies with `sha256sum -c`:
(cd "$P29" && sha256sum -c SHA256SUMS >/dev/null && echo "payload29 manifest verifies")
```

The lab README note is git documentation; add `README.md` to `--changed` only if
you want the note inside the frozen payload, and only if payload28's manifest
lists it.

## 2. Host-only pre-checks (no guest booted)

```sh
cd "$P29"
# Frozen-lineage test suites must pass before any guest run:
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -W error::ResourceWarning \
  -m unittest discover -s "$P29" -p 'test_capacity*.py' -v

# Host-only slow/stalled generator check on CPUs 2,3 (never backend evidence):
nice -n 10 taskset --cpu-list 2,3 /usr/bin/python3 -B "$P29/capacity_slowpath_check.py" \
  --output /var/tmp/halvo-capacity-p29/slowpath29.json

# Host 256-rps load-generator self-check (scope: load-generator-selfcheck):
/usr/bin/python3 -B "$P29/capacity_preflight.py" \
  --output /var/tmp/halvo-capacity-p29/selfcheck29.json
```

## 3. Both path preflights (cheap, non-committal)

Use a fresh writable overlay of a stopped reference guest for each backend. Run
the frozen lineage's `vm-capacity.sh`, detached, with a watchdog logging
descendants at least every five minutes.

```sh
# Native path preflight:
setsid nohup sudo bash "$P29/vm-capacity.sh" --external-preflight-native \
  /var/tmp/halvo-native-vm-external-preflight-native-29 \
  > /var/tmp/halvo-capacity-runs/preflight-native-29/launcher.log 2>&1 &

# Docker path preflight (fresh clone; reuses the exact retained image
# sha256:da38db8b3347ab4f61eaa54bd09cd6601fb8f42a31a43ad1767d25262dd9e2f8):
setsid nohup sudo bash "$P29/vm-capacity.sh" --external-preflight-docker \
  /var/tmp/halvo-native-vm-external-preflight-docker-29 \
  > /var/tmp/halvo-capacity-runs/preflight-docker-29/launcher.log 2>&1 &
```

Each writes `results/<UTC>/capacity-external.json` (scope
`external-generator-path-preflight`, `capacity_evidence:false`). Validate each
with the frozen validator, confirm graceful shutdown and that the host lock
released before continuing:

```sh
/usr/bin/python3 "$P29/capacity_external_validate.py" --preflight \
  /var/tmp/halvo-native-vm-external-preflight-native-29/results/<UTC>/capacity-external.json
```

Stop here and investigate if either preflight does not validate.

## 4. One matched pair — the decisive, cheap test

Run a single native→Docker pair (not the suite). Fresh overlay each, host lock
held, same wrapper + watchdog:

```sh
setsid nohup sudo bash "$P29/vm-capacity.sh" --external-capacity-native \
  /var/tmp/halvo-native-vm-capacity-native-29-1 \
  > /var/tmp/halvo-capacity-runs/capacity-native-29-1/launcher.log 2>&1 &
# then, after it finishes and the lock frees:
setsid nohup sudo bash "$P29/vm-capacity.sh" --external-capacity-docker \
  /var/tmp/halvo-native-vm-capacity-docker-29-1 \
  > /var/tmp/halvo-capacity-runs/capacity-docker-29-1/launcher.log 2>&1 &
```

**The fix is self-evidencing — look at the health-snapshot durations in each
`capacity-external.json`.** Every snapshot records `started_at_monotonic` and
`ended_at_monotonic`; before the fix those were climbing toward the deadline,
after it they should be milliseconds. That delta is the direct proof the
subprocess contention is gone — no inference needed.

## Decision tree after the one pair

- **Health samples now cheap, windows scored by the error budget** → proceed to
  the full six-trial suite (alternating native→Docker→native…), then validate all
  six with `capacity_external_validate.py` and compare with the pinned corrected
  comparator.
- **Trials stop as legitimate error-budget saturation** (a real, possibly low,
  capacity reading) → that is the saturation-stop path working as designed;
  interpret per the fixed gate rules. A low TCG number is lab-relative, not a
  production-capacity claim.
- **It still invalidates on health control** → TCG is conclusively inadequate for
  a valid sustained-load trial. Escalate the capacity gate to a KVM-capable host
  (the migration plan's explicit escape hatch) rather than patching the instrument
  again.

## Notes

- The 90-second health budget is left as-is. With cheap sampling a generous
  deadline cannot cause a false trip, so it is the safe setting — do not treat
  reverting it to 30s as part of this fix.
- Record the payload29 manifest hash, the slowpath/selfcheck receipts, both
  preflight report SHA-256s, and the pair's health-duration evidence in the
  Phase 0 report once collected.
