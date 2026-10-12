#!/usr/bin/env python3
"""Freeze a new capacity payload lineage reproducibly from its predecessor.

A frozen lineage is a directory of capacity lab files plus a SHA256SUMS manifest;
`vm-capacity.sh` verifies that manifest with `sha256sum -c` and uses
`sha256(SHA256SUMS)` as the payload id. This helper copies a predecessor lineage,
overlays only the files that changed, regenerates the manifest in the
predecessor's exact byte format (swapping only the leading hash of each changed
line), and refuses to proceed unless exactly the intended files differ. It makes
no network, guest, or Docker call.
"""
import argparse
import hashlib
from pathlib import Path
import shutil
import sys

HASH_LEN = 64


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _norm(path):
    return str(Path(path.strip()))


def _parse_manifest(text):
    """Return ordered (hash, path, raw_line) tuples for a sha256sum manifest."""
    entries = []
    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\n")
        if not line:
            continue
        if len(line) < HASH_LEN + 2 \
                or any(c not in "0123456789abcdef" for c in line[:HASH_LEN]):
            raise ValueError(f"manifest line is not sha256sum format: {line[:80]!r}")
        entries.append((line[:HASH_LEN], line[HASH_LEN + 2:], raw))
    return entries


def freeze(from_dir, to_dir, overlay_dir, changed, manifest_name):
    from_dir, to_dir, overlay_dir = Path(from_dir), Path(to_dir), Path(overlay_dir)
    manifest_path = from_dir / manifest_name
    if not manifest_path.is_file():
        raise SystemExit(f"predecessor manifest not found: {manifest_path}")
    if to_dir.exists():
        raise SystemExit(f"destination already exists: {to_dir}")

    entries = _parse_manifest(manifest_path.read_text())
    listed = {_norm(path) for _, path, _ in entries}
    want_changed = {_norm(name) for name in changed}
    for name in changed:
        if _norm(name) not in listed:
            raise SystemExit(f"--changed file not in predecessor manifest: {name}")
        if not (overlay_dir / name).is_file():
            raise SystemExit(f"overlay source missing: {overlay_dir / name}")

    shutil.copytree(from_dir, to_dir, symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in changed:
        shutil.copyfile(overlay_dir / name, to_dir / name)

    new_lines, actually_changed, changed_hashes = [], set(), {}
    for digest, path, raw in entries:
        target = to_dir / path
        if not target.is_file():
            raise SystemExit(f"manifest lists a missing file: {path}")
        fresh = _sha256(target)
        if fresh != digest:
            actually_changed.add(_norm(path))
            changed_hashes[_norm(path)] = (digest, fresh)
        new_lines.append(fresh + raw[HASH_LEN:])

    if actually_changed != want_changed:
        unexpected = sorted(actually_changed - want_changed)
        missing = sorted(want_changed - actually_changed)
        detail = []
        if unexpected:
            detail.append("unexpected content changes: " + ", ".join(unexpected))
        if missing:
            detail.append("expected to change but identical to predecessor: "
                          + ", ".join(missing))
        shutil.rmtree(to_dir)
        raise SystemExit("refusing to freeze; " + "; ".join(detail))

    present = {_norm(str(p.relative_to(to_dir)))
               for p in to_dir.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    unlisted = present - listed - {_norm(manifest_name)}
    if unlisted:
        shutil.rmtree(to_dir)
        raise SystemExit("refusing to freeze; files present but unlisted: "
                         + ", ".join(sorted(unlisted)))

    new_manifest = "".join(new_lines)
    (to_dir / manifest_name).write_text(new_manifest)
    return {"files": len(entries),
            "payload_sha256": hashlib.sha256(new_manifest.encode()).hexdigest(),
            "changed": changed_hashes}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from", dest="from_dir", required=True,
                        help="predecessor lineage directory (authoritative file set)")
    parser.add_argument("--to", dest="to_dir", required=True,
                        help="new lineage directory to create (must not exist)")
    parser.add_argument("--overlay", dest="overlay_dir", required=True,
                        help="directory holding the changed files (e.g. the repo native-lab tree)")
    parser.add_argument("--changed", nargs="+", default=["capacity.py", "test_capacity.py"],
                        help="files expected to differ from the predecessor")
    parser.add_argument("--manifest", default="SHA256SUMS")
    args = parser.parse_args(argv)
    result = freeze(args.from_dir, args.to_dir, args.overlay_dir, args.changed, args.manifest)
    print(f"froze {result['files']} files -> {args.to_dir}")
    print(f"payload_sha256 (sha256 of {args.manifest}): {result['payload_sha256']}")
    for path, (old, new) in sorted(result["changed"].items()):
        print(f"  changed {path}: {old[:12]} -> {new[:12]}")
    print(f"regenerated {args.manifest}; confirm with: "
          f"(cd {args.to_dir} && sha256sum -c {args.manifest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
