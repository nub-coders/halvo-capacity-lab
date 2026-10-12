"""Refuse destructive lab operations outside an explicitly marked disposable guest."""

from pathlib import Path
import subprocess
import uuid


def require_lab():
    marker = Path("/etc/halvo-native-lab")
    if not marker.is_file():
        raise SystemExit("Refusing to run without the disposable lab marker")
    container = Path("/run/systemd/container")
    if container.is_file():
        if container.read_text().strip() == "systemd-nspawn":
            return "systemd-nspawn"
        raise SystemExit("Refusing to run in an unrelated container")
    identity = Path("/etc/halvo-native-lab-vm-id")
    dmi = Path("/sys/class/dmi/id/product_uuid")
    if marker.read_text().strip() != "qemu-phase0-v1" or not identity.is_file() or not dmi.is_file():
        raise SystemExit("Refusing to run outside the disposable native lab")
    try:
        matches = uuid.UUID(identity.read_text().strip()) == uuid.UUID(dmi.read_text().strip())
    except ValueError:
        matches = False
    if not matches:
        raise SystemExit("Refusing to run with a mismatched disposable VM identity")
    result = subprocess.run(
        ["systemd-detect-virt", "--vm"], capture_output=True, text=True, timeout=10, check=False
    )
    if result.returncode != 0 or result.stdout.strip() not in ("qemu", "kvm"):
        raise SystemExit("Refusing to run outside the disposable QEMU VM")
    return "qemu"


if __name__ == "__main__":
    print(require_lab())
