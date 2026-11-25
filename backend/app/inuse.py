"""Is a package running? From the agent's list of packages in use, and for kernels from the booted release."""
from __future__ import annotations

import re

# One installed kernel's packages, eg linux-image-6.1.0-18-amd64 or linux-headers-6.8.0-45. Metapackages such as
# linux-image-generic carry no release, so they never count as a kernel here.
KERNEL_DEB = re.compile(r"^linux-(?:image|modules|modules-extra|headers|objects|buildinfo|tools)(?:-unsigned)?"
                        r"-(\d[\w.+~-]*)$")
KERNEL_RPM = {"kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-modules-extra", "kernel-devel"}


def is_kernel(binaries: list[str] | None) -> bool:
    """Every binary is a versioned kernel package, so the group is one installed kernel and nothing else."""
    return bool(binaries) and (all(KERNEL_DEB.match(b) for b in binaries) or set(binaries) <= KERNEL_RPM)


def kernel_running(binaries: list[str], version: str | None, release: str) -> bool:
    """Whether this installed kernel is the booted one (release is `uname -r`)."""
    rels = [m.group(1) for b in binaries if (m := KERNEL_DEB.match(b))]
    if rels:
        return any(release == r or release.startswith(r + "-") for r in rels)
    if not set(binaries) & KERNEL_RPM:
        return False
    v = (version or "").split(":", 1)[-1]  # RPM: uname -r is version-release.arch
    return bool(v) and (release == v or release.startswith(v + "."))


def in_use(binaries: list[str], version: str | None, release: str | None, running: set[str] | None) -> bool | None:
    """True, False, or None when unknown (an agent too old to say, or processes hidden from it)."""
    if release and kernel_running(binaries, version, release):
        return True  # the booted kernel, even when its group also holds eg linux-libc-dev
    if release and is_kernel(binaries):
        return False  # installed, not booted
    if running is None:
        return None
    return any(b in running for b in binaries)
