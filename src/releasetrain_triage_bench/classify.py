"""Deterministic classification helpers - ports of the same pure,
stateless logic the real triage pipeline's guardrail layer computes
(classifyVersionBump/classifyComponentRiskType), reused here so a
benchmark builder can derive ComponentFacts without needing the real
server running. These are deliberately simple and have no dependency on
anything else in this package, so they can be unit-tested in complete
isolation (see tests/test_classify.py).
"""

from __future__ import annotations

import re

from .types import RiskType, VersionBump

_VERSION_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse(version: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.match(version.strip())
    if not m:
        return None
    major, minor, patch = (int(g) if g is not None else 0 for g in m.groups())
    return major, minor, patch


def classify_version_bump(installed_version: str, latest_version: str | None) -> VersionBump:
    """Compares two version strings and classifies the size of the jump
    between them. Returns UNKNOWN whenever either string doesn't parse as
    a plain numeric major[.minor[.patch]] version, or when there is no
    newer version at all - never guesses."""
    if not latest_version:
        return VersionBump.UNKNOWN
    installed = _parse(installed_version)
    latest = _parse(latest_version)
    if installed is None or latest is None:
        return VersionBump.UNKNOWN
    if latest <= installed:
        return VersionBump.UNKNOWN
    if latest[0] > installed[0]:
        return VersionBump.MAJOR
    if latest[1] > installed[1]:
        return VersionBump.MINOR
    return VersionBump.PATCH


# A small, explicit, publicly-documented taxonomy (not an internal catalog
# lookup) - deliberately small and literal rather than a learned/opaque
# classifier, so a reader can audit every entry without needing access to
# any proprietary data. Extend this list, don't replace it with a scoring
# model, if a benchmark needs a component this doesn't cover - the point
# of this function is that every classification decision is inspectable
# in the source itself.
_FOUNDATIONAL_KEYWORDS = (
    "kernel", "linux", "windows", "macos", "ios", "android",
    "hypervisor", "vmware", "virtualbox", "hyper-v", "kvm", "xen",
    "docker", "containerd", "kubernetes",
    "glibc", "systemd", "openssl", "bash",
)


def classify_component_risk_type(component_name: str) -> RiskType:
    """FOUNDATIONAL if the component name matches a known OS/hypervisor/
    core-runtime keyword (case-insensitive substring match), STANDARD
    otherwise. See _FOUNDATIONAL_KEYWORDS above for the exact, auditable
    list this decision is based on."""
    lowered = component_name.lower()
    if any(kw in lowered for kw in _FOUNDATIONAL_KEYWORDS):
        return RiskType.FOUNDATIONAL
    return RiskType.STANDARD
