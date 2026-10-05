"""Benchmark loading: turns a frozen JSON snapshot into a list of
Scenario objects.

Why frozen JSON, not a live lookup: the facts a benchmark scores against
(CVSS score, latest version) change over time at the real sources they
come from (NIST NVD, vendor release feeds). A snapshot recorded once and
replayed is what makes two different runs - today, and someone else's six
months from now - comparable at all; see this package's README for the
full reproducibility rationale. `data/sample_benchmark.json` is a small,
hand-built illustrative set (a handful of scenarios) meant to exercise
every guardrail at least once and to validate the harness end-to-end - it
is NOT the full benchmark a paper's reported numbers would be computed
over. Building that larger, NVD-sourced snapshot is a separate
data-collection step (see scripts/build_snapshot.py, not included in
this initial package version) that only needs to produce JSON in this
exact shape to be usable by everything else here.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from .types import ComponentFacts, EcosystemComponent, RiskType, Scenario, VersionBump


def _facts_from_dict(d: dict) -> ComponentFacts:
    return ComponentFacts(
        component=d["component"],
        latest_version=d.get("latest_version"),
        version_bump=VersionBump(d.get("version_bump", "unknown")),
        risk_type=RiskType(d.get("risk_type", "standard")),
        cve_id=d.get("cve_id"),
        cvss_score=d.get("cvss_score"),
        community_risk_flagged=d.get("community_risk_flagged", False),
        community_risk_url=d.get("community_risk_url"),
    )


def _scenario_from_dict(d: dict) -> Scenario:
    components = tuple(
        EcosystemComponent(name=c["name"], installed_version=c["installed_version"], vendor=c.get("vendor"))
        for c in d["components"]
    )
    facts = tuple(_facts_from_dict(f) for f in d["facts"])
    return Scenario(scenario_id=d["scenario_id"], components=components, facts=facts)


def load_benchmark(path: str | Path) -> list[Scenario]:
    """Loads a benchmark snapshot from a JSON file on disk. The file is a
    JSON array of scenario objects; see data/sample_benchmark.json for the
    exact shape."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [_scenario_from_dict(d) for d in data]


def load_sample_benchmark() -> list[Scenario]:
    """Loads the small, bundled illustrative benchmark shipped inside the
    package itself - no file path needed, works immediately after
    `pip install`. See this module's own docstring for what this dataset
    is (and is not) suitable for."""
    with resources.files("releasetrain_triage_bench.data").joinpath("sample_benchmark.json").open(
        "r", encoding="utf-8"
    ) as f:
        data = json.load(f)
    return [_scenario_from_dict(d) for d in data]
