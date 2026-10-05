"""A trivial, dependency-free reference TriageSystem: no LLM, no network,
no server. Sorts by (has a KEV-listed CVE, CVSS score, version-bump size)
depending on mode. Exists so `pip install releasetrain-triage-bench` works
end-to-end with zero setup (see README), and so an evaluation report has
at least one comparison point that trivially satisfies the ordering
guardrails by construction - the interesting question for any real
system under test is whether it matches this baseline's guardrail
compliance while ALSO doing things this baseline structurally cannot
(weigh unstructured evidence, reason about ties).

This adapter needs the real ComponentFacts to sort by, which a real
TriageSystem would normally have to fetch itself - BaselineTriageSystem
is instead constructed with the Scenario's facts already known, since its
whole point is to be a transparent, auditable reference, not a realistic
"system under test" implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..classify import classify_component_risk_type, classify_version_bump
from ..types import ComponentFacts, EcosystemComponent, RiskType, TriagedUpdate, VersionBump

_BUMP_RANK = {VersionBump.MAJOR: 2, VersionBump.MINOR: 1, VersionBump.PATCH: 0, VersionBump.UNKNOWN: 0}


@dataclass
class BaselineTriageSystem:
    facts_by_component: dict[str, ComponentFacts]

    def triage(
        self, components: Sequence[EcosystemComponent], mode: str, feedback: str | None = None
    ) -> list[TriagedUpdate]:
        # Deterministic sort: retry feedback has nothing to add, so it's
        # intentionally ignored rather than threaded through for show.
        del feedback
        def key(c: EcosystemComponent):
            f = self.facts_by_component.get(c.name)
            if f is None:
                f = ComponentFacts(
                    component=c.name, latest_version=None,
                    version_bump=classify_version_bump(c.installed_version, None),
                    risk_type=classify_component_risk_type(c.name),
                )
            if mode == "security":
                return (not f.kev_listed, -(f.cvss_score or 0.0))
            if mode == "stability":
                return (-(_BUMP_RANK[f.version_bump] + (1 if f.risk_type is RiskType.FOUNDATIONAL else 0)),)
            # "both": security signal first, stability signal as tiebreak
            return (
                not f.kev_listed, -(f.cvss_score or 0.0),
                -(_BUMP_RANK[f.version_bump] + (1 if f.risk_type is RiskType.FOUNDATIONAL else 0)),
            )

        ordered = sorted(components, key=key)
        return [
            TriagedUpdate(component=c.name, order=i + 1, reasoning="baseline: deterministic sort, no model")
            for i, c in enumerate(ordered)
        ]
