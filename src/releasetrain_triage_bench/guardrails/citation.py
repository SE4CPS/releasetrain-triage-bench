"""Reference guardrail: community-risk citation, a presence check rather
than an ordering constraint - mirrors the "always name a flagged-risky
report by link" pattern (never left as an unverified number) already used
elsewhere in agentic update-monitoring pipelines for exactly this reason:
a real, flagged-risky community report is cheap for a reasoning agent to
silently drop, and a plain ranking-agreement check would never catch that
omission.

This does not constrain ORDER at all (it never compares two components
against each other) - it only derives a one-sided obligation: if a
component has a real, flagged-risky community report, the system's own
reasoning text for that component must mention it. The "component" on
both sides of the returned Constraint is the same component; the scorer
(see scorer.py) checks this kind of self-referential constraint by
substring-matching reasoning text, not by comparing two orders.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..types import Constraint, Scenario


@dataclass
class CommunityRiskCitationGuardrail:
    guardrail_id: str = "community_risk_citation"
    applies_to_modes: tuple[str, ...] = ("security", "stability", "both")

    def derive_constraints(self, scenario: Scenario, mode: str) -> list[Constraint]:
        if mode not in self.applies_to_modes:
            return []
        constraints: list[Constraint] = []
        for f in scenario.facts:
            if f.community_risk_flagged:
                constraints.append(Constraint(
                    scenario_id=scenario.scenario_id,
                    mode=mode,
                    guardrail_id=self.guardrail_id,
                    component_a=f.component,
                    component_b=f.component,
                    reason=(
                        f"{f.component} has a flagged community risk report"
                        + (f" ({f.community_risk_url})" if f.community_risk_url else "")
                        + "; the reasoning for this component must mention it."
                    ),
                ))
        return constraints
