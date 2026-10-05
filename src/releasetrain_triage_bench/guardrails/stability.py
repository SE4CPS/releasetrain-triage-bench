"""Reference guardrail: stability-mode ordering, derived from version-bump
size (major/minor/patch) and component risk type (foundational vs.
standard - see classify.py for the exact, auditable taxonomy).

Policy this encodes: a major-version bump on a foundational (OS-level,
wide blast radius) component must never be ranked AHEAD of a patch-level
bump on a standard component - the foundational+major case is the one
this guardrail considers highest-risk and therefore needing the most
care/testing before being rushed to the front just because it is also,
separately, out of date. Two components at the same bump size and risk
tier, or any pair this specific comparison doesn't resolve, are left
unconstrained.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..types import Constraint, RiskType, Scenario, VersionBump

@dataclass
class StabilityOrderingGuardrail:
    guardrail_id: str = "stability_bump_risk_ordering"
    applies_to_modes: tuple[str, ...] = ("stability", "both")

    def derive_constraints(self, scenario: Scenario, mode: str) -> list[Constraint]:
        if mode not in self.applies_to_modes:
            return []
        constraints: list[Constraint] = []
        facts = scenario.facts
        for i, fa in enumerate(facts):
            for fb in facts[i + 1 :]:
                constraint = self._compare(scenario.scenario_id, mode, fa, fb)
                if constraint is not None:
                    constraints.append(constraint)
        return constraints

    def _compare(self, scenario_id, mode, fa, fb) -> Constraint | None:
        if fa.version_bump is VersionBump.UNKNOWN or fb.version_bump is VersionBump.UNKNOWN:
            return None  # never constrain a pair we can't actually size the risk of
        # Only the clearest case is enforced as a hard constraint: a
        # foundational+major component must not rank after a standard
        # component at patch level or below. Anything closer than that is
        # left to the system's own judgment, per this guardrail's own
        # docstring.
        a_is_high_risk = fa.risk_type is RiskType.FOUNDATIONAL and fa.version_bump is VersionBump.MAJOR
        b_is_high_risk = fb.risk_type is RiskType.FOUNDATIONAL and fb.version_bump is VersionBump.MAJOR
        if a_is_high_risk and fb.version_bump is VersionBump.PATCH and not b_is_high_risk:
            return Constraint(
                scenario_id, mode, self.guardrail_id, fa.component, fb.component,
                f"{fa.component} is a major bump on a foundational component; "
                f"{fb.component} is only a patch-level bump.",
            )
        if b_is_high_risk and fa.version_bump is VersionBump.PATCH and not a_is_high_risk:
            return Constraint(
                scenario_id, mode, self.guardrail_id, fb.component, fa.component,
                f"{fb.component} is a major bump on a foundational component; "
                f"{fa.component} is only a patch-level bump.",
            )
        return None
