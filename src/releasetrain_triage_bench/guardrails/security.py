"""Reference guardrail: security-mode ordering, derived entirely from NIST
NVD data (CVE presence and CVSS score) - a single public, third-party,
independently-verifiable source (see the benchmark's own data-provenance
notes in benchmark.py), not anything proprietary to whichever triage
system is under test.

Policy this encodes, in plain language: a component with a known CVE must
never be ranked below a component with no known CVE at all. Among two
components that both have a CVE, the one with the higher CVSS score must
not rank below the one with the lower score. Everything else (two
components with no CVE, tie-breaking among equal-severity CVEs) is left
unconstrained - that is where the system under test's own judgment is
free to operate.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..types import Constraint, Scenario


@dataclass
class SecurityOrderingGuardrail:
    guardrail_id: str = "security_cve_cvss_ordering"
    applies_to_modes: tuple[str, ...] = ("security", "both")

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
        # Rule 1: a known CVE beats no CVE at all, unconditionally.
        if fa.cve_id and not fb.cve_id:
            return Constraint(
                scenario_id, mode, self.guardrail_id, fa.component, fb.component,
                f"{fa.component} has a known CVE ({fa.cve_id}); {fb.component} has none.",
            )
        if fb.cve_id and not fa.cve_id:
            return Constraint(
                scenario_id, mode, self.guardrail_id, fb.component, fa.component,
                f"{fb.component} has a known CVE ({fb.cve_id}); {fa.component} has none.",
            )
        # Rule 2: among two components that both have a CVE, higher CVSS
        # must not rank after lower CVSS. Only compared when both scores
        # are known - an unscored CVE is not assumed to be low-severity.
        if fa.cve_id and fb.cve_id and fa.cvss_score is not None and fb.cvss_score is not None:
            if fa.cvss_score > fb.cvss_score:
                return Constraint(
                    scenario_id, mode, self.guardrail_id, fa.component, fb.component,
                    f"{fa.component} CVSS {fa.cvss_score} > {fb.component} CVSS {fb.cvss_score}.",
                )
            if fb.cvss_score > fa.cvss_score:
                return Constraint(
                    scenario_id, mode, self.guardrail_id, fb.component, fa.component,
                    f"{fb.component} CVSS {fb.cvss_score} > {fa.component} CVSS {fa.cvss_score}.",
                )
        return None
