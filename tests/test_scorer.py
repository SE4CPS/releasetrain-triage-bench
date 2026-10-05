from dataclasses import dataclass

from releasetrain_triage_bench.guardrails.citation import CommunityRiskCitationGuardrail
from releasetrain_triage_bench.guardrails.security import SecurityOrderingGuardrail
from releasetrain_triage_bench.scorer import check_violations, derive_all_constraints, evaluate, run_scenario
from releasetrain_triage_bench.types import ComponentFacts, EcosystemComponent, RiskType, Scenario, TriagedUpdate, VersionBump


def _security_scenario():
    facts = (
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1"),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    )
    components = tuple(EcosystemComponent(name=f.component, installed_version="1.0.0") for f in facts)
    return Scenario(scenario_id="s1", components=components, facts=facts)


@dataclass
class FakeSystem:
    """A scriptable TriageSystem for tests - returns `output` regardless
    of input, so a test controls exactly what the scorer has to check."""
    output: list[TriagedUpdate]

    def triage(self, components, mode, feedback=None):
        return self.output


class RaisingSystem:
    def triage(self, components, mode, feedback=None):
        raise RuntimeError("boom")


def test_compliant_output_has_no_violations():
    scenario = _security_scenario()
    g = SecurityOrderingGuardrail()
    output = [TriagedUpdate("A", 1), TriagedUpdate("B", 2)]
    constraints = derive_all_constraints(scenario, "security", [g])
    violations = check_violations(scenario, "security", output, constraints)
    assert violations == []


def test_violating_output_is_caught():
    scenario = _security_scenario()
    g = SecurityOrderingGuardrail()
    output = [TriagedUpdate("B", 1), TriagedUpdate("A", 2)]  # wrong way around
    constraints = derive_all_constraints(scenario, "security", [g])
    violations = check_violations(scenario, "security", output, constraints)
    assert len(violations) == 1
    assert violations[0].constraint.component_a == "A"


def test_missing_component_in_output_counts_as_a_violation():
    scenario = _security_scenario()
    g = SecurityOrderingGuardrail()
    output = [TriagedUpdate("A", 1)]  # B silently dropped
    constraints = derive_all_constraints(scenario, "security", [g])
    violations = check_violations(scenario, "security", output, constraints)
    assert len(violations) == 1


def test_citation_guardrail_passes_when_reasoning_mentions_the_url():
    facts = (ComponentFacts(
        "A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD,
        community_risk_flagged=True, community_risk_url="https://example.com/post",
    ),)
    scenario = Scenario("s1", (EcosystemComponent("A", "1.0.0"),), facts)
    g = CommunityRiskCitationGuardrail()
    output = [TriagedUpdate("A", 1, reasoning="See https://example.com/post for details.")]
    constraints = derive_all_constraints(scenario, "security", [g])
    assert check_violations(scenario, "security", output, constraints) == []


def test_citation_guardrail_fails_when_reasoning_is_silent():
    facts = (ComponentFacts(
        "A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD,
        community_risk_flagged=True, community_risk_url="https://example.com/post",
    ),)
    scenario = Scenario("s1", (EcosystemComponent("A", "1.0.0"),), facts)
    g = CommunityRiskCitationGuardrail()
    output = [TriagedUpdate("A", 1, reasoning="Just a minor patch bump.")]
    constraints = derive_all_constraints(scenario, "security", [g])
    assert len(check_violations(scenario, "security", output, constraints)) == 1


def test_run_scenario_handles_a_raising_system_as_full_violation():
    scenario = _security_scenario()
    g = SecurityOrderingGuardrail()
    run = run_scenario(scenario, "security", RaisingSystem(), [g])
    assert run.output == ()
    assert len(run.violations) == len(run.constraints) == 1


def test_evaluate_aggregates_violation_rate_across_modes():
    scenario = _security_scenario()
    g = SecurityOrderingGuardrail()
    compliant = FakeSystem([TriagedUpdate("A", 1), TriagedUpdate("B", 2)])
    report = evaluate([scenario], compliant, [g], modes=["security", "stability"])
    assert report.violation_rate["security"] == 0.0
    # stability has no applicable constraints here (no bump data), so its
    # rate must be a clean 0/0 -> 0.0, not a division error.
    assert report.violation_rate["stability"] == 0.0
    assert report.total_violations == 0
