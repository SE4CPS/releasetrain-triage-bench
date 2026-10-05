from releasetrain_triage_bench.guardrails.citation import CommunityRiskCitationGuardrail
from releasetrain_triage_bench.types import ComponentFacts, EcosystemComponent, RiskType, Scenario, VersionBump


def _scenario(facts):
    components = tuple(EcosystemComponent(name=f.component, installed_version="1.0.0") for f in facts)
    return Scenario(scenario_id="s1", components=components, facts=tuple(facts))


def test_flagged_component_produces_a_self_referential_constraint():
    facts = [
        ComponentFacts(
            "A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD,
            community_risk_flagged=True, community_risk_url="https://example.com/post",
        ),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = CommunityRiskCitationGuardrail()
    constraints = g.derive_constraints(_scenario(facts), "security")
    assert len(constraints) == 1
    assert constraints[0].component_a == "A"
    assert constraints[0].component_b == "A"


def test_no_constraint_when_nothing_flagged():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = CommunityRiskCitationGuardrail()
    assert g.derive_constraints(_scenario(facts), "security") == []


def test_applies_to_all_three_modes():
    facts = [ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, community_risk_flagged=True)]
    g = CommunityRiskCitationGuardrail()
    for mode in ("security", "stability", "both"):
        assert len(g.derive_constraints(_scenario(facts), mode)) == 1
