from releasetrain_triage_bench.guardrails.stability import StabilityOrderingGuardrail
from releasetrain_triage_bench.types import ComponentFacts, EcosystemComponent, RiskType, Scenario, VersionBump


def _scenario(facts):
    components = tuple(EcosystemComponent(name=f.component, installed_version="1.0.0") for f in facts)
    return Scenario(scenario_id="s1", components=components, facts=tuple(facts))


def test_foundational_major_beats_standard_patch():
    facts = [
        ComponentFacts("A", "6.9.0", VersionBump.MAJOR, RiskType.FOUNDATIONAL),
        ComponentFacts("B", "3.2.2", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = StabilityOrderingGuardrail()
    constraints = g.derive_constraints(_scenario(facts), "stability")
    assert len(constraints) == 1
    assert constraints[0].component_a == "A"
    assert constraints[0].component_b == "B"


def test_no_constraint_when_both_major_foundational():
    facts = [
        ComponentFacts("A", "6.9.0", VersionBump.MAJOR, RiskType.FOUNDATIONAL),
        ComponentFacts("B", "6.9.0", VersionBump.MAJOR, RiskType.FOUNDATIONAL),
    ]
    g = StabilityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "stability") == []


def test_no_constraint_for_standard_major_vs_standard_patch():
    # Only the foundational+major case is a hard constraint; this pair is
    # deliberately left to the system's own judgment.
    facts = [
        ComponentFacts("A", "6.9.0", VersionBump.MAJOR, RiskType.STANDARD),
        ComponentFacts("B", "3.2.2", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = StabilityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "stability") == []


def test_no_constraint_when_bump_unknown():
    facts = [
        ComponentFacts("A", None, VersionBump.UNKNOWN, RiskType.FOUNDATIONAL),
        ComponentFacts("B", "3.2.2", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = StabilityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "stability") == []


def test_skipped_outside_its_modes():
    facts = [
        ComponentFacts("A", "6.9.0", VersionBump.MAJOR, RiskType.FOUNDATIONAL),
        ComponentFacts("B", "3.2.2", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = StabilityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "security") == []
