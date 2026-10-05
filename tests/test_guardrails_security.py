from releasetrain_triage_bench.guardrails.security import SecurityOrderingGuardrail
from releasetrain_triage_bench.types import ComponentFacts, EcosystemComponent, RiskType, Scenario, VersionBump


def _scenario(facts):
    components = tuple(EcosystemComponent(name=f.component, installed_version="1.0.0") for f in facts)
    return Scenario(scenario_id="s1", components=components, facts=tuple(facts))


def test_cve_beats_no_cve():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1"),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = SecurityOrderingGuardrail()
    constraints = g.derive_constraints(_scenario(facts), "security")
    assert len(constraints) == 1
    assert constraints[0].component_a == "A"
    assert constraints[0].component_b == "B"


def test_higher_cvss_must_not_rank_after_lower():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1", cvss_score=9.8),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-2", cvss_score=4.3),
    ]
    g = SecurityOrderingGuardrail()
    constraints = g.derive_constraints(_scenario(facts), "security")
    assert len(constraints) == 1
    assert constraints[0].component_a == "A"
    assert constraints[0].component_b == "B"


def test_no_constraint_when_neither_has_a_cve():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = SecurityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "security") == []


def test_no_constraint_for_unscored_cves():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1"),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-2"),
    ]
    g = SecurityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "security") == []


def test_skipped_entirely_outside_its_modes():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1"),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = SecurityOrderingGuardrail()
    assert g.derive_constraints(_scenario(facts), "stability") == []


def test_applies_in_both_mode_too():
    facts = [
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1"),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    ]
    g = SecurityOrderingGuardrail()
    assert len(g.derive_constraints(_scenario(facts), "both")) == 1
