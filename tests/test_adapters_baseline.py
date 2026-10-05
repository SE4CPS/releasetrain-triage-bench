from releasetrain_triage_bench.adapters.baseline import BaselineTriageSystem
from releasetrain_triage_bench.types import ComponentFacts, EcosystemComponent, RiskType, VersionBump


def test_kev_listed_ranked_first_in_security_mode():
    facts = {
        "A": ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1", kev_listed=True),
        "B": ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    }
    system = BaselineTriageSystem(facts_by_component=facts)
    components = [EcosystemComponent("B", "1.0.0"), EcosystemComponent("A", "1.0.0")]
    result = system.triage(components, "security")
    by_name = {u.component: u.order for u in result}
    assert by_name["A"] < by_name["B"]


def test_foundational_major_ranked_first_in_stability_mode():
    facts = {
        "A": ComponentFacts("A", "6.9.0", VersionBump.MAJOR, RiskType.FOUNDATIONAL),
        "B": ComponentFacts("B", "3.2.2", VersionBump.PATCH, RiskType.STANDARD),
    }
    system = BaselineTriageSystem(facts_by_component=facts)
    components = [EcosystemComponent("B", "1.0.0"), EcosystemComponent("A", "1.0.0")]
    result = system.triage(components, "stability")
    by_name = {u.component: u.order for u in result}
    assert by_name["A"] < by_name["B"]


def test_every_component_gets_a_distinct_order():
    facts = {}
    system = BaselineTriageSystem(facts_by_component=facts)
    components = [EcosystemComponent(n, "1.0.0") for n in ("A", "B", "C")]
    result = system.triage(components, "both")
    orders = sorted(u.order for u in result)
    assert orders == [1, 2, 3]


def test_unknown_component_falls_back_to_live_classification():
    # No pre-supplied facts at all - BaselineTriageSystem must derive its
    # own via classify.py rather than crashing on a missing lookup.
    system = BaselineTriageSystem(facts_by_component={})
    components = [EcosystemComponent("Linux kernel", "5.0.0"), EcosystemComponent("htop", "3.0.0")]
    result = system.triage(components, "stability")
    assert len(result) == 2
