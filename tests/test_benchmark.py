from releasetrain_triage_bench.benchmark import load_sample_benchmark


def test_sample_benchmark_loads():
    scenarios = load_sample_benchmark()
    assert len(scenarios) == 5
    ids = {s.scenario_id for s in scenarios}
    assert "security_kev_vs_none" in ids
    assert "citation_flagged_community_risk" in ids


def test_every_scenario_has_matching_facts_for_every_component():
    scenarios = load_sample_benchmark()
    for s in scenarios:
        component_names = {c.name for c in s.components}
        fact_names = {f.component for f in s.facts}
        assert component_names == fact_names, f"{s.scenario_id} has mismatched components/facts"


def test_facts_for_lookup_works():
    scenarios = load_sample_benchmark()
    s = next(s for s in scenarios if s.scenario_id == "security_kev_vs_none")
    f = s.facts_for("OpenSSL")
    assert f is not None
    assert f.kev_listed is True
    assert s.facts_for("nonexistent") is None
