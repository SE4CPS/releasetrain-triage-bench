"""Validates the real, NVD-sourced benchmark snapshot - distinct from
test_benchmark.py's checks on the small illustrative sample. These tests
assert structural correctness (shape, internal consistency) and the kind
of properties scripts/build_snapshot.py's own "never guess" rule
guarantees; they do not assert specific CVE IDs or scores, since those
are real, external facts that could change if the snapshot is rebuilt
later - pinning this test suite to one run's exact CVE numbers would make
it fail the moment the dataset is legitimately regenerated.
"""

from releasetrain_triage_bench.benchmark import load_nvd_snapshot_v1


def test_snapshot_loads_and_is_non_trivial():
    scenarios = load_nvd_snapshot_v1()
    assert len(scenarios) >= 5
    total_components = sum(len(s.components) for s in scenarios)
    assert total_components >= 10


def test_every_scenario_has_matching_facts_for_every_component():
    scenarios = load_nvd_snapshot_v1()
    for s in scenarios:
        component_names = {c.name for c in s.components}
        fact_names = {f.component for f in s.facts}
        assert component_names == fact_names, f"{s.scenario_id} has mismatched components/facts"


def test_cve_fields_are_never_half_populated():
    # A component either has both a cve_id and a cvss_score, or neither -
    # scripts/build_snapshot.py never emits a cve_id with no score or a
    # score with no id (see find_cve_for's own "never a guess" contract).
    scenarios = load_nvd_snapshot_v1()
    for s in scenarios:
        for f in s.facts:
            assert (f.cve_id is None) == (f.cvss_score is None), (
                f"{s.scenario_id}/{f.component} has a half-populated CVE fact: "
                f"cve_id={f.cve_id!r} cvss_score={f.cvss_score!r}"
            )


def test_real_cve_ids_look_like_real_cve_ids():
    scenarios = load_nvd_snapshot_v1()
    for s in scenarios:
        for f in s.facts:
            if f.cve_id is not None:
                assert f.cve_id.startswith("CVE-")
                assert 0.0 <= f.cvss_score <= 10.0
