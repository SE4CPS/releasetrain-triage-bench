"""End-to-end check: the bundled sample benchmark, the baseline adapter,
and all three reference guardrails, wired together exactly the way the
CLI's `evaluate` command does it. If every other test file passes but
this one fails, the bug is in how the pieces are wired together, not in
any one piece - which is the point of keeping this as the one test that
spans module boundaries instead of folding integration checks into the
unit test files above."""

from releasetrain_triage_bench.adapters.baseline import BaselineTriageSystem
from releasetrain_triage_bench.benchmark import load_sample_benchmark
from releasetrain_triage_bench.guardrails.citation import CommunityRiskCitationGuardrail
from releasetrain_triage_bench.guardrails.security import SecurityOrderingGuardrail
from releasetrain_triage_bench.guardrails.stability import StabilityOrderingGuardrail
from releasetrain_triage_bench.scorer import evaluate


def test_baseline_system_is_fully_compliant_on_the_sample_benchmark():
    # The baseline is constructed to satisfy the ordering guardrails by
    # design (see adapters/baseline.py's own docstring) - this is the
    # sanity check that the constraint derivation and the baseline's own
    # sort logic actually agree with each other end to end. The citation
    # guardrail is the one exception: the baseline never writes reasoning
    # text at all, so it is expected to fail that guardrail every time.
    scenarios = load_sample_benchmark()
    facts_by_component = {f.component: f for s in scenarios for f in s.facts}
    system = BaselineTriageSystem(facts_by_component=facts_by_component)
    guardrails = [SecurityOrderingGuardrail(), StabilityOrderingGuardrail()]

    report = evaluate(scenarios, system, guardrails, modes=["security", "stability", "both"])

    assert report.total_constraints > 0
    assert report.total_violations == 0
    for rate in report.violation_rate.values():
        assert rate == 0.0


def test_baseline_fails_the_citation_guardrail_by_design():
    scenarios = load_sample_benchmark()
    facts_by_component = {f.component: f for s in scenarios for f in s.facts}
    system = BaselineTriageSystem(facts_by_component=facts_by_component)
    guardrails = [CommunityRiskCitationGuardrail()]

    report = evaluate(scenarios, system, guardrails, modes=["security"])

    assert report.total_constraints > 0
    assert report.total_violations == report.total_constraints
