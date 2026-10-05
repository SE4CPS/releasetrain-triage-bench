from releasetrain_triage_bench.dynamic import SelfCorrectionConfig, run_scenario_with_self_correction
from releasetrain_triage_bench.guardrails.security import SecurityOrderingGuardrail
from releasetrain_triage_bench.types import ComponentFacts, EcosystemComponent, RiskType, Scenario, TriagedUpdate, VersionBump


def _scenario():
    facts = (
        ComponentFacts("A", "2.0.0", VersionBump.PATCH, RiskType.STANDARD, cve_id="CVE-1"),
        ComponentFacts("B", "2.0.0", VersionBump.PATCH, RiskType.STANDARD),
    )
    components = tuple(EcosystemComponent(name=f.component, installed_version="1.0.0") for f in facts)
    return Scenario(scenario_id="s1", components=components, facts=facts)


class AlwaysCompliant:
    def triage(self, components, mode, feedback=None):
        return [TriagedUpdate("A", 1), TriagedUpdate("B", 2)]


class NeverCompliant:
    def triage(self, components, mode, feedback=None):
        return [TriagedUpdate("B", 1), TriagedUpdate("A", 2)]


class CorrectsOnSecondAttempt:
    def __init__(self):
        self.calls = 0

    def triage(self, components, mode, feedback=None):
        self.calls += 1
        if feedback is None:
            return [TriagedUpdate("B", 1), TriagedUpdate("A", 2)]  # wrong first try
        return [TriagedUpdate("A", 1), TriagedUpdate("B", 2)]  # fixed once corrected


def test_succeeds_on_first_attempt_when_already_compliant():
    run = run_scenario_with_self_correction(
        _scenario(), "security", AlwaysCompliant(), [SecurityOrderingGuardrail()]
    )
    assert run.attempts == 1
    assert run.violations == ()


def test_stops_at_max_attempts_when_never_compliant():
    cfg = SelfCorrectionConfig(max_attempts=2)
    run = run_scenario_with_self_correction(
        _scenario(), "security", NeverCompliant(), [SecurityOrderingGuardrail()], cfg
    )
    assert run.attempts == 2
    assert len(run.violations) == 1


def test_succeeds_once_feedback_is_incorporated():
    system = CorrectsOnSecondAttempt()
    run = run_scenario_with_self_correction(
        _scenario(), "security", system, [SecurityOrderingGuardrail()], SelfCorrectionConfig(max_attempts=3)
    )
    assert run.attempts == 2
    assert run.violations == ()
    assert system.calls == 2


def test_feedback_is_none_on_first_call_only():
    seen_feedback = []

    class RecordingSystem:
        def triage(self, components, mode, feedback=None):
            seen_feedback.append(feedback)
            return [TriagedUpdate("B", 1), TriagedUpdate("A", 2)]  # always wrong

    run_scenario_with_self_correction(
        _scenario(), "security", RecordingSystem(), [SecurityOrderingGuardrail()],
        SelfCorrectionConfig(max_attempts=2),
    )
    assert seen_feedback[0] is None
    assert seen_feedback[1] is not None
    assert "must not rank after" in seen_feedback[1]
