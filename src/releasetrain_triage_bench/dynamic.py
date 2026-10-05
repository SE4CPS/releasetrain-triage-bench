"""The dynamic (self-correcting) pipeline: wraps a static TriageSystem in
a bounded retry loop that feeds the harness's own violation report back
to the system as corrective feedback, stopping on the first clear
success/failure condition - exactly the "dynamic pipeline with clear
goals to stop" shape, not an open-ended search:

    stop as SUCCESS the moment a run has zero violations;
    stop as (bounded) FAILURE once `max_attempts` is reached.

This mirrors the retry-ceiling shape already used elsewhere for
guardrail-style retries (a fixed, admin-configurable max attempts, never
an unbounded loop) - reused here as the evaluation's own ablation: does
feeding a system its own compliance failures back as feedback measurably
improve compliance over a single (static) attempt?

Deliberately built on top of scorer.py's own already-tested
derive_all_constraints/check_violations rather than duplicating that
logic - see this package's README on modularization for why that
reuse is the point, not an afterthought.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .adapters import TriageSystem
from .guardrails import Guardrail
from .scorer import DEFAULT_MODES, aggregate, check_violations, derive_all_constraints
from .types import EvalReport, Scenario, ScenarioRun, Violation


def format_feedback(violations: Sequence[Violation]) -> str:
    """Turns a list of Violation into the plain-language correction text
    handed back to the system under test on a retry. Kept as a standalone
    function (not inlined into the retry loop) so a caller can override
    the wording - e.g. to match a specific system's own prompt style -
    without needing to reimplement the retry loop itself."""
    lines = ["Your previous ranking violated the following rules:"]
    for v in violations:
        c = v.constraint
        if c.component_a == c.component_b:
            lines.append(f"- {c.reason}")
        else:
            lines.append(
                f"- {c.component_a} must not rank after {c.component_b}: {c.reason}"
            )
    lines.append("Please revise the ranking to satisfy these rules.")
    return "\n".join(lines)


@dataclass
class SelfCorrectionConfig:
    max_attempts: int = 3  # same bounded-retry shape as this project's other retry guardrails
    feedback_formatter: callable = format_feedback


def run_scenario_with_self_correction(
    scenario: Scenario,
    mode: str,
    system: TriageSystem,
    guardrails: Sequence[Guardrail],
    config: SelfCorrectionConfig | None = None,
) -> ScenarioRun:
    """The dynamic-pipeline counterpart to scorer.run_scenario: calls
    `system.triage` up to `config.max_attempts` times, feeding back the
    previous attempt's violations each retry, stopping the moment a
    violation-free attempt is produced. The returned ScenarioRun's
    `attempts` field records how many tries it actually took (1 means the
    static and dynamic results are identical for this scenario)."""
    cfg = config or SelfCorrectionConfig()
    constraints = derive_all_constraints(scenario, mode, guardrails)
    feedback: str | None = None
    last_output: tuple = ()
    last_violations: list[Violation] = []

    for attempt in range(1, cfg.max_attempts + 1):
        try:
            output = tuple(system.triage(scenario.components, mode, feedback))
        except Exception:
            last_output, last_violations = (), list(
                Violation(c, -1, -1) for c in constraints
            )
            break
        violations = check_violations(scenario, mode, output, constraints)
        last_output, last_violations = output, violations
        if not violations:
            return ScenarioRun(
                scenario_id=scenario.scenario_id, mode=mode, output=output,
                constraints=tuple(constraints), violations=(), attempts=attempt,
            )
        feedback = cfg.feedback_formatter(violations)

    return ScenarioRun(
        scenario_id=scenario.scenario_id, mode=mode, output=last_output,
        constraints=tuple(constraints), violations=tuple(last_violations),
        attempts=cfg.max_attempts,
    )


def evaluate_dynamic(
    scenarios: Sequence[Scenario],
    system: TriageSystem,
    guardrails: Sequence[Guardrail],
    modes: Sequence[str] = DEFAULT_MODES,
    config: SelfCorrectionConfig | None = None,
) -> EvalReport:
    """The dynamic-pipeline counterpart to scorer.evaluate - same
    aggregation, same report shape, so a static EvalReport and a dynamic
    EvalReport can be compared field-for-field (that comparison is the
    paper's own static-vs-dynamic finding)."""
    runs = [
        run_scenario_with_self_correction(scenario, mode, system, guardrails, config)
        for scenario in scenarios
        for mode in modes
    ]
    return aggregate(runs, modes)
