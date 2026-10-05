"""The harness: runs a TriageSystem against a set of Scenarios under a set
of caller-supplied Guardrails, and scores the result as a violation rate.

Kept deliberately small and dependency-free (pure functions over the
types in types.py) so each piece - constraint derivation, violation
detection, rate aggregation - can be unit-tested independently of an
actual system under test (see tests/test_scorer.py, which exercises this
whole module against a fake TriageSystem rather than any real pipeline).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from .adapters import TriageSystem
from .guardrails import Guardrail
from .types import Constraint, EvalReport, Scenario, ScenarioRun, TriagedUpdate, Violation

DEFAULT_MODES: tuple[str, ...] = ("security", "stability", "both")


def derive_all_constraints(
    scenario: Scenario, mode: str, guardrails: Sequence[Guardrail]
) -> list[Constraint]:
    """Collects every constraint every applicable guardrail derives for
    this scenario/mode. A guardrail whose `applies_to_modes` doesn't
    include `mode` is simply not asked (see Guardrail's own docstring for
    why that's the guardrail's responsibility, not the caller's)."""
    constraints: list[Constraint] = []
    for g in guardrails:
        if mode in g.applies_to_modes:
            constraints.extend(g.derive_constraints(scenario, mode))
    return constraints


def _order_of(output: Sequence[TriagedUpdate], component: str) -> int | None:
    for u in output:
        if u.component == component:
            return u.order
    return None


def _reasoning_of(output: Sequence[TriagedUpdate], component: str) -> str:
    for u in output:
        if u.component == component:
            return u.reasoning
    return ""


def _mentions_community_risk(reasoning: str, facts) -> bool:
    """Heuristic presence check for the citation guardrail: does the
    reasoning text for a component acknowledge its flagged community
    risk report? Checked against the component's own real risk URL first
    (an exact, unambiguous signal), falling back to a couple of generic
    keywords only when no URL is on record. This is intentionally a
    simple, auditable substring check, not an LLM-judged "did it really
    engage with this" call - see this package's README for why a
    deterministic check is preferred here."""
    text = reasoning.lower()
    if facts.community_risk_url and facts.community_risk_url.lower() in text:
        return True
    return any(kw in text for kw in ("community risk", "reddit", "reported issue", "user reports"))


def check_violations(
    scenario: Scenario,
    mode: str,
    output: Sequence[TriagedUpdate],
    constraints: Sequence[Constraint],
) -> list[Violation]:
    """Checks one scenario/mode's constraints against one system's actual
    output. A self-referential constraint (component_a == component_b, as
    the citation guardrail produces) is checked against that component's
    own reasoning text; every other constraint is checked as an ordering
    comparison. A component the output doesn't mention at all is treated
    as failing any constraint that names it - a system cannot satisfy a
    constraint about a component it silently dropped."""
    violations: list[Violation] = []
    for c in constraints:
        if c.component_a == c.component_b:
            facts = scenario.facts_for(c.component_a)
            reasoning = _reasoning_of(output, c.component_a)
            order = _order_of(output, c.component_a)
            if order is None or (facts is not None and not _mentions_community_risk(reasoning, facts)):
                violations.append(Violation(constraint=c, a_order=order or -1, b_order=order or -1))
            continue
        order_a = _order_of(output, c.component_a)
        order_b = _order_of(output, c.component_b)
        if order_a is None or order_b is None or order_a > order_b:
            violations.append(Violation(constraint=c, a_order=order_a or -1, b_order=order_b or -1))
    return violations


def run_scenario(
    scenario: Scenario, mode: str, system: TriageSystem, guardrails: Sequence[Guardrail]
) -> ScenarioRun:
    """Runs one (scenario, mode) pair through `system` once and scores it.
    A system raising while answering is recorded as a fully-violated run
    (every constraint unmet, since no output exists to satisfy any of
    them) rather than propagating the exception - one bad scenario should
    not abort a whole benchmark pass."""
    constraints = derive_all_constraints(scenario, mode, guardrails)
    try:
        output = tuple(system.triage(scenario.components, mode))
    except Exception:
        return ScenarioRun(
            scenario_id=scenario.scenario_id, mode=mode, output=(),
            constraints=tuple(constraints),
            violations=tuple(Violation(c, -1, -1) for c in constraints),
        )
    violations = check_violations(scenario, mode, output, constraints)
    return ScenarioRun(
        scenario_id=scenario.scenario_id, mode=mode, output=output,
        constraints=tuple(constraints), violations=tuple(violations),
    )


def evaluate(
    scenarios: Sequence[Scenario],
    system: TriageSystem,
    guardrails: Sequence[Guardrail],
    modes: Sequence[str] = DEFAULT_MODES,
) -> EvalReport:
    """Runs `system` against every scenario under every mode, and
    aggregates the result. Guardrails are a caller-supplied input (not a
    fixed list this package bakes in) - pass this package's own reference
    guardrails (guardrails/security.py, stability.py, citation.py) or any
    custom Guardrail implementation, mixed freely."""
    runs: list[ScenarioRun] = []
    for scenario in scenarios:
        for mode in modes:
            runs.append(run_scenario(scenario, mode, system, guardrails))
    return aggregate(runs, modes)


def aggregate(runs: Sequence[ScenarioRun], modes: Sequence[str]) -> EvalReport:
    total_constraints = sum(len(r.constraints) for r in runs)
    total_violations = sum(len(r.violations) for r in runs)

    by_mode_constraints: dict[str, int] = defaultdict(int)
    by_mode_violations: dict[str, int] = defaultdict(int)
    by_guardrail_constraints: dict[str, int] = defaultdict(int)
    by_guardrail_violations: dict[str, int] = defaultdict(int)

    for r in runs:
        by_mode_constraints[r.mode] += len(r.constraints)
        by_mode_violations[r.mode] += len(r.violations)
        for c in r.constraints:
            by_guardrail_constraints[c.guardrail_id] += 1
        for v in r.violations:
            by_guardrail_violations[v.constraint.guardrail_id] += 1

    violation_rate = {
        mode: (by_mode_violations[mode] / by_mode_constraints[mode]) if by_mode_constraints[mode] else 0.0
        for mode in modes
    }
    violation_rate_by_guardrail = {
        gid: (by_guardrail_violations[gid] / n) if n else 0.0
        for gid, n in by_guardrail_constraints.items()
    }

    return EvalReport(
        runs=tuple(runs),
        violation_rate=violation_rate,
        violation_rate_by_guardrail=violation_rate_by_guardrail,
        total_constraints=total_constraints,
        total_violations=total_violations,
    )
