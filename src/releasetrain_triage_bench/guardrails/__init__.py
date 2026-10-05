"""The Guardrail abstraction - the one piece of this package's design
that is NOT hardcoded, by direct request: guardrails are an INPUT to
evaluate() (see scorer.py), not a fixed list baked into the package.

Why a guardrail derives CONSTRAINTS, not a full ranking: a system that
delegates reasoning to an agent is supposed to add judgment beyond what a
deterministic rule could already decide. Scoring the agent against one
complete hardcoded ordering would penalize it for doing exactly that - a
full ranking forces an answer (and a tie-breaking rule) for every pair,
including pairs the guardrail's own stated policy has no opinion about. A
guardrail instead names only the pairs it has a real, unambiguous
position on ("if A is KEV-listed and B is not, A must not rank after B"),
and leaves every other pair for the system under test to decide freely.
Compliance is then measured as a violation rate against those specific,
derivable constraints - see scorer.py.

A guardrail is any object with a `derive_constraints` method matching the
signature below; this is a Protocol (structural typing), not an ABC a
user is required to subclass, so a guardrail can be as simple as a
function wrapped in a small class, or reuse this package's own reference
implementations in guardrails/security.py, guardrails/stability.py, and
guardrails/citation.py and compose/extend them.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..types import Constraint, Scenario


@runtime_checkable
class Guardrail(Protocol):
    #: a short, stable identifier for this guardrail, used to key
    #: EvalReport.violation_rate_by_guardrail - e.g. "security_kev_ordering".
    guardrail_id: str

    #: which optimize_for mode(s) this guardrail applies to; a guardrail
    #: not listed for the mode being evaluated is simply skipped by the
    #: scorer rather than erroring, so a caller can mix guardrails meant
    #: for different modes into one list without filtering first.
    applies_to_modes: tuple[str, ...]

    def derive_constraints(self, scenario: Scenario, mode: str) -> list[Constraint]:
        """Returns every pairwise constraint this guardrail's policy
        implies for this scenario, when evaluated under `mode`. Must be
        pure (no I/O, no randomness) - the whole point of deriving
        constraints from already-frozen ComponentFacts is that calling
        this twice on the same scenario/mode always returns the same
        constraints, which is what makes a reported violation rate
        reproducible by someone re-running only the harness, without
        needing to re-run the system under test at all."""
        ...
