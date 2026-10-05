"""The TriageSystem contract - the one thing any "system under test" must
implement to be scored by this package. Deliberately a Protocol (structural
typing, no required base class) so wrapping an existing system is always
possible without modifying it: write a small adapter class with a `triage`
method that calls into the real system however it needs to, and return
its output reshaped into TriagedUpdate - see adapters/http.py and
adapters/baseline.py for the two reference implementations this package
ships.
"""

from __future__ import annotations

from typing import Protocol, Sequence, runtime_checkable

from ..types import EcosystemComponent, TriagedUpdate


@runtime_checkable
class TriageSystem(Protocol):
    def triage(
        self,
        components: Sequence[EcosystemComponent],
        mode: str,
        feedback: str | None = None,
    ) -> list[TriagedUpdate]:
        """Given a list of installed components and an optimize_for mode
        ("security" | "stability" | "both"), return a ranked list of
        TriagedUpdate, one per input component, each with a distinct
        `order` (1 = highest priority) and a `reasoning` string. Must not
        mutate `components`. May raise - the harness (see scorer.py)
        treats a raised exception as a scenario the system failed to
        answer, not a crash of the eval run itself.

        `feedback`: None on a system's first attempt at a scenario; on a
        retry issued by the dynamic self-correction loop (see dynamic.py),
        a human-readable description of which constraints the previous
        attempt violated. A system with no notion of revision (e.g. a
        deterministic baseline) is free to ignore this parameter entirely
        - it exists so a real agentic system CAN use it to produce a
        genuinely revised answer, not so every system must act on it."""
        ...
