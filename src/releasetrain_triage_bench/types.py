"""Core data types shared across every module in this package.

Kept in one place, deliberately with no behavior (no methods beyond plain
dataclass equality/repr) - every other module (guardrails, scorer, adapters,
dynamic pipeline) imports from here rather than redefining its own shape for
"a component" or "a ranked update". That is the modularization this package
is built around: a module can be tested in isolation because its inputs and
outputs are always one of the types below, never a module-specific ad hoc
dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class VersionBump(str, Enum):
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    UNKNOWN = "unknown"


class RiskType(str, Enum):
    FOUNDATIONAL = "foundational"  # OS kernel, hypervisor, core runtime - wide blast radius
    STANDARD = "standard"


@dataclass(frozen=True)
class EcosystemComponent:
    """One piece of installed software in a scenario. This is the only
    input shape a "system under test" (a TriageSystem adapter) ever
    receives - it never sees the frozen facts below directly, since those
    represent what the guardrail layer computed, not what a real caller
    would hand a triage system up front."""

    name: str
    installed_version: str
    vendor: str | None = None


@dataclass(frozen=True)
class ComponentFacts:
    """The deterministic, guardrail-computed facts for one component in one
    scenario, frozen into the benchmark snapshot at build time (see
    benchmark.py's own module docstring for why these are frozen rather than
    fetched live). Every guardrail in guardrails/ reads from this type and
    this type alone - a guardrail must never reach into a benchmark's raw
    source data itself, which is what keeps a new guardrail's own unit tests
    independent of how the benchmark was built.
    """

    component: str
    latest_version: str | None
    version_bump: VersionBump
    risk_type: RiskType
    cve_id: str | None = None
    cvss_score: float | None = None  # 0.0-10.0, NVD scale
    community_risk_flagged: bool = False  # a real, flagged-risky community report exists
    community_risk_url: str | None = None


@dataclass(frozen=True)
class TriagedUpdate:
    """One row of a triage system's output: its own ranking position and
    reasoning for one component. `order` is 1-indexed, 1 = highest
    priority - the only requirement is that it defines a total order
    across a system's response (ties are a modeling choice the system
    under test makes, not something this type enforces)."""

    component: str
    order: int
    reasoning: str = ""


@dataclass(frozen=True)
class Scenario:
    """One benchmark test case: a realistic set of installed components
    plus the frozen facts for each. `scenario_id` is stable across package
    versions so a reported violation can always be traced back to exactly
    which scenario produced it."""

    scenario_id: str
    components: tuple[EcosystemComponent, ...]
    facts: tuple[ComponentFacts, ...]

    def facts_for(self, component_name: str) -> ComponentFacts | None:
        for f in self.facts:
            if f.component == component_name:
                return f
        return None


@dataclass(frozen=True)
class Constraint:
    """A single, directional, pairwise rule a guardrail derives from a
    scenario's frozen facts: "component_a must not rank after component_b".
    Deliberately partial, not a full ordering - see guardrails/__init__.py's
    own module docstring for why a hard total order is the wrong thing to
    check a reasoning agent against."""

    scenario_id: str
    mode: str
    guardrail_id: str
    component_a: str
    component_b: str
    reason: str


@dataclass(frozen=True)
class Violation:
    """A Constraint that the system under test's actual output
    contradicted."""

    constraint: Constraint
    a_order: int
    b_order: int


@dataclass
class ScenarioRun:
    """The raw record of one (scenario, mode) run against one system -
    this is the artifact to persist/share for reproducibility (see the
    package README's own "what to share" section): it names exactly what
    was asked, which system answered, and what came back, independent of
    any later scoring."""

    scenario_id: str
    mode: str
    output: tuple[TriagedUpdate, ...]
    constraints: tuple[Constraint, ...] = field(default_factory=tuple)
    violations: tuple[Violation, ...] = field(default_factory=tuple)
    attempts: int = 1  # >1 only when run through the dynamic self-correction wrapper


@dataclass
class EvalReport:
    """The full output of evaluate() (see scorer.py). Every field here is
    derivable from `runs` alone - `violation_rate`/`violation_rate_by_guardrail`
    are precomputed for convenience, not independent sources of truth, so a
    reviewer re-deriving them from `runs` should always get the same numbers
    (see tests/test_scorer.py's own cross-check)."""

    runs: tuple[ScenarioRun, ...]
    violation_rate: dict[str, float]  # keyed by mode
    violation_rate_by_guardrail: dict[str, float]  # keyed by guardrail_id
    total_constraints: int
    total_violations: int
