"""releasetrain-triage-bench: a reproducible benchmark harness for
measuring guardrail compliance in agentic software-update triage systems.

See the README for the full design rationale. This module only re-exports
the public surface - every real implementation lives in its own small,
independently-testable module (types, classify, guardrails/, adapters/,
benchmark, scorer, dynamic)."""

from .benchmark import load_benchmark, load_nvd_snapshot_v1, load_sample_benchmark
from .classify import classify_component_risk_type, classify_version_bump
from .dynamic import (
    SelfCorrectionConfig,
    evaluate_dynamic,
    format_feedback,
    run_scenario_with_self_correction,
)
from .guardrails import Guardrail
from .guardrails.citation import CommunityRiskCitationGuardrail
from .guardrails.security import SecurityOrderingGuardrail
from .guardrails.stability import StabilityOrderingGuardrail
from .scorer import DEFAULT_MODES, evaluate, run_scenario
from .types import (
    ComponentFacts,
    Constraint,
    EcosystemComponent,
    EvalReport,
    RiskType,
    Scenario,
    ScenarioRun,
    TriagedUpdate,
    VersionBump,
    Violation,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # types
    "EcosystemComponent", "ComponentFacts", "TriagedUpdate", "Scenario",
    "Constraint", "Violation", "ScenarioRun", "EvalReport",
    "VersionBump", "RiskType",
    # classify
    "classify_version_bump", "classify_component_risk_type",
    # guardrails
    "Guardrail", "SecurityOrderingGuardrail", "StabilityOrderingGuardrail",
    "CommunityRiskCitationGuardrail",
    # benchmark
    "load_benchmark", "load_sample_benchmark", "load_nvd_snapshot_v1",
    # scorer
    "evaluate", "run_scenario", "DEFAULT_MODES",
    # dynamic
    "evaluate_dynamic", "run_scenario_with_self_correction",
    "SelfCorrectionConfig", "format_feedback",
]
