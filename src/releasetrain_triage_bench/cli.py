"""Command-line entry point: `releasetrain-triage-bench evaluate ...`.

Kept thin on purpose - it only wires together functions already defined
and tested elsewhere (benchmark loading, guardrail construction, the
scorer) rather than containing any evaluation logic of its own. This is
what "strong modularization" buys in practice: the CLI has nothing to
unit-test beyond argument parsing, because everything it calls is already
covered by its own module's tests.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .adapters.baseline import BaselineTriageSystem
from .adapters.http import HTTPTriageSystem
from .benchmark import load_benchmark, load_nvd_snapshot_v1, load_sample_benchmark
from .dynamic import evaluate_dynamic
from .guardrails.citation import CommunityRiskCitationGuardrail
from .guardrails.security import SecurityOrderingGuardrail
from .guardrails.stability import StabilityOrderingGuardrail
from .scorer import DEFAULT_MODES, evaluate


def default_guardrails():
    return [
        SecurityOrderingGuardrail(),
        StabilityOrderingGuardrail(),
        CommunityRiskCitationGuardrail(),
    ]


def _report_to_dict(report) -> dict:
    d = asdict(report)
    # ScenarioRun.output/constraints/violations are tuples of dataclasses;
    # asdict already recurses into them, this just keeps the top level tidy.
    return d


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="releasetrain-triage-bench")
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evaluate", help="Run a system against a benchmark and report guardrail compliance.")
    ev.add_argument("--benchmark",
                     help="Path to a benchmark JSON snapshot, or the keyword 'nvd' for the bundled "
                          "NVD-sourced snapshot. Defaults to the small illustrative sample.")
    ev.add_argument("--system", choices=["baseline", "http"], default="baseline",
                     help="Which reference adapter to use as the system under test.")
    ev.add_argument("--endpoint", help="Required when --system=http: the triage endpoint URL.")
    ev.add_argument("--modes", nargs="+", default=list(DEFAULT_MODES))
    ev.add_argument("--dynamic", action="store_true",
                     help="Run the bounded self-correction loop instead of a single static attempt.")
    ev.add_argument("--max-attempts", type=int, default=3)
    ev.add_argument("--out", help="Write the full JSON report here instead of stdout.")

    args = parser.parse_args(argv)

    if args.command == "evaluate":
        if not args.benchmark:
            scenarios = load_sample_benchmark()
        elif args.benchmark == "nvd":
            scenarios = load_nvd_snapshot_v1()
        else:
            scenarios = load_benchmark(args.benchmark)
        guardrails = default_guardrails()

        if args.system == "http":
            if not args.endpoint:
                parser.error("--endpoint is required when --system=http")
            system = HTTPTriageSystem(endpoint=args.endpoint)
        else:
            facts_by_component = {f.component: f for s in scenarios for f in s.facts}
            system = BaselineTriageSystem(facts_by_component=facts_by_component)

        if args.dynamic:
            from .dynamic import SelfCorrectionConfig
            report = evaluate_dynamic(
                scenarios, system, guardrails, modes=args.modes,
                config=SelfCorrectionConfig(max_attempts=args.max_attempts),
            )
        else:
            report = evaluate(scenarios, system, guardrails, modes=args.modes)

        output = json.dumps(_report_to_dict(report), indent=2, default=str)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
        print(
            f"\nviolation_rate: {report.violation_rate}\n"
            f"total_constraints={report.total_constraints} total_violations={report.total_violations}",
            file=sys.stderr,
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
