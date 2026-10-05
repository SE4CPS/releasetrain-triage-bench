# releasetrain-triage-bench

A reproducible benchmark harness for measuring **guardrail compliance**
in agentic software-update triage systems.

## What this measures

Given a multi-agent pipeline that triages a list of installed software
into an update-priority ranking (e.g. "patch this CVE first, this minor
bump can wait"), this package does **not** ask "is this ranking
objectively correct?" or "does it match one hardcoded order?" Neither
question is answerable in a way that respects what an agent is actually
for: if a system delegates planning to an LLM instead of hardcoding every
rule, scoring it against one fixed total order punishes it for exercising
judgment at all.

Instead, this package asks: **given the explicit, codified guardrails a
pipeline was built with, does its actual output respect them?** A
guardrail here is a deterministic, auditable rule derived from real,
externally-verifiable facts (NIST NVD CVSS scores, version-bump size, a
small public component-criticality taxonomy) - not a full ranking, but a
set of *partial*, pairwise constraints the rule is confident about ("a
component with a known CVE must not be ranked below a component with no
known CVE"). Everywhere a guardrail has no opinion, the system
under test is free to use its own reasoning, and this harness never
penalizes that.

Compliance is reported as a **violation rate**: of every constraint a
guardrail could derive from a benchmark scenario, what fraction did the
system's actual output contradict?

## Install

```bash
pip install releasetrain-triage-bench
```

## Quick start

```bash
# Runs the small illustrative sample benchmark against the dependency-free
# baseline adapter - no server, no API key, no setup.
releasetrain-triage-bench evaluate

# Runs the real, NVD-sourced snapshot instead (see "The benchmark
# datasets" below) - still no setup needed, it's bundled too.
releasetrain-triage-bench evaluate --benchmark nvd
```

```python
from releasetrain_triage_bench import (
    load_sample_benchmark, evaluate, evaluate_dynamic,
    SecurityOrderingGuardrail, StabilityOrderingGuardrail, CommunityRiskCitationGuardrail,
)
from releasetrain_triage_bench.adapters.baseline import BaselineTriageSystem

scenarios = load_sample_benchmark()
facts = {f.component: f for s in scenarios for f in s.facts}
system = BaselineTriageSystem(facts_by_component=facts)
guardrails = [SecurityOrderingGuardrail(), StabilityOrderingGuardrail(), CommunityRiskCitationGuardrail()]

report = evaluate(scenarios, system, guardrails, modes=["security", "stability", "both"])
print(report.violation_rate)              # {"security": 0.0, "stability": 0.0, "both": 0.0}
print(report.violation_rate_by_guardrail) # per-guardrail breakdown
```

## Evaluating your own system

Implement the one-method `TriageSystem` contract - no base class required:

```python
class MyTriageSystem:
    def triage(self, components, mode, feedback=None):
        # components: list[EcosystemComponent] (name, installed_version, vendor)
        # mode: "security" | "stability" | "both"
        # feedback: None on a system's first attempt; on a retry issued by
        #           the dynamic self-correction loop, a plain-language
        #           description of which constraints the previous attempt
        #           violated (see "Static vs. dynamic" below). Safe to ignore.
        # returns: list[TriagedUpdate] (component, order, reasoning)
        ...
```

A thin, reference HTTP adapter is included for a system that runs behind
an HTTP API (`releasetrain_triage_bench.adapters.http.HTTPTriageSystem`)
so your **real, unmodified pipeline** can be evaluated by calling its own
endpoint - this package never reimplements the system it's scoring.

## The benchmark datasets

Two snapshots ship with the package:

- **`load_sample_benchmark()`** (`data/sample_benchmark.json`) - a small,
  hand-built set exercising every guardrail at least once. For validating
  the harness itself, not for reporting real numbers.
- **`load_nvd_snapshot_v1()`** (`data/nvd_snapshot_v1.json`) - built from
  live NIST NVD data by `scripts/build_snapshot.py`. For each
  (component, installed-version) pair, the script queries NVD and
  verifies a candidate CVE actually affects that product via the CVE's
  own structured CPE data (not just a keyword-search hit, which produces
  real false positives - e.g. "curl" as a keyword matches an unrelated
  Linux kernel CVE that happens to mention it in passing). If nothing
  verified is found, `cve_id`/`cvss_score` are left `None` rather than
  guessed. Which components/versions to simulate, and each component's
  `latest_version`, are curated (stated plainly, not hidden behind
  "automated"). The raw NVD API responses are committed in
  `scripts/.nvd_cache/`, so the exact facts behind every number are
  inspectable without depending on NVD's live API returning the same
  thing later - rerun `python scripts/build_snapshot.py` to regenerate
  from the cache, or add `--refresh`-style cache-busting yourself to pull
  fresh data.

```bash
releasetrain-triage-bench evaluate --benchmark nvd
```

## Bringing your own guardrails

Guardrails are a package **input**, not a fixed list baked in. Three
reference guardrails ship with this package
(`SecurityOrderingGuardrail`, `StabilityOrderingGuardrail`,
`CommunityRiskCitationGuardrail`, all in `guardrails/`), but any object
with a `derive_constraints(scenario, mode) -> list[Constraint]` method
and a `guardrail_id`/`applies_to_modes` pair can be passed to `evaluate()`
alongside or instead of them. Write your own to test a different policy
against the same benchmark.

## Static vs. dynamic pipelines

`evaluate()` runs a system once per scenario (static). `evaluate_dynamic()`
wraps the same system in a **bounded self-correction loop**: on a
violation, the harness's own violation report is fed back to the system
as corrective feedback, and it gets another attempt, up to
`SelfCorrectionConfig.max_attempts`. The loop has a clear, bounded stop
condition either way - zero violations (success) or the attempt ceiling
(bounded failure) - never an open-ended search.

```python
from releasetrain_triage_bench import evaluate_dynamic, SelfCorrectionConfig

report = evaluate_dynamic(scenarios, system, guardrails, config=SelfCorrectionConfig(max_attempts=3))
```

Comparing a static `EvalReport` against a dynamic one on the same system
and benchmark is the harness's second built-in experiment: does feeding a
system its own compliance failures measurably improve compliance?

## Reproducibility: what to share

This package is itself the scorer and the dataset-loading code. To make
a reported result independently checkable, also share:

1. **Raw outputs** - the `EvalReport.runs` from your actual run (each
   `ScenarioRun` records the system's real output, not just the score).
2. **The benchmark snapshot used** - a frozen JSON file (see
   `benchmark.load_benchmark`); the bundled `load_sample_benchmark()` is a
   small illustrative set for validating the harness itself, not a full
   reported-numbers benchmark (see `benchmark.py`'s own docstring).
3. **System configuration** - model name, temperature, and which
   guardrails/settings were in effect on the real system at eval time, if
   it has any of its own (e.g. admin-toggleable feature flags) that could
   change its behavior on a later run.

Do not share production credentials, API keys, or anything that
identifies you if this is being used for a double-anonymous submission -
only the triage-relevant code slice and the frozen facts are needed.

## Design notes

- **No part of this package reimplements the agentic pipeline being
  evaluated.** The adapter pattern exists specifically so the real
  system - LLM calls, prompts, its own guardrails - runs unmodified; this
  package only calls it and scores what comes back.
- **Guardrails derive partial constraints, never a full ranking**, so a
  reasoning system is never penalized for exercising judgment in a place
  its guardrails didn't specify an answer.
- **Every module is independently testable**: `classify.py` has no
  dependency on anything else in the package; `guardrails/*.py` depend
  only on `types.py`; `scorer.py` and `dynamic.py` are exercised against
  a fake `TriageSystem` in this package's own test suite, never a real
  network call. See `tests/` for the per-module test files.

## License

MIT
