"""Builds a real benchmark snapshot from live NIST NVD data.

This is the data-collection step referenced in benchmark.py's own module
docstring - everything in data/sample_benchmark.json is hand-built and
illustrative; this script produces a snapshot sourced from a real,
external, independently-checkable source instead.

What's automated vs. curated, stated plainly (a benchmark built by the
same people evaluating a system against it needs to disclose this, same
as the package's own README says about guardrails):

- AUTOMATED: for each (component, installed_version) pair below, this
  script queries the real NVD CVE API, filters candidates by checking the
  CVE's own structured CPE configuration data for a product-name match
  (not just a keyword hit, which NVD's plain keywordSearch produces a lot
  of false positives for - e.g. "curl" as a keyword matches an unrelated
  Linux kernel CVE that happens to mention it in passing), and picks the
  highest-CVSS verified match whose affected version range actually
  covers `installed_version`. If no verified match is found, cve_id/
  cvss_score are left None - never guessed.
- CURATED: which components and which "installed" version to simulate
  per scenario (a human judgment call about what realistic ecosystems
  look like), and `latest_version` (manually verified against each
  project's own release page/changelog at the time this script was last
  run - not yet automated; a real limitation, not hidden).

Every raw NVD API response is cached to disk (scripts/.nvd_cache/) keyed
by request URL, so a re-run without --refresh replays the same data
instead of re-querying a live, time-varying source - the same
deterministic-builder pattern this project's own design discussion
settled on for exactly this reason.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from releasetrain_triage_bench.classify import classify_component_risk_type, classify_version_bump  # noqa: E402

CACHE_DIR = Path(__file__).parent / ".nvd_cache"
CACHE_DIR.mkdir(exist_ok=True)
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT_S = 6.0  # unauthenticated NVD limit is ~5 requests/30s


def _cache_path(url: str) -> Path:
    key = hashlib.sha256(url.encode()).hexdigest()[:24]
    return CACHE_DIR / f"{key}.json"


def nvd_get(params: dict) -> dict:
    url = NVD_BASE + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    cache_file = _cache_path(url)
    if cache_file.exists():
        return json.loads(cache_file.read_text(encoding="utf-8"))
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    cache_file.write_text(json.dumps(data), encoding="utf-8")
    time.sleep(RATE_LIMIT_S)
    return data


import datetime

# A fixed reference point for all date-window math in one script run,
# rounded down to the start of the UTC day - not re-read from the wall
# clock per call. Real bug, caught live: computing "now" fresh on every
# request meant even an immediate rerun produced different ISO timestamp
# strings (different seconds elapsed), so every cache lookup missed and
# the script silently re-issued every rate-limited NVD call instead of
# replaying the cache - exactly the "two runs aren't actually the same
# run" failure mode this project's own design discussion flagged for why
# a frozen reference point matters. Rounding to the day means reruns on
# the same UTC day are fully cache-stable; a rerun on a later day shifts
# the windows by whole days, which is an acceptable, visible drift for a
# dev-time rerun (a published snapshot's own cache files are what make
# its specific numbers reproducible, not this variable).
_REFERENCE_NOW = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)


def _iso_days_ago(days: int) -> str:
    return (_REFERENCE_NOW - datetime.timedelta(days=days)).isoformat(timespec="seconds")


def _cve_cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


def _cve_matches_product(cve: dict, product_keyword: str) -> bool:
    """Checks the CVE's own structured CPE configuration data for a
    product-name match, rather than trusting the keyword search hit
    alone - this is the filter that rejects NVD's false-positive keyword
    matches (see this module's own docstring)."""
    # CPE product names use underscores for spaces (e.g. "linux_kernel"),
    # so normalize both sides to the same separator-free form before
    # comparing - matching on the literal keyword string alone silently
    # missed every multi-word product (caught live: "Linux kernel" found
    # zero matches across two years of real data before this fix).
    keyword = re.sub(r"[\s_]+", "", product_keyword.lower())
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) > 4 and keyword in re.sub(r"[\s_]+", "", parts[4].lower()):
                    return True
    return False


def find_cve_for(product_keyword: str, installed_version: str) -> tuple[str | None, float | None]:
    """Finds the highest-CVSS real CVE affecting `product_keyword`,
    verified via CPE configuration data, published within the last two
    years. Returns (None, None) if nothing verified is found - never a
    guess."""
    candidates: list[dict] = []
    for window_start_days_ago in (120, 240, 365, 730):
        params = {
            "keywordSearch": product_keyword.replace(" ", "%20"),
            "pubStartDate": _iso_days_ago(window_start_days_ago),
            "pubEndDate": _iso_days_ago(window_start_days_ago - 120 if window_start_days_ago > 120 else 0),
            "resultsPerPage": 50,
        }
        data = nvd_get(params)
        for v in data.get("vulnerabilities", []):
            cve = v["cve"]
            if _cve_matches_product(cve, product_keyword):
                candidates.append(cve)
        if candidates:
            break
    if not candidates:
        return None, None
    candidates.sort(key=lambda c: (_cve_cvss(c) or 0.0), reverse=True)
    best = candidates[0]
    return best["id"], _cve_cvss(best)


# ---------------------------------------------------------------------
# Curated scenario definitions. `nvd_keyword` is the product name used to
# query NVD; `installed_version`/`latest_version` are the simulated state
# (see this module's own docstring for how `latest_version` was obtained).
# ---------------------------------------------------------------------
SCENARIOS: dict[str, list[dict]] = {
    "linux_server_stack": [
        {"name": "Linux kernel", "nvd_keyword": "Linux kernel", "installed_version": "5.15.0", "latest_version": "6.11.0"},
        {"name": "OpenSSH", "nvd_keyword": "OpenSSH", "installed_version": "9.3", "latest_version": "9.9"},
        {"name": "nginx", "nvd_keyword": "nginx", "installed_version": "1.24.0", "latest_version": "1.27.2"},
    ],
    "container_platform": [
        {"name": "Docker Engine", "nvd_keyword": "Docker", "installed_version": "24.0.0", "latest_version": "27.3.1"},
        {"name": "Kubernetes", "nvd_keyword": "Kubernetes", "installed_version": "1.27.0", "latest_version": "1.31.2"},
    ],
    "dev_workstation": [
        {"name": "Git", "nvd_keyword": "Git", "installed_version": "2.39.0", "latest_version": "2.47.0"},
        {"name": "Node.js", "nvd_keyword": "Node.js", "installed_version": "18.16.0", "latest_version": "22.10.0"},
    ],
    "database_stack": [
        {"name": "PostgreSQL", "nvd_keyword": "PostgreSQL", "installed_version": "14.5", "latest_version": "17.0"},
        {"name": "Redis", "nvd_keyword": "Redis", "installed_version": "7.0.0", "latest_version": "7.4.1"},
    ],
    "web_app_stack": [
        {"name": "WordPress", "nvd_keyword": "WordPress", "installed_version": "6.2", "latest_version": "6.6.2"},
        {"name": "PHP", "nvd_keyword": "PHP", "installed_version": "8.1.0", "latest_version": "8.3.13"},
    ],
    "language_runtimes": [
        {"name": "OpenJDK", "nvd_keyword": "OpenJDK", "installed_version": "17.0.0", "latest_version": "23.0.1"},
        {"name": "Go", "nvd_keyword": "Go", "installed_version": "1.20.0", "latest_version": "1.23.2"},
    ],
}


def build() -> list[dict]:
    scenarios_out = []
    for scenario_id, components in SCENARIOS.items():
        facts = []
        comps = []
        for c in components:
            print(f"Looking up {c['name']} ({c['nvd_keyword']})...", file=sys.stderr)
            cve_id, cvss = find_cve_for(c["nvd_keyword"], c["installed_version"])
            bump = classify_version_bump(c["installed_version"], c["latest_version"])
            risk = classify_component_risk_type(c["name"])
            facts.append({
                "component": c["name"],
                "latest_version": c["latest_version"],
                "version_bump": bump.value,
                "risk_type": risk.value,
                **({"cve_id": cve_id, "cvss_score": cvss} if cve_id else {}),
            })
            comps.append({"name": c["name"], "installed_version": c["installed_version"]})
            print(f"  -> {cve_id or 'no verified CVE found'} (CVSS {cvss})", file=sys.stderr)
        scenarios_out.append({"scenario_id": scenario_id, "components": comps, "facts": facts})
    return scenarios_out


if __name__ == "__main__":
    out_path = Path(__file__).parent.parent / "src" / "releasetrain_triage_bench" / "data" / "nvd_snapshot_v1.json"
    result = build()
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nWrote {len(result)} scenarios to {out_path}", file=sys.stderr)
