from releasetrain_triage_bench.classify import classify_component_risk_type, classify_version_bump
from releasetrain_triage_bench.types import RiskType, VersionBump


def test_major_bump_detected():
    assert classify_version_bump("5.15.0", "6.9.0") == VersionBump.MAJOR


def test_minor_bump_detected():
    assert classify_version_bump("1.24.0", "1.26.1") == VersionBump.MINOR


def test_patch_bump_detected():
    assert classify_version_bump("3.0.1", "3.0.14") == VersionBump.PATCH


def test_no_newer_version_is_unknown():
    assert classify_version_bump("2.0.0", "1.9.0") == VersionBump.UNKNOWN
    assert classify_version_bump("2.0.0", "2.0.0") == VersionBump.UNKNOWN


def test_missing_latest_version_is_unknown():
    assert classify_version_bump("2.0.0", None) == VersionBump.UNKNOWN


def test_unparseable_version_is_unknown():
    assert classify_version_bump("not-a-version", "2.0.0") == VersionBump.UNKNOWN
    assert classify_version_bump("2.0.0", "not-a-version") == VersionBump.UNKNOWN


def test_leading_v_is_handled():
    assert classify_version_bump("v5.15.0", "v6.9.0") == VersionBump.MAJOR


def test_foundational_keyword_match():
    assert classify_component_risk_type("Linux kernel") == RiskType.FOUNDATIONAL
    assert classify_component_risk_type("Docker Engine") == RiskType.FOUNDATIONAL
    assert classify_component_risk_type("OpenSSL") == RiskType.FOUNDATIONAL


def test_standard_when_no_keyword_matches():
    assert classify_component_risk_type("htop") == RiskType.STANDARD
    assert classify_component_risk_type("ripgrep") == RiskType.STANDARD


def test_match_is_case_insensitive():
    assert classify_component_risk_type("LINUX") == RiskType.FOUNDATIONAL
