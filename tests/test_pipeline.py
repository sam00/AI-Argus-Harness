"""End-to-end and unit tests for the AI-Argus-Harness pipeline."""

import json
from pathlib import Path

import pytest

from ai_argus.config import Config
from ai_argus.core import Orchestrator, ScanTarget
from ai_argus.core import auth as authmod
from ai_argus.core import cache as cache_mod
from ai_argus.core import suppressions as supp_mod
from ai_argus.core.auth import AUTH_STAGES, AuthMode
from ai_argus.core.context import ScanContext
from ai_argus.evidence import EvidenceStore
from ai_argus.llm import get_provider
from ai_argus.models import (
    Asset, AssetType, Category, Confidence, Evidence, Finding, IdentityHop, Impact,
    Owner, Relationship, Remediation, Severity, content_id,
)
from ai_argus.reliability import completeness_gate, verify_claims
from ai_argus.reliability.completeness_gate import _IDENTITY_PATH_REQUIRED
from ai_argus.reliability.grounding import grounded
from ai_argus.reliability.voting import vote
from ai_argus.reporting.sarif import to_sarif
from ai_argus.scanners.secrets import SecretsScanner
from ai_argus.scanners.endpoint import EndpointScanner
from ai_argus.scoring import deduplicate, score_finding

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _complete_finding(title="t", sev=Severity.HIGH,
                      category=Category.DATA_EXPOSURE.value):
    return Finding(
        title=title,
        asset=Asset.make(AssetType.CLOUD, "bucket-x"),
        category=category,
        severity=sev,
        confidence=Confidence.HIGH,
        evidence=[Evidence("cloud-api", "bucket is public", Confidence.HIGH)],
        identity_path=[IdentityHop("anon", "read", "bucket-x", Relationship.CAN_READ)],
        impact=Impact(business="data exposure", blast_radius="all objects"),
        remediation=Remediation(summary="block public access", steps=["x"]),
        owner=Owner(team="Cloud Security", service="bucket-x"),
    )


# --------------------------------------------------------------------------- #
def test_completeness_gate_promotes_complete_finding():
    f = _complete_finding()
    res = completeness_gate([f], strict=False)
    assert f in res.passed
    assert not res.review


def test_completeness_gate_routes_incomplete_to_review():
    f = _complete_finding()
    f.owner = Owner()  # remove owner -> incomplete
    res = completeness_gate([f], strict=False)
    assert f in res.review
    assert "owner" in res.reasons[f.finding_id]


def test_high_severity_privilege_requires_identity_path():
    # Privilege/access findings must show the access path at high+ severity.
    f = _complete_finding(sev=Severity.HIGH, category=Category.IDENTITY.value)
    f.identity_path = []
    res = completeness_gate([f], strict=False)
    assert f in res.review


def test_high_severity_exposure_exempt_from_identity_path():
    # Exposure/credential findings have an implicit principal and are NOT routed
    # to review solely for lacking an identity path.
    f = _complete_finding(sev=Severity.HIGH, category=Category.SECRETS.value)
    f.identity_path = []
    res = completeness_gate([f], strict=False)
    assert f in res.passed


def test_claim_verifier_drops_evidenceless_finding():
    f = _complete_finding()
    f.evidence = []
    verified, rejected = verify_claims([f])
    assert not verified and f in rejected


def test_scoring_is_deterministic():
    f1 = _complete_finding()
    f2 = _complete_finding()
    score_finding(f1)
    score_finding(f2)
    assert f1.risk_score == f2.risk_score
    assert f1.severity == f2.severity


def test_dedup_collapses_identical_findings():
    a = _complete_finding()
    b = _complete_finding()
    for f in (a, b):
        score_finding(f)
    out = deduplicate([a, b])
    assert len(out) == 1


def test_sarif_structure():
    f = _complete_finding()
    score_finding(f)
    doc = to_sarif([f])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]
    assert doc["runs"][0]["tool"]["driver"]["name"] == "AI-Argus-Harness"


# --------------------------------------------------------------------------- #
def test_offline_scan_end_to_end():
    cfg = Config()
    cfg.provider = "offline"
    cfg.cost_mode = "offline"
    cfg.profile = "enterprise"
    cfg.stealth_mode = "safe"
    cfg.workers = 1
    target = ScanTarget(
        raw=str(EXAMPLES / "vulnerable-sample"),
        kind="file",
        attributes={"path": str(EXAMPLES / "vulnerable-sample"),
                    "inventory_path": str(EXAMPLES / "inventory.json")},
    )
    result = Orchestrator(cfg).run(target)
    assert result.summary()["total_findings"] >= 8
    titles = [f.title for f in result.findings]
    assert any("storage bucket" in t for t in titles)
    assert any("hardcoded" in t for t in titles)
    # every promoted finding must be complete (evidence-first invariant)
    for f in result.findings:
        assert f.evidence
        assert f.owner.team or f.owner.service
        # identity path is mandatory only for privilege/access categories
        if f.severity.rank >= Severity.HIGH.rank and f.category in _IDENTITY_PATH_REQUIRED:
            assert f.identity_path


def test_offline_provider_is_zero_cost():
    cfg = Config()
    cfg.cost_mode = "offline"
    target = ScanTarget(raw=str(EXAMPLES / "vulnerable-sample"), kind="file",
                        attributes={"path": str(EXAMPLES / "vulnerable-sample")})
    result = Orchestrator(cfg).run(target)
    assert result.cost_summary["today_usd"] == 0


# --------------------------------------------------------------------------- #
# Regression tests for the reliability / efficiency / FP / hallucination work
# --------------------------------------------------------------------------- #
def test_finding_id_is_content_addressed():
    a = _complete_finding()
    b = _complete_finding()
    assert a.compute_id() == b.compute_id()           # deterministic across runs
    assert a.finding_id.startswith("FINDING-")
    c = _complete_finding(title="different")
    assert c.compute_id() != a.finding_id             # content changes the id


def test_evidence_store_is_content_addressed_and_dedupes():
    store = EvidenceStore()
    r1 = store.put("scanner", "same observation")
    r2 = store.put("scanner", "same observation")
    assert r1 == r2 and len(store.records) == 1       # identical evidence dedupes
    r3 = store.put("scanner", "another observation")
    assert r3 != r1 and len(store.records) == 2


def test_secrets_scoring_decoupled_from_severity():
    f = _complete_finding(category=Category.SECRETS.value)
    f.identity_path = []
    score_finding(f)
    # a hardcoded credential is intrinsically exploitable -> high, regardless of
    # any seed severity (exploitability no longer reads severity).
    assert f.severity.rank >= Severity.HIGH.rank


def _secrets_ctx(tmp_path):
    cfg = Config(); cfg.provider = "offline"
    return ScanContext(config=cfg, target=ScanTarget(
        raw=str(tmp_path), kind="file", attributes={"path": str(tmp_path)}))


def test_secrets_scanner_filters_placeholders(tmp_path):
    (tmp_path / "app.py").write_text(
        'api_key = "abcdef0123456789abcdef0123456789"\n'
        'password = "changeme"\n'
        'api_secret = "${ENV_TOKEN}"\n')
    res = SecretsScanner().run(_secrets_ctx(tmp_path))
    titles = [f.title for f in res.findings]
    assert any("API Key" in t for t in titles)        # real high-entropy key kept
    assert all("Password" not in t for t in titles)   # placeholder filtered


def test_secrets_scanner_prunes_noise_dirs(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"\n')
    res = SecretsScanner().run(_secrets_ctx(tmp_path))
    assert not res.findings                            # test/ dir pruned


def test_suppression_hides_finding():
    f = _complete_finding(); f.compute_id()
    rule = supp_mod.Suppression(match=f.finding_id, reason="accepted risk")
    kept, suppressed = supp_mod.apply([f], [rule])
    assert not kept and suppressed
    assert suppressed[0].review_status == "suppressed"


def test_expired_suppression_does_not_hide():
    f = _complete_finding(); f.compute_id()
    rule = supp_mod.Suppression(match=f.finding_id, reason="x", expires="2000-01-01")
    kept, suppressed = supp_mod.apply([f], [rule])
    assert kept and not suppressed


def test_incremental_diff_computation():
    d = cache_mod.compute_diff(["A", "B"], ["B", "C"])
    assert d.added == ["A"] and d.fixed == ["C"] and d.unchanged == ["B"]
    assert d.had_baseline is True


def test_offline_vote_supported_zero_disagreement():
    f = _complete_finding()
    v = vote(get_provider(Config()), f, n=3)           # offline provider
    assert v.verdict == "supported"
    assert v.disagreement == 0.0 and v.grounded is True


def test_grounding_flags_invented_entities():
    ev = [Evidence("cloud-api", "bucket prod-data is public", Confidence.HIGH)]
    ok, _ = grounded("The bucket prod-data is public.", ev)
    assert ok
    ok2, ungrounded = grounded("Also CVE-2023-99999 affects 10.0.0.5", ev)
    assert not ok2 and ungrounded                       # invented CVE/IP flagged


# --------------------------------------------------------------------------- #
# Authenticated vs non-authenticated scan (credential preflight)
# --------------------------------------------------------------------------- #
def test_parse_overrides_pairs():
    ov = authmod.parse_overrides(["aws=AWS_PROFILE", "gcp=@/tmp/k.json", "bad", "x="])
    assert ov == {"aws": "AWS_PROFILE", "gcp": "@/tmp/k.json"}


def test_auth_discovers_env_credential(monkeypatch):
    # presence only — the value is irrelevant and never read/stored.
    monkeypatch.setenv("OKTA_API_TOKEN", "irrelevant")
    st = authmod.discover_credentials(["saas"])["saas"]
    assert st.present and st.source == "env" and "OKTA_API_TOKEN" in st.ref


def test_auth_missing_when_absent(monkeypatch):
    for v in ("OKTA_API_TOKEN", "SLACK_TOKEN", "GITHUB_TOKEN", "SAAS_API_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    st = authmod.discover_credentials(["saas"])["saas"]   # saas has no cred files
    assert not st.present and st.required


def test_auth_override_uses_named_env(monkeypatch):
    monkeypatch.setenv("MY_SAAS_TOKEN", "irrelevant")
    st = authmod.discover_credentials(["saas"],
                                      overrides={"saas": "MY_SAAS_TOKEN"})["saas"]
    assert st.present and st.source == "override:env" and st.ref == "MY_SAAS_TOKEN"


def test_auth_inventory_census_takes_priority(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    inv = {"auth": {"aws": {"present": True, "ref": "vault://aws/prod"}}}
    st = authmod.discover_credentials(["aws"], inventory=inv)["aws"]
    assert st.present and st.source == "inventory" and st.ref == "vault://aws/prod"


def test_auth_resolution_satisfied_and_label():
    inv = {"credentials": {"aws": True, "gcp": True}}
    res = authmod.resolve(AuthMode.AUTHENTICATED, ["aws", "gcp"], inventory=inv)
    assert res.mode is AuthMode.AUTHENTICATED
    assert res.satisfied and not res.missing_services
    assert res.label("aws") == "authenticated"


def test_unauthenticated_resolution_marks_required_absent():
    res = authmod.unauthenticated(["aws", "saas"])
    assert res.mode is AuthMode.UNAUTHENTICATED
    assert not res.satisfied
    assert res.label("aws") == "unauthenticated"
    assert set(res.missing_services) == {"aws", "saas"}


def test_orchestrator_unauthenticated_by_default():
    cfg = Config(); cfg.provider = "offline"; cfg.cost_mode = "offline"
    target = ScanTarget(
        raw=str(EXAMPLES / "vulnerable-sample"), kind="file",
        attributes={"path": str(EXAMPLES / "vulnerable-sample"),
                    "inventory_path": str(EXAMPLES / "inventory.json")})
    result = Orchestrator(cfg).run(target)
    assert result.auth["mode"] == "unauthenticated"
    s0 = [e for e in result.stage_log if e.get("stage") == "S0"]
    assert s0 and s0[0]["applies_to"] == AUTH_STAGES   # preflight covers S1..S5.5


def test_orchestrator_authenticated_via_inventory_census():
    inv = json.loads((EXAMPLES / "inventory.json").read_text())
    inv["auth"] = {s: True for s in ("aws", "gcp", "kubernetes", "saas", "cicd")}
    cfg = Config(); cfg.provider = "offline"; cfg.cost_mode = "offline"
    cfg.profile = "enterprise"; cfg.auth_scan = True
    target = ScanTarget(
        raw=str(EXAMPLES / "vulnerable-sample"), kind="file",
        attributes={"path": str(EXAMPLES / "vulnerable-sample"), "inventory": inv})
    result = Orchestrator(cfg).run(target)
    a = result.auth
    assert a["mode"] == "authenticated" and a["satisfied"] is True
    assert {"aws", "gcp", "kubernetes", "saas", "cicd"}.issubset(
        set(a["authenticated_services"]))
    s1 = [e for e in result.stage_log
          if e.get("stage") == "S1" and e.get("status") == "done"]
    assert s1 and s1[0]["auth"] == "authenticated"


def test_orchestrator_explicit_auth_resolution_passthrough():
    # An explicitly supplied resolution is used verbatim (no re-discovery).
    res = authmod.unauthenticated(["aws"])
    cfg = Config(); cfg.provider = "offline"; cfg.cost_mode = "offline"
    cfg.auth_scan = True   # would otherwise authenticate; explicit arg wins
    target = ScanTarget(raw=str(EXAMPLES / "vulnerable-sample"), kind="file",
                        attributes={"path": str(EXAMPLES / "vulnerable-sample")})
    result = Orchestrator(cfg).run(target, auth=res)
    assert result.auth["mode"] == "unauthenticated"


# --------------------------------------------------------------------------- #
# Endpoint scanner (macOS / Linux / Windows posture, agent-driven)
# --------------------------------------------------------------------------- #
def _endpoint_ctx(devices):
    cfg = Config(); cfg.provider = "offline"
    return ScanContext(config=cfg, target=ScanTarget(
        raw="endpoints", kind="file",
        attributes={"inventory": {"devices": devices}}))


def test_endpoint_scanner_flags_posture_issues():
    devices = [{
        "host": "laptop-eng-014", "os": "macos", "environment": "prod",
        "edr": {"installed": True, "healthy": False},
        "disk_encryption": False, "patch_age_days": 200,
        "listening_ports": [3389], "local_admins": ["jdoe", "contractor-tmp"],
        "suspicious_libraries": ["/tmp/.x/libinject.dylib"],
        "software": [{"name": "openssl", "version": "1.0.1", "vulnerable": True}],
    }]
    res = EndpointScanner().run(_endpoint_ctx(devices))
    titles = " | ".join(f.title for f in res.findings)
    assert "Unhealthy EDR" in titles
    assert "Disk encryption disabled" in titles
    assert "Stale patch level" in titles
    assert "Risky service listening" in titles
    assert "Excessive local admin" in titles
    assert "Suspicious library" in titles
    assert "Vulnerable software" in titles
    # endpoint findings are complete and pass the gate without an identity path
    for f in res.findings:
        score_finding(f)
    gate = completeness_gate(res.findings, strict=False)
    assert gate.passed and not gate.review


def test_endpoint_scanner_no_edr_is_detection_gap():
    devices = [{"host": "win-1", "os": "windows", "edr": {"installed": False}}]
    res = EndpointScanner().run(_endpoint_ctx(devices))
    no_edr = [f for f in res.findings if "No EDR agent" in f.title]
    assert no_edr and no_edr[0].detection_gap is True


def test_endpoint_scanner_inapplicable_without_devices():
    cfg = Config(); cfg.provider = "offline"
    ctx = ScanContext(config=cfg, target=ScanTarget(
        raw="x", kind="file", attributes={}))
    assert EndpointScanner().applicable(ctx) is False
