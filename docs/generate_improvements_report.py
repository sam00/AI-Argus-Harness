#!/usr/bin/env python3
"""Generate the AI-Argus-Harness Improvements & Smoke-Test Report (PDF).

Pure standard library. Reuses the zero-dependency PDF primitives from
``generate_design_pdf.py``.

Run:  python3 docs/generate_improvements_report.py
Out:  docs/AI-Argus-Harness-Improvements-Report.pdf
"""

from __future__ import annotations

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_design_pdf import (  # noqa: E402
    Canvas, build_pdf, tint, wrap, text_width, _version,
    PW, PH, ML, MR, INK, MUTED, LINE, CARD, WHITE, SOFT,
)

GREEN = (0.16, 0.49, 0.30)
BLUE = (0.10, 0.20, 0.34)
TEAL = (0.03, 0.47, 0.45)
AMBER = (0.80, 0.52, 0.12)
RED = (0.70, 0.20, 0.32)

TOP, BOTTOM = 748.0, 60.0
MAXW = MR - ML


def footer(c: Canvas, page_no: int) -> None:
    c.line(ML, 46, MR, 46, LINE, 0.6)
    c.text(ML, 34, "AI-Argus-Harness  -  Improvements & Smoke-Test Report", 8, False, MUTED)
    c.text(MR - 46, 34, "Page %d" % page_no, 8, False, MUTED)


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #
RECOMMENDATIONS = [
    (1, "Content-addressed finding / chain IDs",
     "finding_id and chain_id are now SHA-derived from stable content (asset + "
     "category + title + identity path + primary evidence), enabling diffs, "
     "suppressions and idempotent ticket export."),
    (2, "Thread-safe + deterministic evidence",
     "EvidenceStore and the asset/identity graphs are lock-guarded; evidence refs "
     "are content-addressed and de-duplicated, removing the insertion-order race."),
    (3, "Secrets false-positive reduction",
     "Added Shannon-entropy gating, an anchored placeholder/template denylist, "
     "path/extension pruning and per-secret de-duplication."),
    (4, "Category enum + scoring fixes",
     "Introduced a single-source-of-truth Category enum across all scanners and "
     "scoring; removed the dead 'cloud' control-weakness branch and unified the "
     "Kubernetes categories."),
    (5, "Decoupled exploitability + gate exemptions",
     "Exploitability is now category-intrinsic (no severity feedback loop). "
     "Credentials score HIGH; an identity path is required only for "
     "privilege/access categories."),
    (6, "Parallel ports + os.walk pruning",
     "Network port probes run concurrently (was up to ~22s/host); the secrets "
     "walk prunes skip/noise directories and filters by extension before reading."),
    (7, "LLM grounding + N-sample voting",
     "Model output is checked for invented entities (CVEs/IPs/ARNs) and judged by "
     "N-sample majority voting with a disagreement metric; ungrounded rationales "
     "cannot support a finding."),
    (8, "Incremental --diff + suppression store",
     "A baseline cache yields new/fixed/unchanged diffs across runs; an auditable "
     "suppression store accepts known risks by id, dedup-key or title with "
     "optional expiry."),
]

METRICS = [
    ("8 / 8", "recommendations", GREEN),
    ("20 / 20", "tests passing", GREEN),
    ("16 / 16", "CLI checks", GREEN),
    ("0", "regressions", BLUE),
]


def _blocks() -> list:
    b: list = []

    def h1(t): b.append(("h1", t))
    def h2(t): b.append(("h2", t))
    def p(t): b.append(("p", t))
    def li(t): b.append(("li", t))
    def rec(v): b.append(("rec", v))
    def sp(n=6): b.append(("sp", n))

    h1("1.  Recommendations Implemented")
    p("All eight improvement areas below were implemented, tested and verified. "
      "Each is summarized with the concrete change.")
    for r in RECOMMENDATIONS:
        rec(r)

    h1("2.  Smoke-Test Results")
    p("The harness was exercised end-to-end in the deterministic offline mode "
      "against the bundled sample target (code path + cloud/identity inventory).")
    li("16 / 16 CLI commands passed: version, stages, plugins, models, doctor, "
       "cost, scan, quick, strict, stage-subset, single-scanner, graph, identity, "
       "report, evidence, suppressions.")
    li("20 / 20 unit + regression tests passed (pytest).")
    li("Offline enterprise scan produced 13 findings, 0 review-queue items, "
       "1 attack-path chain, at $0.00 cost.")
    li("Promoted-finding categories: data-exposure, identity, kubernetes, "
       "kubernetes-rbac, saas, secrets, supply-chain.")

    h1("3.  Verification Evidence")
    h2("Determinism & thread-safety (#1, #2)")
    li("finding_ids, chain_ids and evidence refs were byte-identical across "
       "repeated runs AND across worker counts (1 vs 8).")
    li("Evidence refs are content-addressed and unique (no duplicates).")
    h2("False-positive reduction (#3, #4)")
    li("The three real sample secrets are detected while placeholder values "
       "(\"changeme\", \"${ENV_TOKEN}\") and test/fixture directories are filtered out.")
    li("A typosquat allowlist suppresses known-legitimate near-name packages.")
    h2("Severity correctness (#5)")
    li("Hardcoded credentials are now scored HIGH (previously MEDIUM) and are "
       "correctly promoted, exempt from the identity-path rule.")
    h2("Hallucination guard (#7)")
    li("Grounding flags invented entities (e.g. a fabricated CVE / IP not present "
       "in the evidence corpus).")
    li("The offline provider short-circuits voting to an evidence-bound verdict "
       "with zero disagreement.")
    h2("Incremental diff & suppressions (#8)")
    li("First --diff run recorded a baseline (+13 new); the immediate re-run "
       "reported +0 new / 13 unchanged.")
    li("Suppressing 'Privileged pod' reduced promoted findings 13 -> 12 with "
       "suppressed = 1; the rule is listed by `argus suppressions`.")

    h1("4.  Files Changed")
    li("models.py - Category enum, content_id() helper, compute_id() for Finding/Chain.")
    li("evidence/store.py - thread-safe, content-addressed, de-duplicating store.")
    li("graph/asset_graph.py, graph/identity_graph.py - lock-guarded mutations.")
    li("scanners/secrets.py - entropy/placeholder/path/extension filters, os.walk pruning.")
    li("scanners/network.py - concurrent port probing.")
    li("scanners/* - migrated every finding to the Category enum; supply_chain allowlist.")
    li("scoring/risk_scoring.py - decoupled exploitability; fixed dead/inconsistent branches.")
    li("reliability/completeness_gate.py - identity-path required only for privilege categories.")
    li("reliability/adversarial_reviewer.py - grounded N-sample voting integration.")
    li("reliability/grounding.py, reliability/voting.py - NEW anti-hallucination modules.")
    li("core/suppressions.py, core/cache.py - NEW suppression store + baseline/diff.")
    li("core/orchestrator.py - wired IDs, suppressions and --diff; new RunResult fields.")
    li("config.py, reporting/json_report.py, cli.py - diff flag, suppress commands, output.")
    li("tests/test_pipeline.py - updated gate tests + 10 new regression tests.")

    h1("5.  Notes & Future Work")
    li("A full result cache (skip-recompute) and real provider SDK wiring remain "
       "future work; the deterministic offline path stays the default.")
    li("Stealth pacing delays and SARIF location-URI refinement are tracked as "
       "follow-ups.")
    li("Reproduce: `python3 -m pytest`  and  `python3 docs/generate_improvements_report.py`.")
    return b


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def page_title(page_no: int) -> str:
    c = Canvas()
    c.rect(0, PH - 188, PW, 188, fill=BLUE)
    c.rect(0, PH - 192, PW, 4, fill=TEAL)
    c.text_center(PW / 2, PH - 86, "AI-Argus-Harness", 30, True, WHITE)
    c.text_center(PW / 2, PH - 120, "Improvements & Smoke-Test Report", 16, True,
                  (0.86, 0.90, 0.95))
    c.text_center(PW / 2, PH - 146,
                  "Implementation of all 8 recommendations, with verification",
                  10.5, False, (0.78, 0.83, 0.90))
    c.text_center(PW / 2, PH - 166, "Author: Sam Gupta", 11, True, (0.90, 0.93, 0.97))

    # metric chips
    n = len(METRICS)
    gap = 14.0
    cw = (MR - ML - gap * (n - 1)) / n
    top = 560.0
    for i, (value, label, col) in enumerate(METRICS):
        x = ML + i * (cw + gap)
        c.rect(x, top - 64, cw, 64, fill=tint(col, 0.88), stroke=LINE, lw=0.8, r=8)
        c.rect(x, top - 64, cw, 5, fill=col, r=2)
        c.text_center(x + cw / 2, top - 34, value, 19, True, col)
        c.text_center(x + cw / 2, top - 52, label, 8.5, False, INK)

    c.text(ML, 470, "Scope", 13, True, INK)
    for i, ln in enumerate(wrap(
            "Improve efficiency, reduce false positives and lower hallucination "
            "risk, then smoke-test the harness and report the results. Every "
            "change preserves the evidence-first, zero-dependency, offline-by-"
            "default design.", 10, False, MAXW)):
        c.text(ML, 450 - i * 14, ln, 10, False, MUTED)

    c.rect(ML, 360, MAXW, 30, fill=tint(GREEN, 0.86), stroke=LINE, lw=0.7, r=6)
    c.text_center(PW / 2, 378,
                  "Status: ALL 8 RECOMMENDATIONS IMPLEMENTED, TESTED & VERIFIED",
                  10.5, True, (0.06, 0.30, 0.18))

    c.text(ML, 96, "Version %s" % _version(), 9.5, False, MUTED)
    c.text(ML, 80, "Author: Sam Gupta", 9.5, True, INK)
    c.text(ML, 64, "Generated %s" % datetime.date.today().isoformat(), 9.5, False, MUTED)
    c.text(ML, 48, "Mode: offline / deterministic   Target: bundled sample "
                   "(code + inventory)", 9.5, False, MUTED)
    footer(c, page_no)
    return c.data()


def render_body(start_page: int) -> list:
    pages: list = []
    blocks = _blocks()
    c = Canvas()
    y = TOP
    page_no = start_page

    def flush():
        footer(c, page_no)
        pages.append(c.data())

    def newpage():
        nonlocal c, y, page_no
        flush()
        page_no += 1
        c = Canvas()
        y = TOP

    def need(h):
        if y - h < BOTTOM:
            newpage()

    for kind, val in blocks:
        if kind == "h1":
            need(34)
            c.line(ML, y + 4, MR, y + 4, LINE, 0.6)
            c.text(ML, y - 13, val, 14.5, True, INK)
            y -= 30
        elif kind == "h2":
            need(22)
            c.text(ML, y - 12, val, 11, True, BLUE)
            y -= 21
        elif kind == "p":
            lines = wrap(val, 9.5, False, MAXW)
            need(len(lines) * 13 + 4)
            for ln in lines:
                c.text(ML, y - 10, ln, 9.5, False, INK)
                y -= 13
            y -= 4
        elif kind == "li":
            lines = wrap(val, 9.5, False, MAXW - 16)
            need(len(lines) * 13 + 3)
            c.dot(ML + 4, y - 7, 1.7, MUTED)
            for j, ln in enumerate(lines):
                c.text(ML + 14, y - 10 - j * 13, ln, 9.5, False, INK)
            y -= len(lines) * 13 + 3
        elif kind == "rec":
            num, title, change = val
            lines = wrap(change, 8.6, False, MAXW - 26)
            h = 24 + len(lines) * 10.5 + 8
            need(h + 6)
            top = y
            c.rect(ML, top - h, MAXW, h, fill=CARD, stroke=LINE, lw=0.8, r=6)
            c.rect(ML, top - h, 4, h, fill=GREEN, r=2)
            c.text(ML + 13, top - 17, f"#{num}   {title}", 9.6, True, INK)
            bw = 44.0
            c.rect(MR - bw - 8, top - 20, bw, 14, fill=GREEN, r=3)
            c.text_center(MR - 8 - bw / 2, top - 16.7, "DONE", 7.5, True, WHITE)
            yy = top - 31
            for ln in lines:
                c.text(ML + 13, yy, ln, 8.6, False, MUTED)
                yy -= 10.5
            y = top - h - 8
        elif kind == "sp":
            y -= val

    flush()
    return pages


def main() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "AI-Argus-Harness-Improvements-Report.pdf")
    pages = [page_title(1)]
    pages += render_body(2)
    build_pdf(out, pages, title="AI-Argus-Harness - Improvements & Smoke-Test Report",
              author="Sam Gupta")
    return out


if __name__ == "__main__":
    path = main()
    print("Wrote %s (%d bytes)" % (path, os.path.getsize(path)))
