#!/usr/bin/env python3
"""Generate the AI-Argus-Harness Structure & Design PDF (pure stdlib, no deps).

Run:  python3 docs/generate_design_pdf.py
Out:  docs/AI-Argus-Harness-Design.pdf
"""

from __future__ import annotations

import os
from typing import List, Tuple

PW, PH = 612.0, 792.0
ML, MR = 54.0, 558.0
KAPPA = 0.5523

INK = (0.13, 0.15, 0.20)
MUTED = (0.42, 0.46, 0.53)
LINE = (0.80, 0.83, 0.88)
CARD = (0.965, 0.975, 0.99)
WHITE = (1, 1, 1)
SOFT = (0.94, 0.96, 0.98)

PHASE_COLORS = {
    "discovery": (0.13, 0.36, 0.60),
    "identity": (0.30, 0.25, 0.56),
    "analysis": (0.80, 0.52, 0.12),
    "evidence": (0.03, 0.47, 0.45),
    "reliability": (0.70, 0.20, 0.32),
    "risk": (0.16, 0.49, 0.30),
    "reporting": (0.45, 0.27, 0.56),
}

PHASES: List[Tuple[str, str]] = [
    ("discovery", "Discovery"),
    ("identity", "Identity"),
    ("analysis", "Threat Analysis"),
    ("evidence", "Evidence & Verification"),
    ("reliability", "Reliability Review"),
    ("risk", "Risk Intelligence"),
    ("reporting", "Reporting & Governance"),
]

# code, name, phase, short feature, long feature, output, module
STAGES = [
    ("S0", "Credential Preflight", "discovery",
     "Authenticated vs non-authenticated; discover credentials for target services",
     "At the start of a scan, chooses an authenticated or non-authenticated run. For an "
     "authenticated scan it discovers credentials for the services about to be scanned "
     "(operator override, inventory credential census, environment variables, standard "
     "credential files); if none are found it prompts for a key or continues "
     "non-authenticated. Records only references (env-var name / file path), never "
     "secret values, and probes no third-party hosts. This auth context applies to "
     "stages S1-S5.5.",
     "Per-service credential status (authenticated / unauthenticated)",
     "core/auth.py, core/orchestrator.py (S0)"),
    ("S1", "Attack-Surface Mapper", "discovery",
     "DNS, TLS, ports, subdomains -> asset graph",
     "Maps the external footprint (DNS, TLS, open ports, technologies, sensitive "
     "subdomains) and builds the enterprise asset graph.",
     "Assets + attack-surface evidence",
     "scanners/domain.py, scanners/network.py, graph/asset_graph.py"),
    ("S1.5", "Identity & Access Graph Builder", "identity",
     "Identity as a first-class graph; privileged & blind-spot paths",
     "Treats identity as a first-class graph; ingests users, roles, service accounts, "
     "OAuth apps and CI identities; finds privileged and blind-spot paths.",
     "Identity graph + access edges", "graph/identity_graph.py"),
    ("S2", "Threat Modeler", "analysis",
     "Threat hypotheses per asset",
     "Derives the likely threats against each discovered asset to focus research.",
     "Threat hypotheses per asset", "core/orchestrator.py (S2)"),
    ("S3", "Research Strategist", "analysis",
     "Plans which research lenses to run",
     "Plans which research lenses and scanners to run for the target and budget.",
     "Research plan", "core/orchestrator.py (S3)"),
    ("S4", "Research Lenses", "analysis",
     "Parallel deterministic scanners collect evidence",
     "Runs deterministic, plugin-based scanners in parallel to gather structured "
     "evidence (cloud, k8s, secrets, supply chain, SaaS, application).",
     "Candidate findings + evidence", "scanners/*"),
    ("S5", "Evidence Collector", "evidence",
     "Normalize & de-dupe source-bound evidence",
     "Normalizes and de-duplicates source-bound evidence from all scanners; redacts "
     "secrets; persists evidence for replay.",
     "Normalized evidence store", "evidence/normalizer.py, evidence/store.py"),
    ("S5.5", "Controlled Offensive Verification", "evidence",
     "Safe, non-destructive verification",
     "Safely verifies findings with no destructive actions; honors passive/safe/auth/"
     "stealth modes; no exploitation, persistence or exfiltration.",
     "Verified vs rejected claims", "reliability/claim_verifier.py"),
    ("S6", "Adversarial Reviewer", "reliability",
     "Challenge weak claims; track disagreement",
     "Challenges weak or unsupported conclusions and tracks multi-agent disagreement; "
     "can add an independent, evidence-bound model opinion.",
     "Challenged / adjusted findings", "reliability/adversarial_reviewer.py"),
    ("S6.5", "Single-Pass Validator", "reliability",
     "Structural / schema validation",
     "Performs structural and schema validation of every finding's shape and fields.",
     "Validated findings", "reliability/validator.py"),
    ("S7", "Deduplication", "risk",
     "Collapse by asset / root-cause / identity / owner",
     "Collapses related findings by asset, root cause, identity path and remediation owner.",
     "Unique findings", "scoring/dedup.py"),
    ("S8", "Chain Construction", "risk",
     "Link findings into attack paths",
     "Links findings that share assets or identities into multi-step attack paths.",
     "Attack-path chains", "chaining/chain_constructor.py"),
    ("S8.5", "Detection & Control Coverage", "risk",
     "Flag detection blind spots",
     "Reviews detection blind spots and weak controls, feeding the risk score.",
     "Detection-gap signals", "scoring/risk_scoring.py"),
    ("S9", "Report Generator", "reporting",
     "Deterministic scoring + multi-format reports",
     "Deterministically scores and prioritizes findings, then emits SARIF, JSON, "
     "Markdown, executive summary and tickets.",
     "Enterprise reports", "scoring/risk_scoring.py, reporting/*"),
    ("S10", "Human Review / Exceptions", "reporting",
     "Gate promotes complete findings; rest to humans",
     "The completeness gate promotes only complete findings; the rest are routed to a "
     "human review / exception workflow.",
     "Review queue + promoted findings", "reliability/completeness_gate.py"),
]


def _n(v: float) -> str:
    return ("%.2f" % v).rstrip("0").rstrip(".")


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Canvas:
    """Accumulates PDF content-stream operators for one page."""

    def __init__(self) -> None:
        self.ops: List[str] = []

    def data(self) -> str:
        return "\n".join(self.ops)

    # -- color / state ------------------------------------------------- #
    def fill(self, c) -> None:
        self.ops.append(f"{_n(c[0])} {_n(c[1])} {_n(c[2])} rg")

    def stroke(self, c) -> None:
        self.ops.append(f"{_n(c[0])} {_n(c[1])} {_n(c[2])} RG")

    def lw(self, w: float) -> None:
        self.ops.append(f"{_n(w)} w")

    # -- primitives ---------------------------------------------------- #
    def rect(self, x, y, w, h, fill=None, stroke=None, lw=1.0, r=0.0) -> None:
        if r > 0:
            self._round_path(x, y, w, h, r)
        else:
            self.ops.append(f"{_n(x)} {_n(y)} {_n(w)} {_n(h)} re")
        if fill is not None and stroke is not None:
            self.fill(fill); self.stroke(stroke); self.lw(lw); self.ops.append("B")
        elif fill is not None:
            self.fill(fill); self.ops.append("f")
        elif stroke is not None:
            self.stroke(stroke); self.lw(lw); self.ops.append("S")

    def _round_path(self, x, y, w, h, r) -> None:
        k = r * KAPPA
        x2, y2 = x + w, y + h
        a = self.ops.append
        a(f"{_n(x+r)} {_n(y)} m")
        a(f"{_n(x2-r)} {_n(y)} l")
        a(f"{_n(x2-r+k)} {_n(y)} {_n(x2)} {_n(y+r-k)} {_n(x2)} {_n(y+r)} c")
        a(f"{_n(x2)} {_n(y2-r)} l")
        a(f"{_n(x2)} {_n(y2-r+k)} {_n(x2-r+k)} {_n(y2)} {_n(x2-r)} {_n(y2)} c")
        a(f"{_n(x+r)} {_n(y2)} l")
        a(f"{_n(x+r-k)} {_n(y2)} {_n(x)} {_n(y2-r+k)} {_n(x)} {_n(y2-r)} c")
        a(f"{_n(x)} {_n(y+r)} l")
        a(f"{_n(x)} {_n(y+r-k)} {_n(x+r-k)} {_n(y)} {_n(x+r)} {_n(y)} c")
        a("h")

    def line(self, x1, y1, x2, y2, color=LINE, w=1.0) -> None:
        self.stroke(color); self.lw(w)
        self.ops.append(f"{_n(x1)} {_n(y1)} m {_n(x2)} {_n(y2)} l S")

    def dot(self, cx, cy, r, color) -> None:
        self.rect(cx - r, cy - r, 2 * r, 2 * r, fill=color, r=r)

    def tri(self, pts, color) -> None:
        self.fill(color)
        (x0, y0), (x1, y1), (x2, y2) = pts
        self.ops.append(f"{_n(x0)} {_n(y0)} m {_n(x1)} {_n(y1)} l "
                        f"{_n(x2)} {_n(y2)} l h f")

    def arrow_right(self, x1, y, x2, color, w=1.4) -> None:
        self.line(x1, y, x2 - 3, y, color, w)
        self.tri([(x2, y), (x2 - 5, y + 3), (x2 - 5, y - 3)], color)

    def arrow_down(self, x, y1, y2, color, w=1.4) -> None:
        self.line(x, y1, x, y2 + 3, color, w)
        self.tri([(x, y2), (x - 3, y2 + 5), (x + 3, y2 + 5)], color)

    # -- text ---------------------------------------------------------- #
    def text(self, x, y, s, size=10.0, bold=False, color=INK) -> None:
        f = "F2" if bold else "F1"
        self.ops.append(
            f"BT /{f} {_n(size)} Tf {_n(color[0])} {_n(color[1])} {_n(color[2])} rg "
            f"{_n(x)} {_n(y)} Td ({_esc(s)}) Tj ET")

    def text_center(self, cx, y, s, size=10.0, bold=False, color=INK) -> None:
        self.text(cx - text_width(s, size, bold) / 2.0, y, s, size, bold, color)


def text_width(s: str, size: float, bold: bool) -> float:
    factor = 0.55 if bold else 0.52
    return len(s) * size * factor


def wrap(s: str, size: float, bold: bool, maxw: float) -> List[str]:
    words, lines, cur = s.split(), [], ""
    for wd in words:
        trial = (cur + " " + wd).strip()
        if text_width(trial, size, bold) <= maxw or not cur:
            cur = trial
        else:
            lines.append(cur); cur = wd
    if cur:
        lines.append(cur)
    return lines


def build_pdf(path: str, pages: List[str], title: str = "", author: str = "") -> None:
    """Assemble a minimal PDF 1.4 file from a list of page content strings."""
    objs = {}
    counter = [0]

    def alloc() -> int:
        counter[0] += 1
        return counter[0]

    catalog = alloc()
    pages_obj = alloc()
    f1 = alloc()
    f2 = alloc()
    info = alloc()

    content_nums = []
    for content in pages:
        c = alloc()
        stream = content.encode("latin-1", "replace")
        objs[c] = (b"<< /Length %d >>\nstream\n" % len(stream)) + stream + b"\nendstream"
        content_nums.append(c)

    page_nums = []
    for c in content_nums:
        p = alloc()
        page_nums.append(p)
        objs[p] = (
            "<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] "
            "/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> "
            "/Contents %d 0 R >>" % (pages_obj, _n(PW), _n(PH), f1, f2, c)
        ).encode("latin-1")

    objs[f1] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    objs[f2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    kids = " ".join("%d 0 R" % n for n in page_nums)
    objs[pages_obj] = ("<< /Type /Pages /Kids [%s] /Count %d >>"
                       % (kids, len(page_nums))).encode("latin-1")
    objs[catalog] = ("<< /Type /Catalog /Pages %d 0 R >>" % pages_obj).encode("latin-1")
    meta = ["/Creator (AI-Argus-Harness)", "/Producer (AI-Argus-Harness)"]
    if title:
        meta.insert(0, "/Title (%s)" % _esc(title))
    if author:
        meta.append("/Author (%s)" % _esc(author))
    objs[info] = ("<< %s >>" % " ".join(meta)).encode("latin-1")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in range(1, counter[0] + 1):
        offsets[num] = len(out)
        out += ("%d 0 obj\n" % num).encode("latin-1") + objs[num] + b"\nendobj\n"
    xref_pos = len(out)
    out += ("xref\n0 %d\n" % (counter[0] + 1)).encode("latin-1")
    out += b"0000000000 65535 f \n"
    for num in range(1, counter[0] + 1):
        out += ("%010d 00000 n \n" % offsets[num]).encode("latin-1")
    out += ("trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (counter[0] + 1, catalog, info, xref_pos)).encode("latin-1")
    with open(path, "wb") as fh:
        fh.write(out)


def footer(c: Canvas, page_no: int) -> None:
    c.line(ML, 46, MR, 46, LINE, 0.6)
    c.text(ML, 34, "AI-Argus-Harness  -  Structure & Design", 8, False, MUTED)
    c.text_center(PW / 2, 34, "Evidence-first enterprise security harness", 8, False, MUTED)
    c.text(MR - 46, 34, "Page %d" % page_no, 8, False, MUTED)


def tint(color, amt: float):
    """Mix color toward white by amt (0=full color, 1=white)."""
    return tuple(c + (1 - c) * amt for c in color)


def _version() -> str:
    try:
        import ai_argus
        return getattr(ai_argus, "__version__", "0.1.0")
    except Exception:
        return "0.1.0"


# --------------------------------------------------------------------------- #
# Page 1 - Title
# --------------------------------------------------------------------------- #
def page_title(page_no: int) -> str:
    import datetime
    c = Canvas()
    bg = (0.10, 0.20, 0.34)
    c.rect(0, PH - 196, PW, 196, fill=bg)
    c.rect(0, PH - 200, PW, 4, fill=(0.03, 0.47, 0.45))
    c.text_center(PW / 2, PH - 96, "AI-Argus-Harness", 32, True, WHITE)
    c.text_center(PW / 2, PH - 130, "Structure & Design", 16, True, (0.86, 0.90, 0.95))
    c.text_center(PW / 2, PH - 152,
                  "Enterprise AI security harness  -  evidence-first, identity-aware",
                  10.5, False, (0.78, 0.83, 0.90))
    c.text_center(PW / 2, PH - 174, "Author: Sam Gupta", 11, True, (0.90, 0.93, 0.97))

    c.text(ML, 560, "Core principle", 13, True, INK)
    c.rect(ML, 486, MR - ML, 60, fill=SOFT, stroke=LINE, lw=0.8, r=8)
    c.rect(ML, 486, 5, 60, fill=(0.03, 0.47, 0.45), r=2)
    c.text(ML + 18, 524,
           "AI is an evidence INTERPRETER, never an evidence CREATOR.", 11, True, INK)
    for i, ln in enumerate(wrap(
            "Every finding must carry asset + evidence + identity path + impact + "
            "confidence + remediation + owner before it is promoted to enterprise "
            "reporting; otherwise it is routed to human review.",
            9.5, False, MR - ML - 36)):
        c.text(ML + 18, 506 - i * 13, ln, 9.5, False, MUTED)

    c.text(ML, 452, "Pipeline phases  (S0 -> S10)", 13, True, INK)
    counts = {}
    codes = {}
    for code, _name, ph, *_ in STAGES:
        counts[ph] = counts.get(ph, 0) + 1
        codes.setdefault(ph, []).append(code)
    y = 426
    for key, label in PHASES:
        col = PHASE_COLORS[key]
        c.rect(ML, y - 2, 16, 12, fill=col, r=2)
        c.text(ML + 26, y, label, 11, True, INK)
        c.text(ML + 220, y, "%d stage(s):  %s" % (counts[key], ", ".join(codes[key])),
               9.5, False, MUTED)
        y -= 22

    c.rect(ML, 150, MR - ML, 56, fill=tint((0.10, 0.20, 0.34), 0.92),
           stroke=LINE, lw=0.8, r=8)
    c.text(ML + 16, 184, "Pipeline:", 10, True, INK)
    c.text(ML + 78, 184,
           "Discovery  ->  Identity  ->  Verification  ->  Risk Intelligence  ->  Reporting",
           10, True, (0.10, 0.20, 0.34))
    c.text(ML + 16, 164,
           "Deterministic scanners produce evidence; the reliability layer gates it; "
           "scoring & chaining add risk intelligence.", 9, False, MUTED)

    c.text(ML, 104, "Version %s" % _version(), 9.5, False, MUTED)
    c.text(ML, 88, "Author: Sam Gupta", 9.5, True, INK)
    c.text(ML, 72, "Generated %s" % datetime.date.today().isoformat(), 9.5, False, MUTED)
    c.text(ML, 56, "Document: structure, design and the key feature at each stage.",
           9.5, False, MUTED)
    footer(c, page_no)
    return c.data()


# --------------------------------------------------------------------------- #
# Page 2 - Architecture / structure diagram
# --------------------------------------------------------------------------- #
def page_arch(page_no: int) -> str:
    c = Canvas()
    c.text(ML, 748, "1.  Structure & Design", 16, True, INK)
    for i, ln in enumerate(wrap(
            "Five pillars around a Harness Core, with cross-cutting reliability, "
            "evidence and model-provider layers.", 10, False, MR - ML)):
        c.text(ML, 730 - i * 13, ln, 10, False, MUTED)

    pillars = [
        ("discovery", "Discovery",
         ["Attack surface", "DNS / TLS / ports", "Network", "Endpoint",
          "Kubernetes", "Application / API", "SaaS / 3rd-party", "Supply chain"]),
        ("identity", "Identity",
         ["Users / groups", "Roles", "Service accounts", "OAuth apps",
          "CI/CD identities", "Workload IDs", "External users"]),
        ("evidence", "Verification",
         ["Evidence collection", "Claim verification", "Controlled offensive",
          "Adversarial review", "Single-pass validate"]),
        ("risk", "Risk Intelligence",
         ["Deduplication", "Chain construction", "Detection coverage",
          "Control validation", "Risk scoring"]),
        ("reporting", "Reporting",
         ["SARIF", "JSON", "Markdown", "Executive summary",
          "Evidence appendix", "Ticket export"]),
    ]
    n = len(pillars)
    gap = 12.0
    pw = (MR - ML - gap * (n - 1)) / n
    head_top, head_h = 706, 30
    body_top, body_bot = head_top - head_h - 4, 474
    for i, (key, label, items) in enumerate(pillars):
        x = ML + i * (pw + gap)
        col = PHASE_COLORS[key]
        c.rect(x, head_top - head_h, pw, head_h, fill=col, r=6)
        c.text_center(x + pw / 2, head_top - head_h / 2 - 3.5, label, 9.5, True, WHITE)
        c.rect(x, body_bot, pw, body_top - body_bot, fill=CARD, stroke=LINE, lw=0.8, r=6)
        yy = body_top - 16
        for it in items:
            c.dot(x + 10, yy + 2.6, 1.6, col)
            for j, ln in enumerate(wrap(it, 7.6, False, pw - 24)):
                c.text(x + 16, yy - j * 9.5, ln, 7.6, False, INK)
            yy -= 9.5 * max(1, len(wrap(it, 7.6, False, pw - 24))) + 4.0
        if i < n - 1:
            c.arrow_right(x + pw + 1, head_top - head_h / 2,
                          x + pw + gap - 1, MUTED, 1.3)

    # downward arrow into the harness core
    c.arrow_down(PW / 2, body_bot - 1, 458, MUTED, 1.3)

    # Harness core band
    core_top, core_h = 458, 46
    c.rect(ML, core_top - core_h, MR - ML, core_h, fill=tint(INK, 0.90),
           stroke=LINE, lw=0.8, r=8)
    c.rect(ML, core_top - core_h, 5, core_h, fill=INK, r=2)
    c.text(ML + 16, core_top - 18, "Harness Core", 11, True, INK)
    core_items = ("Stage Orchestrator   .   Plugin Loader   .   Model/Agent Router   .   "
                  "Evidence Normalizer   .   Multi-Agent Voting   .   Completeness Gate   "
                  ".   SARIF / JSON / MD Exporters")
    for j, ln in enumerate(wrap(core_items, 8.4, False, MR - ML - 130)):
        c.text(ML + 120, core_top - 18 - j * 11, ln, 8.4, False, MUTED)

    c.arrow_down(PW / 2, core_top - core_h - 1, 404, MUTED, 1.3)

    # cross-cutting layers
    layers = [
        ("reliability", "LLM Reliability Layer",
         "evidence-bound reasoning; AI interprets evidence, never invents findings"),
        ("evidence", "Evidence Store",
         "append-only, secret-redacted, replayable artifact trail"),
        ("analysis", "Model-Agnostic Providers",
         "offline default, cost-aware budgets, no vendor lock-in"),
    ]
    ly, lh, lgap = 404, 32, 8
    for key, title, desc in layers:
        col = PHASE_COLORS[key]
        top = ly
        c.rect(ML, top - lh, MR - ML, lh, fill=tint(col, 0.86), stroke=LINE, lw=0.7, r=6)
        c.rect(ML, top - lh, 5, lh, fill=col, r=2)
        c.text(ML + 16, top - 20, title, 10, True, INK)
        c.text(ML + 190, top - 20, desc, 9, False, INK)
        ly -= lh + lgap

    # principle strip
    c.rect(ML, 196, MR - ML, 34, fill=tint((0.03, 0.47, 0.45), 0.88),
           stroke=LINE, lw=0.7, r=6)
    c.text_center(PW / 2, 214,
                  "Finding = asset + evidence + identity path + impact + confidence "
                  "+ remediation + owner", 9.5, True, (0.05, 0.30, 0.30))
    footer(c, page_no)
    return c.data()


# --------------------------------------------------------------------------- #
# Page 3 - Stage pipeline diagram (feature at each stage)
# --------------------------------------------------------------------------- #
def page_stages(page_no: int) -> str:
    c = Canvas()
    c.text(ML, 748, "2.  Enterprise Stage Pipeline", 16, True, INK)
    c.text(ML, 730,
           "Each phase groups stages; every stage card highlights its key FEATURE.",
           10, False, MUTED)

    # group stages by phase
    grouped = {key: [] for key, _ in PHASES}
    for st in STAGES:
        grouped[st[2]].append(st)

    top_y, bot_y, vgap = 712.0, 58.0, 14.0
    nb = len(PHASES)
    band_h = (top_y - bot_y - vgap * (nb - 1)) / nb
    label_w = 96.0
    cards_x = ML + label_w + 10
    cards_w = MR - cards_x

    band_top = top_y
    for bi, (key, label) in enumerate(PHASES):
        col = PHASE_COLORS[key]
        band_bot = band_top - band_h
        # phase label tab
        c.rect(ML, band_bot, label_w, band_h, fill=col, r=6)
        for j, ln in enumerate(wrap(label, 9.5, True, label_w - 12)):
            c.text(ML + 8, band_top - band_h / 2 + 6 - j * 11, ln, 9.5, True, WHITE)
        # stage cards
        stages = grouped[key]
        nc = len(stages)
        cgap = 8.0
        cw = (cards_w - cgap * (nc - 1)) / nc
        for ci, st in enumerate(stages):
            code, name, _ph, short, *_ = st
            cx = cards_x + ci * (cw + cgap)
            c.rect(cx, band_bot, cw, band_h, fill=CARD, stroke=LINE, lw=0.8, r=6)
            c.rect(cx, band_top - 4, cw, 4, fill=col, r=2)  # top accent
            c.text(cx + 10, band_top - 18, code, 11.5, True, col)
            nx = cx + 10 + text_width(code, 11.5, True) + 7
            for j, ln in enumerate(wrap(name, 8.6, True, cw - (nx - cx) - 10)):
                c.text(nx, band_top - 17 - j * 10, ln, 8.6, True, INK)
            # feature text
            fy = band_top - 40
            c.text(cx + 10, fy, "Feature", 7, True, MUTED)
            for j, ln in enumerate(wrap(short, 7.6, False, cw - 20)):
                c.text(cx + 10, fy - 11 - j * 9.4, ln, 7.6, False, INK)
        # connector arrow to next band
        if bi < nb - 1:
            c.arrow_down(ML + label_w / 2, band_bot - 2, band_bot - vgap + 2, col, 1.2)
        band_top = band_bot - vgap

    footer(c, page_no)
    return c.data()


# --------------------------------------------------------------------------- #
# Detail pages (flowing text)
# --------------------------------------------------------------------------- #
def _blocks() -> list:
    b: list = []

    def h1(t): b.append(("h1", t))
    def h2(t): b.append(("h2", t))
    def p(t): b.append(("p", t))
    def li(t): b.append(("li", t))
    def sp(n=6): b.append(("sp", n))

    h1("3.  Overview")
    p("AI-Argus-Harness maps, analyzes, verifies and reports security exposure across "
      "modern enterprise environments: external attack surface, cloud, identity, "
      "Kubernetes, applications/APIs, SaaS and the software supply chain. It is "
      "evidence-first: deterministic scanners produce structured evidence and AI only "
      "reasons over that evidence, which sharply reduces hallucinations and keeps runs "
      "reproducible and audit-ready.")
    sp()
    h2("Core principle")
    p("AI is an evidence interpreter, never an evidence creator. A finding is only "
      "promoted to enterprise reporting when it carries: asset, evidence, identity "
      "path (for high/critical), impact, confidence, remediation and owner. Anything "
      "incomplete is routed to human review (or dropped in strict mode).")

    h1("4.  Design Principles")
    li("Lightweight and cross-platform; the core harness has zero hard dependencies.")
    li("Model-agnostic with no vendor lock-in; offline provider is the default.")
    li("Offline-capable scanning; the tool always runs even with no network or API key.")
    li("Deterministic and reproducible scoring and severity.")
    li("Cost-aware with per-day, per-month and per-scan budgets.")
    li("Plugin-driven scanners discoverable via Python entry points.")
    li("Read-only and safe by default; active checks require explicit safe/auth modes.")
    li("Enterprise-ready: secret redaction, replayable evidence, SARIF and ticket export.")

    h1("5.  Module Map")
    li("core/ - stage orchestrator, plugin loader, run context, stage model, "
       "credential preflight (authenticated/non-authenticated scanning).")
    li("graph/ - enterprise asset graph and first-class identity/access graph.")
    li("evidence/ - append-only, redacted, replayable evidence store and normalizer.")
    li("reliability/ - claim verifier, adversarial reviewer, validator, completeness gate.")
    li("scoring/ - deterministic additive risk model and deduplication.")
    li("chaining/ - attack-path chain construction.")
    li("reporting/ - JSON, SARIF, Markdown, executive summary and ticket exporters.")
    li("scanners/ - 11 deterministic scanners (domain, network, secrets, supply_chain, "
       "aws, gcp, kubernetes, saas, cicd, data_exposure, application).")
    li("llm/ - model-agnostic provider abstraction with cost tracking (offline default).")

    h1("6.  Stage-by-Stage Feature Highlights")
    for code, name, _ph, _short, long, output, module in STAGES:
        h2("%s  -  %s" % (code, name))
        p("Feature: " + long)
        li("Produces: " + output)
        li("Module: " + module)
        sp(4)

    h1("7.  Authenticated vs Non-Authenticated Scanning")
    p("At the start of every scan the operator chooses an authenticated or a "
      "non-authenticated run. A non-authenticated scan requires no key and behaves "
      "as before; an authenticated scan adds the S0 credential preflight, whose auth "
      "context applies to stages S1, S1.5, S2, S3, S4, S5 and S5.5.")
    h2("Credential discovery (local, read-only)")
    p("Credentials are resolved in priority order: explicit operator overrides, the "
      "inventory credential census, standard environment variables, then standard "
      "credential files (for example ~/.aws/credentials, ~/.kube/config, gcloud ADC). "
      "Only references - an environment-variable name or a file path - and a presence "
      "flag are recorded; secret values are never read, printed, transmitted or "
      "stored, and no third-party hosts are probed to harvest keys.")
    h2("Fallback when no key is found")
    li("Prompt for a key per missing service (an env-var name or an @file path), or")
    li("Continue as a non-authenticated scan for the services without a credential.")
    h2("Scope & visibility")
    li("Credentialed services: aws, gcp, kubernetes, saas, cicd; others run external / optional.")
    li("Per-service status appears in the scan summary, the JSON report (auth block) "
       "and the evidence trail.")
    li("Targets may be a single target, multiple targets, or --all-targets (one "
       "combined inventory run).")

    h1("8.  Reliability Rules (Hallucination Reduction)")
    li("No evidence, no finding.")
    li("No source, no finding (evidence must be source-bound).")
    li("No identity path, no high/critical severity.")
    li("No impact, no severity.")
    li("No owner, no promotion to enterprise reporting.")
    li("No remediation, no ticket.")
    li("Below the confidence threshold in strict mode, route to human review or drop.")
    li("Adversarial review challenges weak claims and records multi-agent disagreement.")

    h1("9.  Risk Scoring & Severity")
    p("Risk is a deterministic additive model: Exposure + Privilege + Exploitability + "
      "IdentityPathStrength + DataSensitivity + BusinessCriticality + Chainability + "
      "DetectionGap + ControlWeakness + Confidence - CompensatingControls.")
    p("Severity is derived from the score plus qualitative signals: internet exposure "
      "with a privileged identity path to sensitive data and weak detection escalates "
      "to critical.")

    h1("10.  Coverage (Scanners)")
    li("Live, read-only, stealth-aware: domain (DNS/TLS/subdomains), network (ports).")
    li("Offline code-path: secrets, supply_chain (SBOM + typosquat), cicd pipelines.")
    li("Inventory-snapshot, credentialed-equivalent: aws, gcp, kubernetes, saas, "
       "data_exposure, application - deterministic policy checks, fully replayable.")

    h1("11.  CLI Quick Reference")
    li("argus init - first-time setup (provider, model, budget).")
    li("argus scan <target> - run the stage pipeline (domain, CIDR, path, or scanner).")
    li("argus quick <target> - fast minimal-cost attack-surface scan.")
    li("argus scan --stage S1,S2,S4 / --until S6 - run a subset of stages.")
    li("Cost modes: --minimal | --balanced | --research | --deep-research | --offline.")
    li("Stealth modes: --passive | --safe | --auth | --stealth; --strict for gating.")
    li("Authenticated scan: --auth-scan / --no-auth-scan (distinct from the --auth "
       "stealth mode); --auth-key SERVICE=ENV_VAR or SERVICE=@/path supplies a "
       "reference, never a secret.")
    li("Targets: argus scan host-a host-b ... or --all-targets (one combined "
       "inventory run).")
    li("Incremental & governance: --diff (new/fixed/unchanged vs baseline); "
       "argus suppress / suppressions for accepted risks.")
    li("argus graph | identity | explain <id> | replay <id> | evidence | cost | doctor.")

    h1("12.  Reports & Outputs")
    li("report.json - full machine-readable run (findings, graphs, evidence, chains).")
    li("report.sarif - SARIF 2.1.0 for code-scanning dashboards.")
    li("report.md - engineer-facing detail with evidence and identity paths.")
    li("executive.md - leadership-ready risk summary.")
    li("tickets.json - owner-based export for Jira / ServiceNow.")

    h1("13.  Enterprise Readiness")
    li("Security: read-only by default, secret redaction, no exploitation or exfiltration.")
    li("Reliability: completeness gate, adversarial review, deterministic reproducibility.")
    li("Scale: parallel scanners, incremental scans, central inventory snapshots.")
    li("Governance: budgets, cost dashboard, audit-ready replayable evidence.")
    return b


def render_details(start_page: int) -> List[str]:
    pages: List[str] = []
    blocks = _blocks()
    top, bottom = 748.0, 60.0
    maxw = MR - ML
    c = Canvas()
    y = top
    page_no = start_page

    def newpage():
        nonlocal c, y
        footer(c, page_no)
        pages.append(c.data())
        c = Canvas()
        y = top

    def need(h):
        nonlocal page_no
        if y - h < bottom:
            newpage()
            page_no += 1

    for kind, val in blocks:
        if kind == "h1":
            need(34)
            c.line(ML, y + 4, MR, y + 4, LINE, 0.6)
            c.text(ML, y - 12, val, 14.5, True, INK)
            y -= 30
        elif kind == "h2":
            need(22)
            c.text(ML, y - 12, val, 11, True, (0.10, 0.20, 0.34))
            y -= 22
        elif kind == "p":
            lines = wrap(val, 9.5, False, maxw)
            need(len(lines) * 13 + 4)
            for ln in lines:
                c.text(ML, y - 10, ln, 9.5, False, INK)
                y -= 13
            y -= 4
        elif kind == "li":
            lines = wrap(val, 9.5, False, maxw - 16)
            need(len(lines) * 13 + 3)
            c.dot(ML + 4, y - 7, 1.7, MUTED)
            for j, ln in enumerate(lines):
                c.text(ML + 14, y - 10 - j * 13, ln, 9.5, False, INK)
            y -= len(lines) * 13 + 3
        elif kind == "sp":
            y -= val
    footer(c, page_no)
    pages.append(c.data())
    return pages


def main() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "AI-Argus-Harness-Design.pdf")
    pages = [page_title(1), page_arch(2), page_stages(3)]
    pages += render_details(4)
    build_pdf(out, pages, title="AI-Argus-Harness - Structure & Design",
              author="Sam Gupta")
    return out


if __name__ == "__main__":
    path = main()
    size = os.path.getsize(path)
    print("Wrote %s (%d bytes)" % (path, size))

