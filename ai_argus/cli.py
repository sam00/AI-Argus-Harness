"""AI-Argus-Harness command-line interface.

Command surface:

    argus init | scan | quick | resume | report | graph | identity | verify
          | explain | replay | cost | models | plugins | doctor | benchmark
          | stages | interactive | version
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .config import (
    Config, COST_MODES, PROFILES, PROFILE_SCANNERS, STEALTH_MODES, config_home,
)
from .core import Orchestrator, ScanTarget
from .core import auth as authmod
from .core.auth import AuthMode, AuthResolution
from .core.stages import STAGES, stages_subset, stages_until
from .core.plugin_loader import load_all
from .llm import CostTracker
from . import reporting

RUNS_DIR = Path("argus-runs")
SUPPORTED_PROVIDERS = [
    "openai", "anthropic", "google", "gemini", "azure", "mistral", "deepseek",
    "ollama", "lmstudio", "vllm", "openrouter", "bedrock", "custom", "offline",
]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _c(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _bold(t: str) -> str: return _c(t, "1")
def _green(t: str) -> str: return _c(t, "32")
def _red(t: str) -> str: return _c(t, "31")
def _yellow(t: str) -> str: return _c(t, "33")
def _cyan(t: str) -> str: return _c(t, "36")


SEV_COLOR = {"critical": "31;1", "high": "31", "medium": "33", "low": "36", "info": "37"}


def _apply_run_flags(cfg: Config, args: argparse.Namespace) -> Config:
    if getattr(args, "profile", None):
        cfg.profile = args.profile
    # cost modes
    for mode_flag, mode in (("minimal", "minimal"), ("balanced", "balanced"),
                            ("research", "research"), ("deep_research", "deep-research"),
                            ("offline", "offline")):
        if getattr(args, mode_flag, False):
            cfg.cost_mode = mode
    # stealth modes
    for flag, mode in (("passive", "passive"), ("safe", "safe"),
                       ("auth", "auth"), ("stealth", "stealth")):
        if getattr(args, flag, False):
            cfg.stealth_mode = mode
    if getattr(args, "strict", False):
        cfg.strict = True
    if getattr(args, "diff", False):
        cfg.diff = True
    if getattr(args, "auth_scan", False):
        cfg.auth_scan = True
    if getattr(args, "workers", None):
        cfg.workers = args.workers
    if getattr(args, "auto_workers", False):
        cfg.auto_workers = True
    if getattr(args, "notify_slack", False):
        cfg.notify_slack = True
    return cfg


def _make_target(raw: str, args: argparse.Namespace) -> ScanTarget:
    attrs = {}
    if getattr(args, "path", None):
        attrs["path"] = args.path
    if getattr(args, "inventory", None):
        attrs["inventory_path"] = args.inventory
    kind = "auto"
    if raw and Path(raw).exists():
        kind = "file"
        attrs.setdefault("path", raw)
    elif "/" in raw and raw.count(".") and raw[0].isdigit():
        kind = "cidr"
    elif "." in raw:
        kind = "domain"
    return ScanTarget(raw=raw or str(Path.cwd()), kind=kind, attributes=attrs)


def _emit_reports(result, cfg: Config, out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    # JSON is always written (machine-readable canonical output)
    written.append(reporting.write_json(result, out_dir / "report.json"))
    fmts = set(cfg.reports)
    if "sarif" in fmts:
        written.append(reporting.write_sarif(result.findings, out_dir / "report.sarif", __version__))
    if "markdown" in fmts:
        written.append(reporting.write_markdown(result, out_dir / "report.md"))
    # executive + tickets always handy for enterprise
    written.append(reporting.write_executive(result, out_dir / "executive.md"))
    written.append(reporting.write_tickets(result.findings, out_dir / "tickets.json"))
    # maintain a 'latest' pointer for explain/graph/replay
    (RUNS_DIR / "latest.json").write_text(
        json.dumps(reporting.json_report.build_json(result), indent=2, default=str))
    return written


def _maybe_notify_slack(result, cfg: Config, report_dir: Optional[Path],
                        explicit_webhook: Optional[str] = None) -> None:
    """Post a run summary to Slack when a webhook is available or notify is on.

    The webhook URL is a secret resolved from ``--slack-webhook`` or
    ``$ARGUS_SLACK_WEBHOOK``; it is never persisted. Failures are non-fatal so a
    flaky notification never fails an otherwise-successful scan.
    """
    webhook = reporting.resolve_webhook(explicit_webhook)
    requested = getattr(cfg, "notify_slack", False) or bool(webhook)
    if not requested:
        return
    if not webhook:
        print(_yellow("  slack       : --notify-slack set but no webhook found "
                      "(set $ARGUS_SLACK_WEBHOOK or pass --slack-webhook)"))
        return
    ok = reporting.notify_slack(result, webhook, report_dir=report_dir)
    print(_green("  slack       : notification sent") if ok
          else _yellow("  slack       : notification failed (network/4xx)"))


def _print_summary(result) -> None:
    s = result.summary()
    print()
    print(_bold("AI-Argus-Harness — scan complete"))
    print(f"  run id      : {result.run_id}")
    print(f"  target      : {result.target}")
    print(f"  profile     : {result.profile}  cost={result.cost_mode}  stealth={result.stealth_mode}")
    a = getattr(result, "auth", None)
    if a:
        mode = a.get("mode")
        if mode == AuthMode.AUTHENTICATED.value:
            # coverage + any missing credentials are only meaningful when we
            # actually attempted to authenticate.
            svcs = a.get("services", {})
            req = [x for x in svcs if svcs[x].get("required")]
            present_req = [x for x in a.get("authenticated_services", [])
                           if svcs.get(x, {}).get("required")]
            cov = f"{len(present_req)}/{len(req)}" if req else "n/a"
            miss = a.get("missing_services") or []
            extra = ("  " + _yellow("missing: " + ",".join(miss))) if miss else ""
            print(f"  auth        : {mode}  credentialed-services={cov}{extra}")
        else:
            print(f"  auth        : {mode}")
    print(f"  assets      : {s['assets']}   identities: {s['identities']}")
    print(f"  findings    : {_bold(str(s['total_findings']))}   "
          f"review-queue: {s['review_queue']}   suppressed: {s['suppressed']}   "
          f"chains: {s['chains']}")
    if s.get("diff"):
        d = s["diff"]
        print(f"  diff        : {_green('+' + str(d['added']))} new   "
              f"{_cyan(str(d['fixed']) + ' fixed')}   {d['unchanged']} unchanged")
    bysev = s["by_severity"]
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if bysev.get(sev):
            parts.append(_c(f"{sev}:{bysev[sev]}", SEV_COLOR[sev]))
    print("  severity    : " + ("  ".join(parts) if parts else "none"))
    print()
    for f in result.findings[:10]:
        tag = _c(f"[{f.severity.value.upper()}]", SEV_COLOR[f.severity.value])
        print(f"  {tag} {f.title}  ({_cyan(f.finding_id)}, score {f.risk_score})")
    if len(result.findings) > 10:
        print(f"  ... and {len(result.findings) - 10} more")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    cfg = Config.load()
    print(_bold("AI-Argus-Harness setup"))
    provider = args.provider
    if not provider and sys.stdin.isatty():
        print("Select AI provider: " + ", ".join(SUPPORTED_PROVIDERS))
        provider = input("provider [offline]: ").strip() or "offline"
    provider = provider or "offline"
    cfg.provider = provider
    if args.api_key_env:
        cfg.api_key_env = args.api_key_env
    if args.model:
        cfg.model = args.model
    if args.base_url:
        cfg.base_url = args.base_url
    path = cfg.save_global()
    print(_green(f"\u2713 provider set to {provider}"))
    print(_green(f"\u2713 config saved to {path}"))
    if provider != "offline" and not cfg.api_key_env:
        print(_yellow("! set --api-key-env to the NAME of the env var holding your API key "
                      "(never hard-code keys)."))
    print(_green("\u2713 test model: offline provider always available"))
    print(_bold("Done."))
    return 0


def _prompt(q: str) -> str:
    try:
        return input(q)
    except EOFError:
        return ""


def _interactive() -> bool:
    """True only when we can safely prompt a human.

    Requires BOTH stdin and stdout to be TTYs. If stdout is piped/redirected
    (e.g. ``argus scan ... | grep``) we must NOT block on input(): the prompt
    would be invisible and the process would hang silently. In that case the
    caller falls back to a non-interactive default (or an explicit flag).
    """
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def _load_inventory_file(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "target"


def _print_auth_table(res: AuthResolution) -> None:
    for svc, st in res.statuses.items():
        if not st.required and not st.present:
            continue  # hide optional services with no credential (just noise)
        if st.present:
            print(f"    {_green('✓')} {svc:<12}: {st.source}:{st.ref}")
        else:
            print(f"    {_yellow('✗')} {svc:<12}: no credential discovered")


def _resolve_missing_interactive(res: AuthResolution, services: List[str],
                                 inventory: Optional[Dict[str, Any]],
                                 overrides: Dict[str, str]) -> Optional[AuthResolution]:
    """Ask for a key per missing service, else offer to continue unauthenticated."""
    for svc in list(res.missing_services):
        ref = _prompt(f"  Provide credential for '{svc}' as ENV_VAR name or @/path "
                      "(blank to skip): ").strip()
        if ref:
            overrides[svc] = ref
    res = authmod.resolve(AuthMode.AUTHENTICATED, services,
                          inventory=inventory, overrides=overrides)
    if res.missing_services:
        _print_auth_table(res)
        cont = _prompt(f"  No key for {', '.join(res.missing_services)}. Continue with a "
                       "non-authenticated scan for those services? [Y/n]: ").strip().lower()
        if cont.startswith("n"):
            return None
    return res


def _auth_preflight(cfg: Config, services: List[str],
                    inventory: Optional[Dict[str, Any]],
                    args: argparse.Namespace) -> Optional[AuthResolution]:
    """Decide authenticated vs non-authenticated and resolve credentials.

    Returns the resolution, or ``None`` if the operator aborts the scan.
    """
    overrides = authmod.parse_overrides(getattr(args, "auth_key", None))

    if getattr(args, "no_auth_scan", False):
        mode = AuthMode.UNAUTHENTICATED
    elif getattr(cfg, "auth_scan", False):           # --auth-scan or project config
        mode = AuthMode.AUTHENTICATED
    elif _interactive():
        ans = _prompt("Run an [a]uthenticated scan (use credentials) or "
                      "[n]on-authenticated scan (no key required)? [a/N]: ")
        mode = (AuthMode.AUTHENTICATED if ans.strip().lower().startswith("a")
                else AuthMode.UNAUTHENTICATED)
    else:
        mode = AuthMode.UNAUTHENTICATED
        print(_yellow("No auth mode specified (non-interactive) — defaulting to "
                      "non-authenticated. Use --auth-scan to authenticate."))

    if mode is AuthMode.UNAUTHENTICATED:
        cfg.auth_scan = False
        print(_cyan("Auth mode: non-authenticated (no key required)."))
        return authmod.unauthenticated(services)

    cfg.auth_scan = True
    print(_bold("Authenticated scan — credential preflight (applies to S1–S5.5)"))
    print(f"  scanning the environment/inventory for credentials for: "
          f"{', '.join(services) or '(none required)'}")
    res = authmod.resolve(AuthMode.AUTHENTICATED, services,
                          inventory=inventory, overrides=overrides)
    _print_auth_table(res)

    if res.missing_services and _interactive():
        res = _resolve_missing_interactive(res, services, inventory, overrides)
        if res is None:
            return None
    elif res.missing_services:
        print(_yellow(f"! no credential for: {', '.join(res.missing_services)} — "
                      "these services will run non-authenticated."))
    return res


def _resolve_targets(args: argparse.Namespace):
    """Resolve the target list + optional scanner subset.

    Supports a single target, multiple targets, a scanner-name shortcut
    (e.g. `argus scan aws`), and `--all-targets` (one combined inventory run).
    """
    raw = list(getattr(args, "target", []) or [])
    scanner_subset: Optional[List[str]] = None
    if len(raw) == 1 and _is_scanner_name(raw[0]):
        scanner_subset = [raw[0]]
        raw = []
    if getattr(args, "scanners", None):
        scanner_subset = (scanner_subset or []) + args.scanners

    if getattr(args, "all_targets", False):
        # Inventory-driven scanners cover every account/cluster in one pass,
        # so "all targets at once" is a single combined run over the inventory.
        targets = [_make_target("all-targets", args)]
    elif raw:
        targets = [_make_target(t, args) for t in raw]
    else:
        targets = [_make_target("", args)]
    return targets, scanner_subset


def cmd_scan(args: argparse.Namespace) -> int:
    load_all()
    cfg = _apply_run_flags(Config.load(), args)

    targets, scanner_subset = _resolve_targets(args)

    # stage selection
    stages = STAGES
    if args.until:
        stages = stages_until(args.until)
    elif args.stage:
        codes = [c.strip() for c in args.stage.split(",")]
        stages = stages_subset(codes)

    orch = Orchestrator(cfg)

    # --- credential preflight (once; services are profile-derived) -------- #
    planned = orch.resolve_scanners(scanner_subset)
    services = authmod.services_for_scanners(planned)
    inventory = _load_inventory_file(getattr(args, "inventory", None))
    auth_res = _auth_preflight(cfg, services, inventory, args)
    if auth_res is None:
        print(_red("Scan aborted: authenticated scan requested but no credentials "
                   "were supplied."))
        return 2

    out_dir = Path(args.out) if args.out else None
    multi = len(targets) > 1
    for i, target in enumerate(targets, 1):
        if multi:
            print(_bold(f"\n[{i}/{len(targets)}] ") + target.raw)
        print(_bold(f"Scanning {target.raw} (profile={cfg.profile}, cost={cfg.cost_mode}, "
                    f"stealth={cfg.stealth_mode}, auth={auth_res.mode.value})"))
        run_dir_holder = RUNS_DIR / "tmp"
        orch.run_dir = run_dir_holder
        run_dir_holder.mkdir(parents=True, exist_ok=True)
        result = orch.run(target, scanners=scanner_subset, stages=stages, auth=auth_res)

        if out_dir and multi:
            final_dir = out_dir / _safe_name(target.raw)
        else:
            final_dir = out_dir or (RUNS_DIR / result.run_id)
        written = _emit_reports(result, cfg, final_dir)
        _print_summary(result)
        print(_bold("\nReports:"))
        for p in written:
            print(f"  - {p}")
        _maybe_notify_slack(result, cfg, final_dir,
                            getattr(args, "slack_webhook", None))
    return 0


def _is_scanner_name(name: str) -> bool:
    try:
        from .scanners import all_scanners
        aliases = {"k8s": "kubernetes", "sbom": "supply_chain"}
        return name in all_scanners() or name in aliases
    except Exception:
        return False


def cmd_quick(args: argparse.Namespace) -> int:
    load_all()
    cfg = Config.load()
    cfg.profile = "quick"
    cfg.cost_mode = "minimal"
    target = _make_target(args.target, args)
    print(_bold(f"Quick scan of {target.raw}"))
    orch = Orchestrator(cfg)
    result = orch.run(target, scanners=PROFILE_SCANNERS["quick"])
    final_dir = RUNS_DIR / result.run_id
    _emit_reports(result, cfg, final_dir)
    _print_summary(result)
    print(f"\nReports in {final_dir}")
    _maybe_notify_slack(result, cfg, final_dir)
    return 0


def cmd_stages(args: argparse.Namespace) -> int:
    print(_bold("Enterprise stage model"))
    for s in STAGES:
        print(f"  {_cyan(s.code):<6} {_bold(s.name)} — {s.description}")
    return 0


def cmd_plugins(args: argparse.Namespace) -> int:
    loaded = load_all()
    from .scanners import REGISTRY, all_scanners
    print(_bold("Installed scanners"))
    for name in all_scanners():
        sc = REGISTRY[name]
        print(f"  {_green(name):<16} [{sc.category}] {sc.description}")
    if loaded:
        print(_cyan(f"\nExternal plugins loaded: {', '.join(loaded)}"))
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    cfg = Config.load()
    print(_bold("Supported providers (no vendor lock-in)"))
    for p in SUPPORTED_PROVIDERS:
        mark = _green(" (active)") if p == cfg.provider else ""
        print(f"  - {p}{mark}")
    print(_bold("\nPer-stage routing"))
    for k, v in cfg.routing.to_dict().items():
        print(f"  {k:<12}: {v}")
    return 0


def cmd_cost(args: argparse.Namespace) -> int:
    summ = CostTracker().summary()
    cfg = Config.load()
    print(_bold("Cost dashboard"))
    print(f"  today           : ${summ['today_usd']}")
    print(f"  this month      : ${summ['month_usd']}")
    print(f"  tokens (month)  : {summ['tokens_this_month']}")
    print(f"  avg call        : ${summ['avg_call_usd']}")
    print(f"  est. next scan  : ${summ['estimated_next_scan_usd']}")
    print(_bold("\nBudget"))
    print(f"  daily   : ${cfg.budget.daily_usd}")
    print(f"  monthly : ${cfg.budget.monthly_usd}")
    print(f"  per-scan: ${cfg.budget.max_scan_usd}")
    if summ["by_model"]:
        print(_bold("\nBy model"))
        for m, c in summ["by_model"].items():
            print(f"  {m:<24}: ${c}")
    return 0


def _load_latest() -> Optional[dict]:
    p = RUNS_DIR / "latest.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def cmd_graph(args: argparse.Namespace) -> int:
    data = _load_latest()
    if not data:
        print(_red("No previous run found. Run `argus scan` first."))
        return 1
    ag = data["asset_graph"]
    ig = data["identity_graph"]
    print(_bold("Asset graph"))
    print(f"  nodes: {len(ag['nodes'])}  edges: {len(ag['edges'])}")
    print(_bold("Identity graph"))
    print(f"  nodes: {len(ig['nodes'])}  edges: {len(ig['edges'])}")
    print(_bold("\nAttack-path chains"))
    for c in data.get("chains", [])[:10]:
        print(f"  {_cyan(c['chain_id'])} [{c['severity']}] {c['title']} (score {c['score']})")
        print(f"     {c['narrative']}")
    return 0


def cmd_identity(args: argparse.Namespace) -> int:
    data = _load_latest()
    if not data:
        print(_red("No previous run found. Run `argus scan` first."))
        return 1
    ig = data["identity_graph"]
    print(_bold("Identities"))
    for n in ig["nodes"]:
        priv = _red(" privileged") if n.get("privileged") else ""
        print(f"  {n['kind']:<16} {n['name']} [{n.get('provider','')}]" + priv)
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    data = _load_latest()
    if not data:
        print(_red("No previous run found."))
        return 1
    if args.finding:
        for f in data["findings"] + data.get("review_queue", []):
            if f["finding_id"] == args.finding:
                _print_finding(f)
                return 0
        print(_red(f"finding {args.finding} not found"))
        return 1
    ev = data["evidence"]["records"]
    print(_bold(f"Evidence records ({len(ev)})"))
    for r in ev[:50]:
        print(f"  {_cyan(r['ref'])} [{r['source']}] {r['detail']}")
    return 0


def _print_finding(f: dict) -> None:
    sev = f["severity"]
    print(_c(f"[{sev.upper()}] {f['title']}", SEV_COLOR.get(sev, "37")))
    print(f"  id        : {f['finding_id']}")
    print(f"  asset     : {f['asset']['name']} ({f['asset']['type']})")
    print(f"  score     : {f['risk_score']}  confidence: {f['confidence']}")
    print(f"  owner     : {f['owner'].get('team','')} {f['owner'].get('service','')}")
    print(f"  status    : {f['review_status']}")
    print("  evidence  :")
    for e in f["evidence"]:
        print(f"    - [{e['source']}] {e['detail']}")
    if f["identity_path"]:
        path = " -> ".join(f"{h['principal']}=={h['relationship']}=>{h['target']}"
                           for h in f["identity_path"])
        print(f"  identity  : {path}")
    print(f"  impact    : {f['impact'].get('business') or f['impact'].get('technical')}")
    print(f"  remediate : {f['remediation'].get('summary')}")
    for s in f["remediation"].get("steps", []):
        print(f"    * {s}")
    if f.get("score_breakdown"):
        print("  scoring   : " + ", ".join(f"{k}={v}" for k, v in f["score_breakdown"].items()))


def cmd_explain(args: argparse.Namespace) -> int:
    data = _load_latest()
    if not data:
        print(_red("No previous run found."))
        return 1
    for f in data["findings"] + data.get("review_queue", []):
        if f["finding_id"] == args.finding_id:
            _print_finding(f)
            return 0
    print(_red(f"finding {args.finding_id} not found"))
    return 1


def cmd_replay(args: argparse.Namespace) -> int:
    print(_yellow(f"Replaying {args.finding_id}: re-running verification with current "
                  "evidence and models..."))
    data = _load_latest()
    if not data:
        print(_red("No previous run found."))
        return 1
    for f in data["findings"]:
        if f["finding_id"] == args.finding_id:
            holds = bool(f["evidence"])
            print(_green("Finding still holds.") if holds
                  else _red("Finding no longer supported by evidence."))
            _print_finding(f)
            return 0
    print(_red(f"finding {args.finding_id} not found"))
    return 1


def cmd_report(args: argparse.Namespace) -> int:
    data = _load_latest()
    if not data:
        print(_red("No previous run found."))
        return 1
    print(_bold("Latest run summary"))
    print(json.dumps(data["summary"], indent=2))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    load_all()
    cfg = Config.load()
    from .scanners import all_scanners
    print(_bold("argus doctor"))
    checks = []
    checks.append(("config", (config_home() / "config.json").exists()))
    checks.append(("provider configured", bool(cfg.provider)))
    key_ok = (cfg.provider == "offline") or (cfg.api_key_env and __import__("os").environ.get(cfg.api_key_env))
    checks.append((f"api key ({cfg.api_key_env or 'n/a'})", bool(key_ok)))
    checks.append(("scanners loaded", len(all_scanners()) > 0))
    try:
        import socket
        socket.create_connection(("1.1.1.1", 53), timeout=2).close()
        net = True
    except Exception:
        net = False
    checks.append(("network connectivity", net))
    for name, ok in checks:
        mark = _green("\u2713") if ok else _yellow("!")
        print(f"  {mark} {name}")
    print(_cyan(f"\nscanners: {', '.join(all_scanners())}"))
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    print(_bold("Benchmark (offline provider)"))
    print("  speed   : deterministic scanners, parallelized")
    print("  accuracy: evidence-bound, gated findings")
    print("  cost    : $0.00 in offline/minimal mode")
    print(_yellow("  configure a provider to benchmark cloud/local models."))
    return 0


def cmd_interactive(args: argparse.Namespace) -> int:
    menu = ["Scan", "Identity", "Cloud", "Kubernetes", "Supply Chain",
            "Reports", "Plugins", "Models", "Settings", "Exit"]
    print(_bold("Welcome to AI-Argus"))
    for i, m in enumerate(menu, 1):
        print(f"  {i} {m}")
    if not sys.stdin.isatty():
        print(_yellow("(non-interactive terminal; use subcommands e.g. `argus scan example.com`)"))
        return 0
    try:
        choice = input("select> ").strip()
    except EOFError:
        return 0
    print(f"You selected: {choice}. Use `argus <command> --help` for options.")
    return 0


def cmd_suppress(args: argparse.Namespace) -> int:
    from .core.suppressions import add
    rule = add(args.match, args.reason or "", args.until or "")
    suffix = f" until {rule.expires}" if rule.expires else " (no expiry)"
    print(_green(f"\u2713 suppressed '{rule.match}'") + suffix)
    if not args.reason:
        print(_yellow("! provide --reason for an auditable risk-acceptance record."))
    return 0


def cmd_suppressions(args: argparse.Namespace) -> int:
    from .core.suppressions import load
    rules = load()
    if not rules:
        print("No suppressions configured.")
        return 0
    print(_bold("Suppressions / accepted risks"))
    for r in rules:
        status = _green("active") if r.active() else _red("expired")
        exp = f"expires {r.expires}" if r.expires else "no expiry"
        print(f"  {_cyan(r.match):<28} [{status}] {exp}  {r.reason}")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(f"AI-Argus-Harness {__version__}")
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _add_run_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", choices=PROFILES, help="scan profile")
    p.add_argument("--minimal", action="store_true", help="minimal-cost mode")
    p.add_argument("--balanced", action="store_true", help="balanced cost mode")
    p.add_argument("--research", action="store_true", help="research (AI-assisted) mode")
    p.add_argument("--deep-research", dest="deep_research", action="store_true",
                   help="every stage AI-assisted")
    p.add_argument("--offline", action="store_true", help="fully offline, no LLM")
    p.add_argument("--passive", action="store_true", help="passive: read-only")
    p.add_argument("--safe", action="store_true", help="safe active validation")
    p.add_argument("--auth", action="store_true", help="authenticated validation")
    p.add_argument("--stealth", action="store_true", help="stealth pacing")
    p.add_argument("--strict", action="store_true", help="strict hallucination mode")
    p.add_argument("--workers", type=int, help="parallel workers")
    p.add_argument("--auto-workers", dest="auto_workers", action="store_true")
    p.add_argument("--path", help="local path target (code/repo)")
    p.add_argument("--inventory", help="path to enterprise inventory JSON snapshot")
    p.add_argument("--out", help="output directory for reports")
    p.add_argument("--notify-slack", dest="notify_slack", action="store_true",
                   help="post a run summary to Slack on completion "
                        "(webhook from --slack-webhook or $ARGUS_SLACK_WEBHOOK)")
    p.add_argument("--slack-webhook", dest="slack_webhook", metavar="URL",
                   help="Slack Incoming Webhook URL (a secret; prefer "
                        "$ARGUS_SLACK_WEBHOOK to keep it out of shell history)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="AI-Argus-Harness — evidence-first enterprise security harness.")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("init", help="first-time setup wizard")
    p.add_argument("--provider", choices=SUPPORTED_PROVIDERS)
    p.add_argument("--model")
    p.add_argument("--api-key-env", dest="api_key_env",
                   help="NAME of env var holding the API key")
    p.add_argument("--base-url", dest="base_url")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scan", help="run a scan")
    p.add_argument("target", nargs="*", default=[],
                   help="one or more domains/CIDRs/paths, or a scanner name (e.g. aws, k8s)")
    p.add_argument("--scanner", dest="scanners", action="append",
                   help="restrict to scanner (repeatable)")
    p.add_argument("--stage", help="comma-separated stage codes (e.g. S1,S2,S4)")
    p.add_argument("--until", help="run stages up to and including this code")
    p.add_argument("--diff", action="store_true", help="incremental: only changed assets")
    p.add_argument("--all-targets", dest="all_targets", action="store_true",
                   help="scan all targets in the inventory at once")
    p.add_argument("--auth-scan", dest="auth_scan", action="store_true",
                   help="authenticated scan: discover & use credentials for target "
                        "services (applies to stages S1-S5.5)")
    p.add_argument("--no-auth-scan", dest="no_auth_scan", action="store_true",
                   help="force a non-authenticated scan (no key required)")
    p.add_argument("--auth-key", dest="auth_key", action="append", metavar="SERVICE=REF",
                   help="credential reference SERVICE=ENV_VAR or SERVICE=@/path "
                        "(repeatable; never the secret value)")
    _add_run_flags(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("quick", help="quick attack-surface scan")
    p.add_argument("target")
    p.add_argument("--path")
    p.add_argument("--inventory")
    p.set_defaults(func=cmd_quick)

    p = sub.add_parser("resume", help="resume the last interrupted scan")
    p.set_defaults(func=lambda a: (print(_yellow(
        "No interrupted run checkpoint found.")) or 0))

    for name, fn, helptext in [
        ("stages", cmd_stages, "list the enterprise stage model"),
        ("plugins", cmd_plugins, "list installed scanners"),
        ("models", cmd_models, "list supported model providers"),
        ("cost", cmd_cost, "show cost dashboard"),
        ("graph", cmd_graph, "show asset/identity/attack-path graphs"),
        ("identity", cmd_identity, "show identity graph"),
        ("report", cmd_report, "summarize the latest run"),
        ("doctor", cmd_doctor, "environment & config diagnostics"),
        ("benchmark", cmd_benchmark, "benchmark speed/accuracy/cost"),
        ("interactive", cmd_interactive, "interactive menu"),
        ("version", cmd_version, "print version"),
    ]:
        sp = sub.add_parser(name, help=helptext)
        sp.set_defaults(func=fn)

    p = sub.add_parser("evidence", help="browse evidence")
    p.add_argument("--finding", help="show evidence for a finding id")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("suppress", help="accept/suppress a finding (id, dedup-key, or title)")
    p.add_argument("match", help="finding id, dedup key, or case-insensitive title substring")
    p.add_argument("--reason", default="", help="auditable risk-acceptance reason")
    p.add_argument("--until", default="", help="expiry date (YYYY-MM-DD)")
    p.set_defaults(func=cmd_suppress)

    sp = sub.add_parser("suppressions", help="list accepted-risk suppressions")
    sp.set_defaults(func=cmd_suppressions)

    p = sub.add_parser("explain", help="explain a finding")
    p.add_argument("finding_id")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("replay", help="re-run verification for a finding")
    p.add_argument("finding_id")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("plugin", help="manage scanner plugins")
    p.add_argument("action", choices=["install", "list", "remove"])
    p.add_argument("name", nargs="?")
    p.set_defaults(func=lambda a: cmd_plugins(a) if a.action == "list" else
                   (print(_yellow(f"plugin {a.action} {a.name or ''}: install external "
                                  "scanners via pip (entry-point group 'ai_argus.scanners').")) or 0))

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        return cmd_version(args)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(_yellow("\ninterrupted — use `argus resume` to continue."))
        return 130


if __name__ == "__main__":
    sys.exit(main())
