"""mcp-audit command-line interface."""
from __future__ import annotations
import argparse, json, os, shlex, sys
from . import __version__
from .checks import SEVERITIES, sev_rank, audit_server, cross_server
from .client import StdioClient, HTTPClient
from .config import load_config, check_config
from .baseline import snapshot, diff
from . import report

BANNER = "mcp-audit by SmartSec - authorised testing only (enumeration mode, no tool calls)"


def enumerate_spec(name, spec, timeout, headers=None):
    url = spec.get("url") or spec.get("serverUrl")
    if url:
        h = dict(spec.get("headers") or {})
        h.update(headers or {})
        with HTTPClient(url, h, timeout) as c:
            return c.enumerate()
    env = {k: os.path.expandvars(str(v)) for k, v in (spec.get("env") or {}).items()}
    with StdioClient(spec["command"], [str(a) for a in spec.get("args") or []], env, timeout) as c:
        return c.enumerate()


def load_dump(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if isinstance(d, list):
        return {os.path.basename(path): {"tools": d}}
    if "result" in d:  # raw JSON-RPC response
        d = d["result"]
    if "servers" in d and isinstance(d["servers"], dict):  # our own --dump output
        return d["servers"]
    return {d.get("serverInfo", {}).get("name") or os.path.basename(path): d}


def build_parser():
    p = argparse.ArgumentParser(prog="mcp-audit", description=BANNER)
    p.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    src = p.add_argument_group("targets (combine freely)")
    src.add_argument("--stdio", action="append", default=[], metavar="CMD",
                     help="launch a stdio MCP server, e.g. --stdio 'python server.py'")
    src.add_argument("--url", action="append", default=[], help="Streamable HTTP MCP endpoint URL")
    src.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                     help="extra HTTP header for --url targets (e.g. Authorization)")
    src.add_argument("--config", action="append", default=[], help="client config (claude_desktop_config.json, mcp.json, .vscode/mcp.json)")
    src.add_argument("--dump", action="append", default=[], help="offline: audit a saved tools/list or enumeration JSON")
    src.add_argument("--no-connect", action="store_true", help="with --config: static config checks only, don't launch servers")
    out = p.add_argument_group("output")
    out.add_argument("--json", metavar="FILE")
    out.add_argument("--sarif", metavar="FILE")
    out.add_argument("--markdown", "--md", metavar="FILE")
    out.add_argument("--save-enum", metavar="FILE", help="save raw enumeration (re-auditable with --dump)")
    out.add_argument("--title", default="MCP Server Security Assessment")
    out.add_argument("-q", "--quiet", action="store_true", help="no console table")
    p.add_argument("--baseline", metavar="FILE", help="save tool-definition hashes to FILE (rug-pull baseline)")
    p.add_argument("--diff", metavar="FILE", help="compare against a saved baseline and flag changes")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit 1 if any finding >= this severity (default: high)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this")
    p.add_argument("--timeout", type=float, default=20.0)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    if not (a.stdio or a.url or a.config or a.dump):
        build_parser().print_help(sys.stderr)
        return 2
    headers = {}
    for h in a.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    servers, findings, errors = {}, [], []

    def attempt(name, spec):
        try:
            servers[name] = enumerate_spec(name, spec, a.timeout, headers)
        except Exception as e:  # noqa
            errors.append(f"{name}: {e}")

    for i, cmd in enumerate(a.stdio):
        parts = shlex.split(cmd)
        attempt(f"stdio-{i + 1}:{os.path.basename(parts[-1])}", {"command": parts[0], "args": parts[1:]})
    for i, u in enumerate(a.url):
        attempt(u, {"url": u})
    for cfg in a.config:
        specs = load_config(cfg)
        findings += check_config(specs)
        if not a.no_connect:
            for n, spec in specs.items():
                if spec.get("disabled"):
                    continue
                attempt(n, spec)
    for d in a.dump:
        servers.update(load_dump(d))

    legs = {}
    for s, d in servers.items():
        f, l = audit_server(s, d)
        findings += f
        legs[s] = l
    findings += cross_server(servers, legs)
    if a.diff:
        with open(a.diff, encoding="utf-8") as fh:
            findings += diff(json.load(fh), servers)
    if a.baseline:
        with open(a.baseline, "w", encoding="utf-8") as fh:
            json.dump(snapshot(servers), fh, indent=2, ensure_ascii=False)
    if a.save_enum:
        with open(a.save_enum, "w", encoding="utf-8") as fh:
            json.dump({"servers": servers}, fh, indent=2, ensure_ascii=False)

    findings = [f for f in findings if sev_rank(f.severity) >= sev_rank(a.min_severity)]
    inventory = {s: {"serverInfo": d.get("serverInfo", {}), "tools": len(d.get("tools", [])),
                     "resources": len(d.get("resources", [])), "prompts": len(d.get("prompts", []))} for s, d in servers.items()}
    if not a.quiet:
        print(BANNER, file=sys.stderr)
        report.console(findings, inventory)
    for e in errors:
        print(f"[!] enumeration failed: {e}", file=sys.stderr)
    for path, fn in ((a.json, lambda: report.to_json(findings, inventory)), (a.sarif, lambda: report.to_sarif(findings)),
                     (a.markdown, lambda: report.to_markdown(findings, inventory, a.title))):
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(fn())
    if a.fail_on != "none" and any(sev_rank(f.severity) >= sev_rank(a.fail_on) for f in findings):
        return 1
    return 3 if errors and not servers else 0


if __name__ == "__main__":
    sys.exit(main())
