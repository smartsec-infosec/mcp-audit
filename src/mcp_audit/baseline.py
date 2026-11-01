"""Rug-pull detection: hash tool definitions and diff against a saved baseline."""
from __future__ import annotations
import hashlib, json
from .checks import make


def _h(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def snapshot(servers):
    return {"version": 1, "servers": {s: {t["name"]: {"hash": _h({k: t.get(k) for k in ("description", "inputSchema", "annotations")}),
                                                      "description": t.get("description"), "inputSchema": t.get("inputSchema")}
                                          for t in d.get("tools", [])} for s, d in servers.items()}}


def diff(baseline, servers):
    findings, cur = [], snapshot(servers)["servers"]
    for s, tools in cur.items():
        old = baseline.get("servers", {}).get(s)
        if old is None:
            continue
        for n, t in tools.items():
            if n not in old:
                findings.append(make("MCP071", f"{s}/{n}", "tool added since baseline"))
            elif old[n]["hash"] != t["hash"]:
                parts = []
                if old[n].get("description") != t.get("description"):
                    parts.append(f"description was: {str(old[n].get('description'))[:120]!r} now: {str(t.get('description'))[:160]!r}")
                if old[n].get("inputSchema") != t.get("inputSchema"):
                    parts.append("inputSchema changed")
                findings.append(make("MCP070", f"{s}/{n}", "; ".join(parts) or "annotations changed"))
        for n in old:
            if n not in tools:
                findings.append(make("MCP071", f"{s}/{n}", "tool removed since baseline"))
    return findings
