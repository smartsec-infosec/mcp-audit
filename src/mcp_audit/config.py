"""Parse MCP client configs (Claude Desktop, Cursor, VS Code, generic) and run config-level checks."""
from __future__ import annotations
import json, re
from urllib.parse import urlparse
from .checks import make

SECRET_KEY = re.compile(r"(token|secret|password|passwd|api[_-]?key|apikey|auth|credential|private[_-]?key|bearer)", re.I)
SECRET_VAL = re.compile(r"^(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
                        r"xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.?.*|"
                        r"Bearer\s+\S{12,}|[A-Za-z0-9_\-]{32,})$")
KNOWN_TOKEN = re.compile(r"^(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|xox[abposr]-[\w-]{10,}|AKIA[0-9A-Z]{16}|AIza[\w-]{30,}|eyJ[\w-]{10,}\.[\w-]+)")
PLACEHOLDER = re.compile(r"^(\$\{.*\}|\$[A-Z_]+|<.*>|your[-_ ].*|xxx+|changeme|\*+|)$", re.I)


def load_config(path):
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    servers = raw.get("mcpServers") or raw.get("servers") or (raw.get("mcp") or {}).get("servers") or {}
    if not servers and isinstance(raw, dict) and all(isinstance(v, dict) and ("command" in v or "url" in v) for v in raw.values()):
        servers = raw
    return servers


def _mask(v):
    return v[:4] + "*" * max(0, min(len(v) - 4, 12)) if len(v) > 4 else "****"


def check_config(servers):
    findings = []
    for name, spec in servers.items():
        tgt = f"config:{name}"
        kv = list((spec.get("env") or {}).items()) + list((spec.get("headers") or {}).items())
        for k, v in kv:
            if not isinstance(v, str) or PLACEHOLDER.match(v.strip()) or v.startswith("${"):
                continue
            if SECRET_VAL.match(v.strip()) or (SECRET_KEY.search(k) and len(v) >= 8):
                findings.append(make("MCP060", tgt, f"{k}={_mask(v)}"))
        args = [str(a) for a in spec.get("args") or []]
        for i, a in enumerate(args):
            m = re.match(r"^--?([\w-]+)=(.+)$", a)
            key, val = (m.group(1), m.group(2)) if m else ((args[i - 1].lstrip("-") if i and args[i - 1].startswith("-") else ""), a)
            known = KNOWN_TOKEN.match(val)
            keyed = key and SECRET_KEY.search(key) and len(val) >= 8 and not PLACEHOLDER.match(val) and not val.startswith(("$", "/", "."))
            if known or keyed:
                findings.append(make("MCP060", tgt, f"arg {key or i}={_mask(val)}"))
        cmd = (spec.get("command") or "").split("/")[-1]
        if cmd in ("npx", "bunx", "pnpx", "uvx", "pipx") or (cmd in ("pnpm", "yarn") and "dlx" in args):
            pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "run")]
            if pkgs:
                pkg = pkgs[0]
                pinned = re.search(r"@\d[\w.\-]*$", pkg) or "==" in pkg or any(a.startswith("--from") and "==" in a for a in args)
                if not pinned:
                    auto = " (auto-install with -y)" if "-y" in args or "--yes" in args else ""
                    findings.append(make("MCP061", tgt, f"{cmd} {pkg}{auto}"))
        url = spec.get("url") or spec.get("serverUrl")
        if url:
            u = urlparse(url)
            local = u.hostname in ("localhost", "127.0.0.1", "::1")
            if u.scheme == "http" and not local:
                findings.append(make("MCP062", tgt, url))
            hdrs = {k.lower() for k in (spec.get("headers") or {})}
            if not local and not hdrs & {"authorization", "x-api-key", "api-key"} and not spec.get("auth") and not spec.get("oauth"):
                findings.append(make("MCP063", tgt, f"{url} has no auth header configured"))
    return findings
