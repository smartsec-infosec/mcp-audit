"""Heuristic security checks. All checks are pattern-based and may yield false positives/negatives."""
from __future__ import annotations
import re, unicodedata
from dataclasses import dataclass, field, asdict

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s):
    return SEVERITIES.index(s)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    target: str  # server[/tool]
    evidence: str
    description: str
    remediation: str
    owasp: list = field(default_factory=list)
    atlas: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# id -> (title, default severity, description, remediation, owasp, atlas)
CHECKS = {
    "MCP001": ("Tool poisoning: model-directed instructions in description", "high",
               "Tool/schema descriptions are injected into the model context. Imperative text aimed at the model "
               "(e.g. 'ignore previous instructions', 'do not tell the user') can hijack agent behaviour.",
               "Review and remove instructions aimed at the model. Descriptions should only describe behaviour.",
               ["LLM01:2025 Prompt Injection"], ["AML.T0051 LLM Prompt Injection"]),
    "MCP002": ("Tool poisoning: references to sensitive files/credentials", "critical",
               "Description references secrets locations (~/.ssh, .env, credentials, API keys) - a classic "
               "exfiltration pattern in poisoned tools.",
               "Remove the reference; investigate the server's provenance and integrity.",
               ["LLM01:2025 Prompt Injection", "LLM02:2025 Sensitive Information Disclosure"],
               ["AML.T0051 LLM Prompt Injection", "AML.T0057 LLM Data Leakage"]),
    "MCP003": ("Hidden Unicode characters in metadata", "high",
               "Zero-width, bidirectional-override or Unicode tag characters can hide instructions from humans "
               "while remaining visible to the model.",
               "Strip non-printing characters; treat their presence as a strong indicator of tampering.",
               ["LLM01:2025 Prompt Injection"], ["AML.T0051 LLM Prompt Injection"]),
    "MCP004": ("Encoded blob in metadata", "medium",
               "Long base64/hex strings in descriptions may smuggle obfuscated instructions.",
               "Decode and review; remove encoded content from descriptions.",
               ["LLM01:2025 Prompt Injection"], ["AML.T0051 LLM Prompt Injection"]),
    "MCP005": ("Excessively long description", "low",
               "Very long descriptions consume context and are a common hiding place for injected instructions.",
               "Keep descriptions concise (<1000 chars) and review long ones manually.",
               ["LLM01:2025 Prompt Injection"], []),
    "MCP010": ("Dangerous capability", "high",
               "Tool appears to expose a high-impact capability. Combined with prompt injection this may allow "
               "an attacker to act through the agent.",
               "Confirm need; restrict scope (allow-lists, sandboxing), require human confirmation, least privilege.",
               ["LLM06:2025 Excessive Agency"], ["AML.T0053 LLM Plugin Compromise"]),
    "MCP020": ("Over-broad input parameter", "medium",
               "A sensitive free-form string parameter has no enum, pattern, or maxLength constraint.",
               "Constrain inputs with enum/pattern/maxLength and validate server-side (path allow-lists, URL allow-lists, parameterised queries).",
               ["LLM05:2025 Improper Output Handling", "LLM06:2025 Excessive Agency"], []),
    "MCP021": ("Input schema allows additional properties", "low",
               "additionalProperties is not false; arbitrary extra arguments may reach the implementation.",
               "Set additionalProperties: false.",
               ["LLM05:2025 Improper Output Handling"], []),
    "MCP030": ("Misleading annotation: destructive tool marked read-only", "high",
               "Tool advertises readOnlyHint=true yet appears to write/delete/execute. Clients may auto-approve it.",
               "Correct the annotations. Clients must not trust annotations from untrusted servers.",
               ["LLM06:2025 Excessive Agency"], []),
    "MCP031": ("Missing annotations on high-impact tool", "low",
               "High-impact tool has no destructiveHint/readOnlyHint annotations, so clients cannot warn users.",
               "Add accurate annotations (readOnlyHint, destructiveHint, openWorldHint).",
               ["LLM06:2025 Excessive Agency"], []),
    "MCP040": ("Tool name collision across servers", "medium",
               "Two servers expose the same tool name; one can shadow the other and intercept calls.",
               "Namespace tools per server; remove the duplicate or untrusted server.",
               ["LLM03:2025 Supply Chain", "LLM06:2025 Excessive Agency"], ["AML.T0053 LLM Plugin Compromise"]),
    "MCP041": ("Tool description references another server's tools", "high",
               "Description mentions tools from a different server - a cross-server shadowing pattern.",
               "Investigate; descriptions should not alter how other tools are used.",
               ["LLM01:2025 Prompt Injection"], ["AML.T0051 LLM Prompt Injection"]),
    "MCP042": ("Tool name mimics a common tool", "medium",
               "Tool name is a near-miss of a well-known tool name (typosquatting), which can trick the model into "
               "calling it instead of the legitimate tool.",
               "Verify the server's provenance; rename or remove the tool.",
               ["LLM03:2025 Supply Chain"], ["AML.T0053 LLM Plugin Compromise"]),
    "MCP050": ("Lethal trifecta present", "high",
               "The combined toolset gives an agent private data access, exposure to untrusted content, and an "
               "external communication channel - enabling prompt-injection-driven data exfiltration.",
               "Split toolsets across agents/sessions, remove one leg, or require human approval for outbound actions.",
               ["LLM01:2025 Prompt Injection", "LLM02:2025 Sensitive Information Disclosure", "LLM06:2025 Excessive Agency"],
               ["AML.T0051 LLM Prompt Injection", "AML.T0057 LLM Data Leakage"]),
    "MCP060": ("Plaintext secret in client config", "high",
               "A credential-like value appears in env/args/headers of the client config file.",
               "Use an OS keychain/secret manager or env var reference; rotate the exposed secret.",
               ["LLM02:2025 Sensitive Information Disclosure"], []),
    "MCP061": ("Unpinned package executed at launch", "medium",
               "Server launched via npx/uvx/pipx without a pinned version; a malicious update runs automatically.",
               "Pin exact versions (pkg@1.2.3 / pkg==1.2.3) and review updates.",
               ["LLM03:2025 Supply Chain"], ["AML.T0010 ML Supply Chain Compromise"]),
    "MCP062": ("Remote server over plaintext HTTP", "high",
               "Remote MCP URL uses http:// (not localhost); traffic and tokens can be intercepted or modified.",
               "Use HTTPS.", ["LLM03:2025 Supply Chain"], []),
    "MCP063": ("Remote server without authentication", "medium",
               "No Authorization header/token configured for a remote server (may be acceptable if OAuth is used).",
               "Require authentication (OAuth 2.1 per MCP spec) on remote servers.",
               ["LLM06:2025 Excessive Agency"], []),
    "MCP070": ("Tool definition changed since baseline (rug pull)", "high",
               "Tool description/schema differs from the saved baseline. Silent changes after approval are a "
               "known MCP attack (rug pull).",
               "Review the diff; re-approve only if expected. Pin server versions.",
               ["LLM03:2025 Supply Chain", "LLM01:2025 Prompt Injection"], ["AML.T0010 ML Supply Chain Compromise"]),
    "MCP071": ("New/removed tool since baseline", "medium",
               "The set of tools differs from the saved baseline.", "Review whether the change is expected.",
               ["LLM03:2025 Supply Chain"], []),
    "MCP080": ("Server instructions contain model-directed text", "medium",
               "The initialize 'instructions' field contains suspicious imperative text.",
               "Review server instructions.", ["LLM01:2025 Prompt Injection"], ["AML.T0051 LLM Prompt Injection"]),
}


def make(check_id, target, evidence, severity=None, title=None):
    t, sev, desc, rem, owasp, atlas = CHECKS[check_id]
    return Finding(check_id, title or t, severity or sev, target, evidence[:400], desc, rem, owasp, atlas)


# --- pattern libraries -------------------------------------------------------
INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts?|messages?)",
    r"disregard (all |any )?(previous|prior|above|other)",
    r"(do not|don't|never) (tell|inform|mention|reveal|show|notify)( this| it)? (to )?the user",
    r"without (telling|informing|notifying|asking) the user",
    r"<\s*(important|system|instructions?|secret|hidden)\s*>",
    r"before (using|calling|invoking) (any|this|other|another)( other)? tool",
    r"(always|must) (first )?(call|use|invoke|run) (this|the \w+) tool",
    r"you (must|should) (now )?(act as|pretend|follow these)",
    r"\bsystem prompt\b",
    r"(the user|user) (has|have) (already )?(authori[sz]ed|approved|consented)",
    r"pass (its|the|their) (content|contents|output) (as|in|into) ",
    r"this is (very )?(important|critical),? (otherwise|or) ",
    r"(otherwise|or else) the (tool|application|system) will (crash|fail|not work)",
]
SENSITIVE_PATTERNS = [
    r"~/?\.ssh", r"\bid_rsa\b", r"\bid_ed25519\b", r"(^|[\s/'\"`])\.env\b", r"\.aws/credentials",
    r"\bcredentials?\.json\b", r"\.npmrc", r"\.netrc", r"\.git-credentials", r"/etc/(passwd|shadow)",
    r"\bmcp\.json\b", r"claude_desktop_config", r"\b(api[_ -]?keys?|private keys?|secret keys?|access tokens?)\b",
]
INJ_RE = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
SENS_RE = [re.compile(p, re.I) for p in SENSITIVE_PATTERNS]
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{48,}\b")

HIDDEN_CHARS = set("\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad\u180e"
                   "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

CAPABILITIES = {
    # name: (regex over name+description, severity, label, trifecta legs)
    "exec": (r"\b(exec(ute)?|shell|bash|terminal|run[_ ]?(command|cmd|script)|subprocess|powershell|cmd\.exe|spawn)\b",
             "critical", "Command/shell execution", {"private", "external"}),
    "eval": (r"\b(eval(uate)?[_ ]?(code|python|js|javascript|expression)?|run[_ ]?(python|code|js)|execute[_ ]?code|repl|jupyter)\b",
             "critical", "Arbitrary code evaluation", {"private", "external"}),
    "file_write": (r"\b(write|create|save|edit|append|overwrite|modify|update)[_ ]?(a |the )?(file|files|document)s?\b|\bwrite_file\b|\bedit_file\b",
                   "high", "File write", set()),
    "file_delete": (r"\b(delete|remove|rm|unlink|erase)[_ ]?(a |the )?(file|files|director(y|ies)|folder)s?\b", "high", "File delete", set()),
    "file_read": (r"\b(read|get|cat|open|load|view)[_ ]?(a |the |any )?(file|files|document|contents?)s?\b|\bread_file\b|\bfilesystem\b",
                  "medium", "File read", {"private"}),
    "http": (r"\b(fetch|http[_ ]?(get|post|request)|curl|wget|download|request[_ ]?url|browse|scrape|crawl|web[_ ]?(request|fetch))\b|\burl\b",
             "medium", "Outbound HTTP / URL fetch (SSRF / exfil)", {"untrusted", "external"}),
    "sql": (r"\b(raw[_ ]?)?(sql|query[_ ]?(database|db)|execute[_ ]?(query|sql)|run[_ ]?query)\b|\bdatabase\b",
            "high", "Database query", {"private"}),
    "messaging": (r"\b(send|post)[_ ]?(an? )?(e-?mail|message|sms|slack|tweet|dm|notification)s?\b|\bsmtp\b",
                  "high", "Send email/message", {"external"}),
    "payment": (r"\b(payment|pay|charge|transfer[_ ]?(funds|money)|refund|invoice|stripe|purchase|checkout|wire)\b",
                "critical", "Payments / financial actions", {"external"}),
    "read_inbox": (r"\b(read|list|search|get)[_ ]?(e-?mails?|inbox|messages|issues|tickets|comments|web ?pages?)\b",
                   "info", "Reads external/untrusted content", {"untrusted", "private"}),
}
CAP_RE = {k: re.compile(v[0], re.I) for k, v in CAPABILITIES.items()}
DESTRUCTIVE = {"exec", "eval", "file_write", "file_delete", "sql", "messaging", "payment"}

SENSITIVE_PARAMS = re.compile(r"^(path|file(path|name)?|dir(ectory)?|url|uri|endpoint|host|command|cmd|"
                              r"script|code|query|sql|statement|expression|shell|args?)$", re.I)

COMMON_TOOLS = {"read_file", "write_file", "list_directory", "search", "fetch", "run_command",
                "execute_command", "send_email", "query", "get_file_contents", "create_issue", "bash"}


def _texts(tool):
    """Yield (location, text) for a tool's description and all nested schema descriptions/titles."""
    if tool.get("description"):
        yield "description", tool["description"]
    if tool.get("title"):
        yield "title", tool["title"]

    def walk(node, path):
        if isinstance(node, dict):
            for k in ("description", "title", "default"):
                if isinstance(node.get(k), str):
                    yield f"{path}.{k}", node[k]
            for k, v in node.items():
                if k == "properties" and isinstance(v, dict):
                    for pn, pv in v.items():
                        yield from walk(pv, f"{path}.{pn}")
                elif isinstance(v, (dict, list)) and k != "properties":
                    yield from walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from walk(v, f"{path}[{i}]")
    yield from walk(tool.get("inputSchema") or {}, "inputSchema")


def _snip(text, m, pad=60):
    s = max(0, m.start() - pad)
    return ("..." if s else "") + text[s:m.end() + pad].replace("\n", " ") + "..."


def _decode(blob, kind):
    import base64, binascii
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4)) if kind == "base64" else bytes.fromhex(blob.removeprefix("0x"))
        txt = raw.decode("utf-8")
        return txt if sum(c.isprintable() for c in txt) / max(1, len(txt)) > 0.9 else None
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def scan_text(target, loc, text, findings, check_inj="MCP001"):
    for r in INJ_RE:
        m = r.search(text)
        if m:
            findings.append(make(check_inj, target, f"[{loc}] {_snip(text, m)}"))
            break
    for r in SENS_RE:
        m = r.search(text)
        if m:
            findings.append(make("MCP002", target, f"[{loc}] {_snip(text, m)}"))
            break
    hidden = [c for c in text if c in HIDDEN_CHARS or 0xE0000 <= ord(c) <= 0xE007F]
    if hidden:
        tag = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
        names = sorted({unicodedata.name(c, f"U+{ord(c):04X}") for c in hidden})[:5]
        ev = f"[{loc}] {len(hidden)} hidden chars"
        if tag:
            ev += f" | decoded tag text: {tag!r}"
        ev += f" | types: {', '.join(names)}"
        findings.append(make("MCP003", target, ev))
        if tag:  # also scan smuggled text
            scan_text(target, loc + "(tag-decoded)", tag, findings, check_inj)
    for r, kind in ((B64_RE, "base64"), (HEX_RE, "hex")):
        m = r.search(text)
        if m and not re.fullmatch(r"[a-z/]+", m.group(0)):  # skip long lowercase paths
            ev = f"[{loc}] {kind}-like blob: {m.group(0)[:60]}..."
            decoded = _decode(m.group(0), kind)
            if decoded:
                ev += f" | decodes to: {decoded[:160]!r}"
            findings.append(make("MCP004", target, ev))
            if decoded and loc.find("decoded") < 0:
                scan_text(target, loc + f"({kind}-decoded)", decoded, findings, check_inj)
            break
    if loc == "description" and len(text) > 1000:
        findings.append(make("MCP005", target, f"description is {len(text)} characters"))


def classify(tool):
    hay = f"{tool.get('name', '')} {tool.get('description', '')}".replace("_", " ")
    hay2 = hay + " " + tool.get("name", "")
    return {k for k, r in CAP_RE.items() if r.search(hay2)}


def check_tool(server, tool, findings):
    name = tool.get("name", "?")
    target = f"{server}/{name}"
    for loc, text in _texts(tool):
        scan_text(target, loc, text, findings)
    caps = classify(tool)
    for c in sorted(caps):
        _, sev, label, _ = CAPABILITIES[c]
        if sev == "info":
            continue
        findings.append(make("MCP010", target, f"{label} (matched on name/description)", severity=sev,
                             title=f"Dangerous capability: {label}"))
    # schema checks
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    for pn, pv in props.items():
        if not isinstance(pv, dict):
            continue
        if pv.get("type", "string") == "string" and SENSITIVE_PARAMS.match(pn) and not any(
                k in pv for k in ("enum", "pattern", "maxLength", "const", "format")):
            findings.append(make("MCP020", target, f"parameter '{pn}' is unconstrained string"))
    if props and schema.get("additionalProperties", True) is not False:
        findings.append(make("MCP021", target, "additionalProperties not set to false"))
    # annotations
    ann = tool.get("annotations") or {}
    destructive = caps & DESTRUCTIVE
    if destructive and ann.get("readOnlyHint") is True:
        findings.append(make("MCP030", target, f"readOnlyHint=true but capabilities: {', '.join(sorted(destructive))}"))
    elif destructive and not ann:
        findings.append(make("MCP031", target, f"no annotations; capabilities: {', '.join(sorted(destructive))}"))
    if destructive and ann.get("destructiveHint") is False and ann.get("readOnlyHint") is not True:
        findings.append(make("MCP030", target, f"destructiveHint=false but capabilities: {', '.join(sorted(destructive))}",
                             title="Misleading annotation: destructive tool marked non-destructive"))
    return caps


def audit_server(server, data):
    """data = enumeration dict (tools/resources/prompts/instructions). Returns (findings, legs)."""
    findings, legs = [], set()
    if data.get("instructions"):
        scan_text(f"{server}", "instructions", data["instructions"], findings, check_inj="MCP080")
    for tool in data.get("tools", []):
        for c in check_tool(server, tool, findings):
            legs |= CAPABILITIES[c][3]
    for kind in ("prompts", "resources"):
        for item in data.get(kind, []):
            if item.get("description"):
                scan_text(f"{server}/{kind}:{item.get('name', item.get('uri', '?'))}", "description",
                          item["description"], findings)
    return findings, legs


def cross_server(servers: dict, legs_by_server: dict):
    """servers: name -> enumeration data."""
    findings = []
    owners = {}
    for s, d in servers.items():
        for t in d.get("tools", []):
            owners.setdefault(t.get("name"), []).append(s)
    for n, ss in owners.items():
        if len(ss) > 1:
            findings.append(make("MCP040", ", ".join(ss), f"tool '{n}' exposed by {len(ss)} servers: {', '.join(ss)}"))
    if len(servers) > 1:
        for s, d in servers.items():
            for t in d.get("tools", []):
                desc = (t.get("description") or "").lower()
                for n, ss in owners.items():
                    if s not in ss and n and len(n) > 4 and re.search(rf"\b{re.escape(n.lower())}\b", desc):
                        findings.append(make("MCP041", f"{s}/{t.get('name')}",
                                             f"mentions tool '{n}' from server(s) {', '.join(ss)}"))
    import difflib
    for s, d in servers.items():
        for t in d.get("tools", []):
            n = (t.get("name") or "").lower()
            for c in COMMON_TOOLS:
                if n != c and len(n) >= 4 and difflib.SequenceMatcher(None, n, c).ratio() >= 0.85:
                    findings.append(make("MCP042", f"{s}/{t.get('name')}", f"'{t.get('name')}' resembles common tool '{c}'"))
    all_legs = set().union(*legs_by_server.values()) if legs_by_server else set()
    if {"private", "untrusted", "external"} <= all_legs:
        detail = "; ".join(f"{s}: {','.join(sorted(l))}" for s, l in legs_by_server.items() if l)
        findings.append(make("MCP050", "(combined toolset)", detail))
    return findings
