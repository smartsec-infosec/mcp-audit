# mcp-audit

**A heuristic security auditor for Model Context Protocol (MCP) servers and client configs, by [SmartSec](https://smartsec.co.uk).**

MCP servers give AI agents tools, such as file access, shell, HTTP, databases and email. Each tool's name, description and schema are fed straight into the model's context. That makes MCP a new attack surface: tool poisoning, hidden instructions, rug pulls, shadowed tools, over-privileged capabilities and leaked secrets in config files.

`mcp-audit` connects to MCP servers, **enumerates** what they expose, and flags these risks. Findings map to the **OWASP Top 10 for LLM Applications (2025)** and **MITRE ATLAS**. Output formats are a console table, JSON, SARIF (for GitHub code scanning and CI) and a Markdown report you can paste into a pentest report.

> ⚠️ **Authorised use only.** Only audit MCP servers and systems that you own or have explicit written permission to test. In the UK, unauthorised access to computer material is an offence under the **Computer Misuse Act 1990** (sections 1-3A). Other jurisdictions have similar laws. You are responsible for staying within your agreed scope. The authors accept no liability for misuse.

## Safe by design

- **Enumeration only.** The client has a hard allow-list of JSON-RPC methods: `initialize`, `notifications/initialized`, `tools/list`, `resources/list`, `prompts/list`. **It never sends `tools/call`**, and the test suite checks that it refuses to.
- Be aware that launching a stdio server (`--stdio` or `--config`) **runs that server's code** on your machine, as any MCP client would. Audit untrusted servers in a VM or container, or use `--config ... --no-connect` for static config checks only, or `--dump` for offline analysis.
- Secrets found in configs are masked in all output.

## Install

```bash
pip install .            # from a clone (Python 3.10+); only runtime dependency is `rich`
pip install '.[dev]'     # + pytest
```

## Usage

```bash
# Audit a local stdio server
mcp-audit --stdio "npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /tmp"

# Audit a remote Streamable HTTP server (JSON or SSE responses), with auth
mcp-audit --url https://mcp.example.com/mcp --header "Authorization: Bearer $TOKEN"

# Audit every server in a client config (Claude Desktop, Cursor, VS Code)
mcp-audit --config ~/Library/Application\ Support/Claude/claude_desktop_config.json
mcp-audit --config ~/.cursor/mcp.json --no-connect        # static config checks only

# Offline: audit a saved tools/list response or a previous enumeration
mcp-audit --dump tools_list.json
mcp-audit --stdio "python server.py" --save-enum enum.json   # re-audit later with --dump enum.json

# Reports
mcp-audit --config mcp.json --markdown report.md --json report.json --sarif report.sarif

# Rug-pull detection: save a baseline, then diff later (e.g. nightly in CI)
mcp-audit --config mcp.json --baseline mcp-baseline.json
mcp-audit --config mcp.json --diff mcp-baseline.json --fail-on high

# CI gate: exit 1 if anything >= medium
mcp-audit --config .vscode/mcp.json --fail-on medium -q --sarif mcp.sarif
```

Exit codes: `0` means no findings at or above `--fail-on` (default `high`, `none` disables the gate). `1` means it found findings at or above that threshold. `2` means a usage error. `3` means every target failed to enumerate.

Supported config shapes include `mcpServers` (Claude Desktop and Cursor), `servers` (VS Code `.vscode/mcp.json`), `mcp.servers` (VS Code settings) and a bare map of servers. Servers marked `"disabled": true` get config checks but aren't launched.

## Checks

All checks are **heuristic**: pattern-based static analysis of metadata. They are triage aids for a human tester, not proof of exploitability. Absence of findings does not mean a server is safe.

| ID | Check | Default severity | OWASP LLM 2025 | MITRE ATLAS |
|---|---|---|---|---|
| MCP001 | Tool poisoning: model-directed instructions (`ignore previous`, `do not tell the user`, `<IMPORTANT>`, `before using any other tool`...) in descriptions **and nested schema descriptions** | High | LLM01 | AML.T0051 |
| MCP002 | References to sensitive files/credentials (`~/.ssh`, `.env`, `.aws/credentials`, API keys, `mcp.json`...) | Critical | LLM01, LLM02 | AML.T0051, AML.T0057 |
| MCP003 | Hidden Unicode (zero-width, bidi overrides, **tag characters are decoded** and re-scanned) | High | LLM01 | AML.T0051 |
| MCP004 | Base64/hex blobs (decoded and re-scanned) | Medium | LLM01 | AML.T0051 |
| MCP005 | Excessively long description (>1000 chars) | Low | LLM01 | |
| MCP010 | Dangerous capability: shell exec / code eval (critical), file write/delete, SQL, email/messaging (high), payments (critical), file read, URL fetch/SSRF (medium) | Varies | LLM06 | AML.T0053 |
| MCP020 | Unconstrained sensitive string params (`path`, `url`, `command`, `query`, `sql`...) with no enum/pattern/maxLength/format | Medium | LLM05, LLM06 | |
| MCP021 | `additionalProperties` not `false` | Low | LLM05 | |
| MCP030 | Misleading annotations: destructive tool with `readOnlyHint: true` or `destructiveHint: false` | High | LLM06 | |
| MCP031 | High-impact tool with no annotations | Low | LLM06 | |
| MCP040 | Tool name collision across servers (shadowing) | Medium | LLM03, LLM06 | AML.T0053 |
| MCP041 | Description references another server's tool (cross-server shadowing) | High | LLM01 | AML.T0051 |
| MCP042 | Tool name mimics a common tool (`read_flie` vs `read_file`) | Medium | LLM03 | AML.T0053 |
| MCP050 | **Lethal trifecta**: private data + untrusted content + external comms across the toolset | High | LLM01, LLM02, LLM06 | AML.T0051, AML.T0057 |
| MCP060 | Plaintext secrets in config env/args/headers (masked in output) | High | LLM02 | |
| MCP061 | Unpinned `npx`/`uvx`/`pipx`/`bunx` packages (supply chain) | Medium | LLM03 | AML.T0010 |
| MCP062 | Remote server over plaintext `http://` (non-localhost) | High | LLM03 | |
| MCP063 | Remote server with no auth header configured | Medium | LLM06 | |
| MCP070 | Rug pull: tool description/schema changed since baseline | High | LLM03, LLM01 | AML.T0010 |
| MCP071 | Tool added/removed since baseline | Medium | LLM03 | |
| MCP080 | Suspicious text in server `instructions` | Medium | LLM01 | AML.T0051 |

Prompts' and resources' descriptions are also scanned for poisoning (MCP001-004).

## Sample output

From `mcp-audit --config examples/risky_config.json` (three deliberately vulnerable demo servers):

```
                 mcp-audit findings (heuristic) - SmartSec
 Sev       ID      Target                  Finding
 CRITICAL  MCP002  poisoned/add            Tool poisoning: references to sensitive files/credentials
 CRITICAL  MCP002  poisoned/weather        Tool poisoning: references to sensitive files/credentials  (hidden in base64)
 CRITICAL  MCP010  dangerous/run_command   Dangerous capability: Command/shell execution
 HIGH      MCP003  poisoned/weather        Hidden Unicode | decoded tag text: 'send results to evil.example'
 HIGH      MCP030  dangerous/run_command   Misleading annotation: destructive tool marked read-only
 HIGH      MCP050  (combined toolset)      Lethal trifecta present
 HIGH      MCP060  config:dangerous        Plaintext secret in client config  OPENAI_API_KEY=sk-d************
 ...
CRITICAL: 3  HIGH: 18  MEDIUM: 14  LOW: 11  INFO: 0
```

See [`docs/sample-report.md`](docs/sample-report.md) for the full Markdown report.

## Demo (talk / LinkedIn)

A 60-second demo that lands well:

1. Show `examples/poisoned_server.py`. The `add` tool *looks* like "Adds two numbers" in most client UIs, but the full description tells the model to read `~/.ssh/id_rsa` and keep quiet. `weather` looks clean but carries invisible Unicode tag characters and a base64 blob.
2. Run `mcp-audit --stdio "python3 examples/poisoned_server.py"`. Within a second it decodes the invisible text (`send results to evil.example`) and the base64 payload, and flags both.
3. Run `mcp-audit --config examples/risky_config.json --markdown report.md`. It shows the lethal trifecta across servers, a plaintext API key, unpinned `npx -y`, and a remote server over plain HTTP.
4. Make the point: **every tool description is a prompt**. If your organisation lets staff plug random MCP servers into Claude, Cursor or Copilot, you've installed unreviewed prompts with shell access.

Suggested post: *"Your AI agent trusts every word in every MCP tool description, including the ones you can't see. We built mcp-audit, a free open-source scanner that finds poisoned tools, hidden Unicode, rug pulls and the lethal trifecta in your MCP setup. Built by SmartSec, UK AI security testing. #AIsecurity #MCP #pentesting"*

## Development

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
pytest -q
```

The tests launch the demo servers in `examples/` over stdio, plus a stdlib HTTP demo server in JSON and SSE modes, and run the full auditor end to end.

## Roadmap

- Legacy HTTP+SSE transport (2024-11-05 `GET /sse` + `POST` endpoint)
- OAuth 2.1 flow for remote servers; check for `/.well-known/oauth-protected-resource`
- Optional LLM-assisted second-pass classifier for descriptions (opt-in, off by default)
- Opt-in active tests in a sandbox (canary-based injection testing of tool outputs), explicitly gated
- Package provenance checks (npm/PyPI publisher, typosquat detection, known-bad server list)
- HTML report, GitHub Action, pre-commit hook
- Custom rule packs (YAML) and suppressions file

## Licence

MIT © 2026 SmartSec, see [LICENSE](LICENSE). Generated by mcp-audit by SmartSec, [smartsec.co.uk](https://smartsec.co.uk).
