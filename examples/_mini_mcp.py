"""Tiny dependency-free stdio MCP server harness used by the demo servers (enumeration only)."""
import json, sys


def serve(name, tools, instructions=None, prompts=None, resources=None):
    caps = {"tools": {}}
    if prompts is not None:
        caps["prompts"] = {}
    if resources is not None:
        caps["resources"] = {}
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:
            continue
        if method == "initialize":
            res = {"protocolVersion": "2025-06-18", "capabilities": caps,
                   "serverInfo": {"name": name, "version": "0.0.1"}}
            if instructions:
                res["instructions"] = instructions
        elif method == "tools/list":
            res = {"tools": tools}
        elif method == "prompts/list":
            res = {"prompts": prompts or []}
        elif method == "resources/list":
            res = {"resources": resources or []}
        elif method == "tools/call":
            # Demo servers deliberately refuse: mcp-audit must never get here.
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "demo: tools/call disabled"}}) + "\n")
            sys.stdout.flush()
            continue
        else:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}}) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}) + "\n")
        sys.stdout.flush()
