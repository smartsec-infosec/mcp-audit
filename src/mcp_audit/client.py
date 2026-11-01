"""Minimal MCP client (raw JSON-RPC 2.0). Enumeration only: never calls tools/call."""
from __future__ import annotations
import json, os, queue, subprocess, threading, urllib.request, urllib.error

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcp-audit", "version": "0.1.0"}
# Hard allow-list of methods this client will ever send. tools/call is deliberately absent.
ALLOWED = {"initialize", "notifications/initialized", "tools/list", "resources/list",
           "resources/templates/list", "prompts/list"}


class MCPError(Exception):
    pass


class _Base:
    _id = 0

    def _next(self):
        self._id += 1
        return self._id

    def request(self, method, params=None):
        if method not in ALLOWED:
            raise MCPError(f"refusing to send non-enumeration method {method!r}")
        msg = {"jsonrpc": "2.0", "id": self._next(), "method": method}
        if params is not None:
            msg["params"] = params
        resp = self._roundtrip(msg)
        if "error" in resp:
            raise MCPError(f"{method}: {resp['error']}")
        return resp.get("result", {})

    def notify(self, method, params=None):
        if method not in ALLOWED:
            raise MCPError(f"refusing {method!r}")
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send_notification(msg)

    def enumerate(self):
        init = self.request("initialize", {"protocolVersion": PROTOCOL_VERSION,
                                           "capabilities": {}, "clientInfo": CLIENT_INFO})
        self.notify("notifications/initialized")
        caps = init.get("capabilities", {}) or {}
        out = {"serverInfo": init.get("serverInfo", {}), "protocolVersion": init.get("protocolVersion"),
               "capabilities": caps, "instructions": init.get("instructions"),
               "tools": [], "resources": [], "prompts": [], "errors": []}
        for key, method in (("tools", "tools/list"), ("resources", "resources/list"), ("prompts", "prompts/list")):
            if key not in caps and key != "tools":
                continue
            try:
                out[key] = self._paginate(method, key)
            except Exception as e:  # noqa
                out["errors"].append(f"{method}: {e}")
        return out

    def _paginate(self, method, key):
        items, cursor = [], None
        for _ in range(50):
            res = self.request(method, {"cursor": cursor} if cursor else {})
            items.extend(res.get(key, []))
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return items


class StdioClient(_Base):
    def __init__(self, command, args=None, env=None, timeout=20.0):
        self.timeout = timeout
        full_env = dict(os.environ)
        full_env.update(env or {})
        self.proc = subprocess.Popen([command, *(args or [])], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=full_env, text=True, bufsize=1)
        self.q: queue.Queue = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.q.put(json.loads(line))
            except json.JSONDecodeError:
                pass  # servers sometimes log junk to stdout

    def _write(self, msg):
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _send_notification(self, msg):
        self._write(msg)

    def _roundtrip(self, msg):
        self._write(msg)
        while True:
            try:
                resp = self.q.get(timeout=self.timeout)
            except queue.Empty:
                raise MCPError(f"timeout waiting for {msg['method']}")
            if resp.get("id") == msg["id"]:
                return resp
            # ignore server->client requests/notifications

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class HTTPClient(_Base):
    """Streamable HTTP transport (JSON or SSE-framed responses)."""

    def __init__(self, url, headers=None, timeout=20.0):
        self.url, self.timeout = url, timeout
        self.headers = {"Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "MCP-Protocol-Version": PROTOCOL_VERSION, **(headers or {})}
        self.session = None

    def _post(self, msg):
        h = dict(self.headers)
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(), headers=h, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            raise MCPError(f"HTTP {e.code} from {self.url}")
        sid = r.headers.get("Mcp-Session-Id")
        if sid:
            self.session = sid
        return r

    def _send_notification(self, msg):
        self._post(msg).read()

    def _roundtrip(self, msg):
        r = self._post(msg)
        ctype = r.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            data = []
            for raw in r:
                line = raw.decode().rstrip("\r\n")
                if line.startswith("data:"):
                    data.append(line[5:].strip())
                elif line == "" and data:
                    obj = json.loads("\n".join(data))
                    data = []
                    if obj.get("id") == msg["id"]:
                        return obj
            raise MCPError("SSE stream ended without response")
        return json.loads(r.read().decode())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass
