"""Demo Streamable-HTTP MCP server (stdlib only). Usage: python http_server.py PORT [--sse] [--token T]"""
import json, sys, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(__file__))

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
SSE = "--sse" in sys.argv
TOKEN = sys.argv[sys.argv.index("--token") + 1] if "--token" in sys.argv else None
DESC = os.environ.get("DEMO_DESC", "Fetch any URL and return its body.")
TOOLS = [{"name": "fetch_url", "description": DESC, "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if TOKEN and self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401); self.end_headers(); return
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if "id" not in msg:
            self.send_response(202); self.end_headers(); return
        m = msg["method"]
        if m == "initialize":
            res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "http-demo", "version": "0.0.1"}}
        elif m == "tools/list":
            res = {"tools": TOOLS}
        else:
            res = None
        body = {"jsonrpc": "2.0", "id": msg["id"]}
        body.update({"result": res} if res is not None else {"error": {"code": -32601, "message": "nope"}})
        data = json.dumps(body)
        self.send_response(200)
        self.send_header("Mcp-Session-Id", "demo-session")
        if SSE:
            self.send_header("Content-Type", "text/event-stream"); self.end_headers()
            self.wfile.write(f"event: message\ndata: {data}\n\n".encode())
        else:
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(data.encode())


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
