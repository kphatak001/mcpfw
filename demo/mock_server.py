"""Mock MCP server over HTTP — simulates a tool server with read_db, format, send_email."""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

# Simulated customer database
CUSTOMER_DB = {
    "cust_001": {"name": "Alice Johnson", "email": "alice@acme.com", "ssn": "123-45-6789", "balance": 15420.00},
    "cust_002": {"name": "Bob Smith", "email": "bob@widgets.io", "ssn": "987-65-4321", "balance": 8930.50},
    "cust_003": {"name": "Carol Davis", "email": "carol@startup.dev", "ssn": "456-78-9012", "balance": 42100.00},
}

TOOLS = [
    {"name": "read_customer", "description": "Read customer account data", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
    {"name": "search_kb", "description": "Search knowledge base", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "format_response", "description": "Format data for output", "inputSchema": {"type": "object", "properties": {"template": {"type": "string"}, "data": {"type": "string"}}}},
    {"name": "send_email", "description": "Send email to any address", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "send_reply", "description": "Send reply to the customer in the current ticket", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}},
]


class MCPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        msg = json.loads(body)

        method = msg.get("method")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        if method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = self._handle_tool_call(params)
        else:
            result = {}

        response = {"jsonrpc": "2.0", "id": msg_id, "result": result}
        resp_bytes = json.dumps(response).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def _handle_tool_call(self, params):
        tool = params.get("name", "")
        args = params.get("arguments", {})

        if tool == "read_customer":
            cid = args.get("id", "")
            data = CUSTOMER_DB.get(cid, {"error": "not found"})
            return {"content": [{"type": "text", "text": json.dumps(data)}]}

        elif tool == "search_kb":
            return {"content": [{"type": "text", "text": "KB result: Password reset requires email verification."}]}

        elif tool == "format_response":
            return {"content": [{"type": "text", "text": f"Formatted: {args.get('data', '')}"}]}

        elif tool == "send_email":
            to = args.get("to", "")
            body = args.get("body", "")
            print(f"  📧 EMAIL SENT to {to}: {body[:80]}...")
            return {"content": [{"type": "text", "text": f"Email sent to {to}"}]}

        elif tool == "send_reply":
            print(f"  💬 REPLY: {args.get('message', '')[:80]}...")
            return {"content": [{"type": "text", "text": "Reply sent to customer"}]}

        return {"content": [{"type": "text", "text": f"Unknown tool: {tool}"}]}

    def log_message(self, format, *args):
        pass  # Suppress default logging


if __name__ == "__main__":
    port = 9000
    server = HTTPServer(("127.0.0.1", port), MCPHandler)
    print(f"🖥️  Mock MCP server running on http://127.0.0.1:{port}")
    server.serve_forever()
