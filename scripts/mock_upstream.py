#!/usr/bin/env python3
"""Minimal mock MCP upstream server for the cMCP quickstart and docker-compose demo.

Listens for JSON-RPC `tools/call` requests over HTTP POST and returns a canned
result. It exists so the quickstart's "allowed call" step has a real upstream to
forward to; it is not part of the runtime and must not be used in production.

Usage:
    python scripts/mock_upstream.py [--host HOST] [--port PORT]

Defaults to 0.0.0.0:9001, which matches the catalog entries shipped in
examples/ and docs/quickstart.md.
"""
from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# Matches MCPServer._max_request_bytes's default in cmcp_runtime/mcp/server.py,
# so the mock rejects at the same boundary the real gateway does.
MAX_REQUEST_BYTES = 1_000_000

# How much of an oversized body we are willing to read and discard so the
# client can finish writing it and read our 413 cleanly, instead of racing
# an abrupt close (a client mid-write into a closed socket gets a
# nondeterministic broken pipe, not the JSON-RPC error object this gate
# promises). Bounded well above MAX_REQUEST_BYTES but still bounded, so an
# attacker cannot turn this into the unbounded read the size check exists
# to prevent -- past this ceiling we give up on a clean response and close.
DRAIN_CEILING_BYTES = 10 * MAX_REQUEST_BYTES

logger = logging.getLogger("mock_upstream")


class MockMCPHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # silence per-request access logging
        pass

    def _send_json(self, payload: dict[str, Any], *, status: int) -> None:
        response = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def _reject(
        self, event: str, code: int, message: str, *, status: int, rpc_id: Any = None
    ) -> None:
        # Security visibility (#518): every rejection is logged, separately
        # from the per-request access log this handler otherwise silences,
        # so a malformed or oversized request leaves a trace even though
        # ordinary traffic does not.
        logger.warning(
            "rejected request: event=%s code=%s status=%s client=%s",
            event, code, status, self.client_address[0],
        )
        self._send_json(
            {"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": rpc_id},
            status=status,
        )

    def do_POST(self) -> None:
        # Bounded request size: reject before reading the body, same boundary
        # and error shape as MCPServer._handle_mcp's DOS-001 check.
        content_length_header = self.headers.get("Content-Length")
        try:
            length = int(content_length_header) if content_length_header else 0
        except ValueError:
            self._reject("invalid_content_length", -32600, "Invalid Content-Length", status=400)
            return
        if length > MAX_REQUEST_BYTES:
            self.rfile.read(min(length, DRAIN_CEILING_BYTES))
            if length > DRAIN_CEILING_BYTES:
                # Past the drain ceiling: do not read further, and do not
                # reuse a connection whose unread tail could be misparsed as
                # the start of the next request.
                self.close_connection = True
            self._reject("oversized_request", -32600, "Request body too large", status=413)
            return

        raw = self.rfile.read(length)

        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            self._reject("parse_error", -32700, "Parse error", status=400)
            return

        if not isinstance(msg, dict):
            self._reject("invalid_request", -32600, "Invalid Request", status=400)
            return

        rpc_id = msg.get("id")
        method = msg.get("method", "")
        if not isinstance(method, str) or not method:
            self._reject("invalid_request", -32600, "Invalid Request", status=400, rpc_id=rpc_id)
            return

        params = msg.get("params", {})
        if not isinstance(params, dict):
            self._reject("invalid_request", -32600, "Invalid Request", status=400, rpc_id=rpc_id)
            return

        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            self._reject(
                "invalid_params", -32602, "Invalid params: 'name' must be a non-empty string",
                status=400, rpc_id=rpc_id,
            )
            return

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            self._reject(
                "invalid_params", -32602, "Invalid params: 'arguments' must be an object",
                status=400, rpc_id=rpc_id,
            )
            return

        text = f"mock upstream: {tool_name} called with {json.dumps(arguments, sort_keys=True)}"
        self._send_json(
            {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {"content": [{"type": "text", "text": text}]},
            },
            status=200,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock MCP upstream for the cMCP demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    server = HTTPServer((args.host, args.port), MockMCPHandler)
    print(f"mock upstream listening on {args.host}:{args.port}/mcp", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
