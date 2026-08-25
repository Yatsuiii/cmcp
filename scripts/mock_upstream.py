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

# #518: the byte cap above bounds total size, not shape. A payload well
# under 1MB can still be expensive to walk -- deep nesting pushes toward
# Python's recursion limit, and a flat object with thousands of short keys
# costs little in bytes but is not free to iterate. These are judgment
# calls, not values derived from an observed cMCP tool call: no real
# `arguments` payload we ship examples for goes past 3-4 levels or a
# handful of keys, so both caps sit an order of magnitude above that,
# leaving room for a legitimate tool with a genuinely nested schema.
_MAX_ARG_DEPTH = 20
_MAX_ARG_KEYS = 256

# #562: docs/spec/proxy-security.md's Fuzzing Definition of Done specs
# MAX_STRING_LENGTH at 1MB per string field, separate from the depth/key
# caps above. A single oversized string can sit inside an otherwise
# shallow, low-key-count payload and slip past both of those unbounded,
# up to whatever the whole-body byte cap happens to be.
#
# Not set to the spec's literal 1MB: that would equal MAX_REQUEST_BYTES
# itself, and a 1MB string plus any JSON structure around it already
# exceeds the whole-body cap, so the check could never fire before
# DOS-001's size rejection already had. Set to half of MAX_REQUEST_BYTES
# instead, so a single string cannot consume the whole request budget and
# the cap is actually reachable. Worth revisiting to the spec's literal
# value if MAX_REQUEST_BYTES itself is ever raised toward the spec's
# stated 10MB (see #562).
#
# Checked as UTF-8 byte length, not character count, since a codepoint
# count understates the actual memory and processing cost of multi-byte
# text.
_MAX_ARG_STRING_LENGTH = MAX_REQUEST_BYTES // 2

logger = logging.getLogger("mock_upstream")


def _reject_nan_and_infinity(text: str) -> float:
    raise ValueError(f"non-standard JSON value not allowed: {text}")


def _valid_rpc_id(value: Any) -> bool:
    # JSON-RPC 2.0 id must be a string, number, or null -- not a bool, even
    # though bool is an int subclass in Python.
    return value is None or (isinstance(value, (str, int, float)) and not isinstance(value, bool))


def _over_string_cap(text: str) -> bool:
    return len(text.encode("utf-8")) > _MAX_ARG_STRING_LENGTH


def _object_shape_violation(value: dict[str, Any], depth: int) -> str | None:
    if len(value) > _MAX_ARG_KEYS:
        return f"object has more than {_MAX_ARG_KEYS} keys"
    for key, child in value.items():
        # Keys carry the same cost as values and are not covered by the key
        # *count* cap above, so a single huge key would otherwise slip
        # through every check here.
        if isinstance(key, str) and _over_string_cap(key):
            return f"object key over the length cap of {_MAX_ARG_STRING_LENGTH} bytes"
        violation = _arg_shape_violation(child, depth=depth + 1)
        if violation is not None:
            return violation
    return None


def _arg_shape_violation(value: Any, *, depth: int = 0) -> str | None:
    """Return a message describing the first depth/key-count/string-length
    violation found under `value`, or None if it fits within `_MAX_ARG_DEPTH` /
    `_MAX_ARG_KEYS` / `_MAX_ARG_STRING_LENGTH`."""
    if depth > _MAX_ARG_DEPTH:
        return f"arguments nested past the depth cap of {_MAX_ARG_DEPTH}"
    if isinstance(value, dict):
        return _object_shape_violation(value, depth)
    if isinstance(value, list):
        for child in value:
            violation = _arg_shape_violation(child, depth=depth + 1)
            if violation is not None:
                return violation
        return None
    if isinstance(value, str) and _over_string_cap(value):
        return f"string value over the length cap of {_MAX_ARG_STRING_LENGTH} bytes"
    return None


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
            msg = json.loads(raw, parse_constant=_reject_nan_and_infinity)
        except (ValueError, TypeError):
            self._reject("parse_error", -32700, "Parse error", status=400)
            return

        if not isinstance(msg, dict):
            self._reject("invalid_request", -32600, "Invalid Request", status=400)
            return

        rpc_id = msg.get("id")
        if "id" in msg and not _valid_rpc_id(rpc_id):
            self._reject("invalid_request", -32600, "Invalid Request", status=400)
            return

        if msg.get("jsonrpc") != "2.0":
            self._reject("invalid_request", -32600, "Invalid Request", status=400, rpc_id=rpc_id)
            return

        method = msg.get("method", "")
        if not isinstance(method, str) or not method:
            self._reject("invalid_request", -32600, "Invalid Request", status=400, rpc_id=rpc_id)
            return

        params = msg.get("params", {})
        if not isinstance(params, dict):
            self._reject("invalid_request", -32600, "Invalid Request", status=400, rpc_id=rpc_id)
            return

        self._handle_tool_call(rpc_id, params)

    def _handle_tool_call(self, rpc_id: Any, params: dict[str, Any]) -> None:
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

        violation = _arg_shape_violation(arguments)
        if violation is not None:
            self._reject(
                "invalid_params", -32602, f"Invalid params: {violation}",
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
