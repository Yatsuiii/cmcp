"""Tests for scripts/mock_upstream.py's JSON-RPC request gate (#518).

Spins up the real MockMCPHandler in-process against a random local port and
issues raw HTTP requests, so these exercise the actual handler class rather
than a reimplementation of it.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from mock_upstream import MockMCPHandler  # noqa: E402


@pytest.fixture(scope="module")
def upstream():
    server = HTTPServer(("127.0.0.1", 0), MockMCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()


def _post(port: int, body: bytes, *, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    conn.request("POST", "/mcp", body=body, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw)


VALID_REQUEST = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hi"}},
    }
).encode()


# ---------------------------------------------------------------------------
# Existing valid-request behavior must be unchanged
# ---------------------------------------------------------------------------


def test_valid_request_returns_200_with_expected_shape(upstream):
    status, body = _post(upstream, VALID_REQUEST)
    assert status == 200
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == "req-1"
    text = body["result"]["content"][0]["text"]
    assert text == 'mock upstream: echo called with {"message": "hi"}'


def test_valid_request_without_arguments_defaults_to_empty_dict(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200
    assert body["result"]["content"][0]["text"] == "mock upstream: echo called with {}"


# ---------------------------------------------------------------------------
# -32700 Parse error: malformed JSON
# ---------------------------------------------------------------------------


def test_malformed_json_returns_parse_error(upstream):
    status, body = _post(upstream, b"{not valid json")
    assert status == 400
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32700
    assert body["id"] is None


def test_empty_body_returns_parse_error(upstream):
    status, body = _post(upstream, b"")
    assert status == 400
    assert body["error"]["code"] == -32700


# ---------------------------------------------------------------------------
# -32600 Invalid Request: structurally wrong
# ---------------------------------------------------------------------------


def test_non_object_json_returns_invalid_request(upstream):
    status, body = _post(upstream, b"[1, 2, 3]")
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] is None


def test_missing_method_returns_invalid_request(upstream):
    req = json.dumps({"jsonrpc": "2.0", "id": 3, "params": {"name": "echo"}}).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 3


def test_non_string_method_returns_invalid_request(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 4, "method": 7, "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 4


def test_non_object_params_returns_invalid_request(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": "nope"}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 5


# ---------------------------------------------------------------------------
# -32602 Invalid params
# ---------------------------------------------------------------------------


def test_missing_tool_name_returns_invalid_params(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 6


def test_non_string_tool_name_returns_invalid_params(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": 42}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 7


def test_non_object_arguments_returns_invalid_params(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": "nope"},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 8


# ---------------------------------------------------------------------------
# Bounded request size
# ---------------------------------------------------------------------------


def test_oversized_request_rejected_before_parsing(upstream):
    huge_args = "x" * 2_000_000
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": huge_args}},
        }
    ).encode()
    status, resp = _post(upstream, body)
    assert status == 413
    assert resp["error"]["code"] == -32600
    assert resp["id"] is None


def test_far_oversized_request_beyond_the_drain_ceiling_still_gets_a_clean_response(upstream):
    # Above DRAIN_CEILING_BYTES the server stops draining and closes instead,
    # so this is allowed to surface as a connection-level failure on the
    # client side rather than a parsed response -- covered separately so the
    # two size regimes (bounded-drain vs. give-up-and-close) are both tested.
    huge_args = "x" * 15_000_000
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": huge_args}},
        }
    ).encode()
    with socket.create_connection(("127.0.0.1", upstream), timeout=5) as sock:
        header = (
            f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode()
        sock.sendall(header)
        # Acceptable above the drain ceiling: the header alone already
        # triggers rejection, so a broken pipe while writing the body is not
        # a defect.
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            sock.sendall(body)
        raw_response = sock.recv(65536)
    assert b"413" in raw_response.split(b"\r\n", 1)[0]


def test_request_at_the_limit_is_accepted(upstream):
    # Build a request whose total serialized size sits just under the cap.
    filler_len = 1_000_000 - 200
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "x" * filler_len}},
        }
    ).encode()
    assert len(body) < 1_000_000
    status, resp = _post(upstream, body)
    assert status == 200
    assert resp["id"] == 10


# ---------------------------------------------------------------------------
# Security visibility: rejections are logged (#518)
# ---------------------------------------------------------------------------


def test_malformed_json_is_logged(upstream, caplog):
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, b"{not valid json")
    assert any("event=parse_error" in r.message for r in caplog.records)


def test_invalid_request_is_logged(upstream, caplog):
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, b"[1, 2, 3]")
    assert any("event=invalid_request" in r.message for r in caplog.records)


def test_invalid_params_is_logged(upstream, caplog):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {}}
    ).encode()
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, req)
    assert any("event=invalid_params" in r.message for r in caplog.records)


def test_oversized_request_is_logged(upstream, caplog):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "x" * 2_000_000}},
        }
    ).encode()
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, body)
    assert any("event=oversized_request" in r.message for r in caplog.records)


def test_valid_request_is_not_logged(upstream, caplog):
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, VALID_REQUEST)
    assert caplog.records == []


# ---------------------------------------------------------------------------
# Strict jsonrpc/id validation (#518)
# ---------------------------------------------------------------------------


def test_wrong_jsonrpc_version_returns_invalid_request(upstream):
    req = json.dumps(
        {"jsonrpc": "1.0", "id": 20, "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 20


def test_missing_jsonrpc_returns_invalid_request(upstream):
    req = json.dumps({"id": 21, "method": "tools/call", "params": {"name": "echo"}}).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600


def test_object_id_returns_invalid_request_with_null_id(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": {"nope": True}, "method": "tools/call", "params": {}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] is None


def test_bool_id_returns_invalid_request_with_null_id(upstream):
    req = json.dumps({"jsonrpc": "2.0", "id": True, "method": "tools/call", "params": {}}).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] is None


def test_null_id_is_valid(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": None, "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200
    assert body["id"] is None


def test_absent_id_is_valid(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200
    assert body["id"] is None


# ---------------------------------------------------------------------------
# Argument depth/key-count caps (#518)
# ---------------------------------------------------------------------------


def _nested(depth: int) -> dict:
    value: Any = "leaf"
    for _ in range(depth):
        value = {"child": value}
    return value


def test_arguments_within_depth_cap_are_accepted(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": _nested(3)},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200


def test_arguments_past_depth_cap_returns_invalid_params(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": _nested(25)},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 31


def test_arguments_past_key_count_cap_returns_invalid_params(upstream):
    huge_flat = {f"k{i}": i for i in range(300)}
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": huge_flat},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 32


def test_arguments_within_key_count_cap_are_accepted(upstream):
    small_flat = {f"k{i}": i for i in range(10)}
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": small_flat},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200


# ---------------------------------------------------------------------------
# Non-standard JSON values (NaN, Infinity, -Infinity) (#518)
# ---------------------------------------------------------------------------


def test_nan_in_arguments_is_rejected(upstream):
    body = (
        b'{"jsonrpc": "2.0", "id": 40, "method": "tools/call", '
        b'"params": {"name": "echo", "arguments": {"x": NaN}}}'
    )
    status, resp = _post(upstream, body)
    assert status == 400
    assert resp["error"]["code"] == -32700


def test_infinity_in_arguments_is_rejected(upstream):
    body = (
        b'{"jsonrpc": "2.0", "id": 41, "method": "tools/call", '
        b'"params": {"name": "echo", "arguments": {"x": Infinity}}}'
    )
    status, resp = _post(upstream, body)
    assert status == 400
    assert resp["error"]["code"] == -32700


def test_negative_infinity_in_arguments_is_rejected(upstream):
    body = (
        b'{"jsonrpc": "2.0", "id": 42, "method": "tools/call", '
        b'"params": {"name": "echo", "arguments": {"x": -Infinity}}}'
    )
    status, resp = _post(upstream, body)
    assert status == 400
    assert resp["error"]["code"] == -32700
