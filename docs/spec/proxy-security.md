# Phase 2 Proxy Security: Parser Fuzzing

---
Status: Draft v0.1
Last updated: 2026-06-04
Stability: Unstable , expect breaking changes before v1.0
---

This document defines the fuzzing definition of done (DoD) for the Phase 2 proxy parser. No Phase 2 release ships without satisfying every item below.

## Fuzz Targets

Four fuzz targets are required:

1. **JSON-RPC parser.** Input: arbitrary bytes. Output: valid or invalid parse result. Must not crash or hang under any input.

2. **MCP message schema validator.** Input: valid JSON-RPC with arbitrary MCP message content. Output: valid or invalid schema result. Must not crash.

3. **Tool call argument deserializer.** Input: arbitrary JSON as tool arguments. Output: deserialized result or parse error. Must not crash and must not produce unbounded memory allocation.

4. **Tool response processor.** Input: arbitrary JSON as tool response. Output: processed response or error. Must not crash.

## Fuzzing Definition of Done

All items must be satisfied before Phase 2 ships. Items are non-negotiable; a partial pass does not qualify.

- [ ] 1 billion fuzz iterations on each target with no crashes
- [ ] 0 timeout-inducing inputs (max 100ms per fuzz case)
- [ ] Resource limits enforced in code (see constants below)
- [ ] All inputs resulting in a parse error return a structured error response (no null returns, no uncaught exceptions)
- [ ] Regression corpus of 50+ MCP edge cases committed to `test/corpus/`

## Resource Limits

These constants are hard-coded in the proxy implementation. They are not configurable at runtime or via operator-supplied configuration. Making them configurable would allow an operator to raise limits and defeat the protection.

```python
MAX_REQUEST_BYTES = 10 * 1024 * 1024  # 10MB
MAX_JSON_NESTING_DEPTH = 64
MAX_PARSE_TIME_MS = 100
MAX_STRING_LENGTH = MAX_REQUEST_BYTES // 2   # per string field, see invariant below
```

### MAX_STRING_LENGTH is a ratio, not an absolute

`MAX_STRING_LENGTH` must stay meaningfully below `MAX_REQUEST_BYTES`, and it is written above as a derivation rather than a literal so that it cannot drift out of that relationship.

The invariant matters because violating it produces a check that reads like a control and can never fire. A single string at or above the whole-body cap makes a request the body-size check already rejects, so the per-string check is unreachable on every input that survives long enough to reach it. That is worse than an absent check: an absent control is visible as missing, while a present one passes review, passes an audit read of the source, and counts toward this Definition of Done.

An implementation MUST derive the per-string cap from whatever whole-body cap it enforces. It MUST NOT restate the value as a literal, since a later change to the body cap then silently recreates the unreachable condition at a new ratio.

### Open: MAX_REQUEST_BYTES disagrees with the implementation

This document states 10MB. Both implementations enforce 1MB: `scripts/mock_upstream.py` and `MCPServer.__init__` in `src/cmcp_runtime/mcp/server.py`.

At the implemented 1MB, the per-string cap this document originally stated as a literal 1MB was exactly the whole-body cap, which is how the unreachable case above was found. Deriving the cap removes the dead-code hazard at either value, but the disagreement itself is still open: nothing records whether 1MB was a deliberate tightening or drift from this spec.

Tracked on #573. Implementers should follow the enforced body cap and the ratio above until that is settled, rather than raising a body cap to match this document.

## Malformed Input Handling

Every parse path has an explicit error handler. No input reaches undefined behavior. The error handler contract:

1. Log the input hash (SHA-256 of the raw bytes), not the input content. This prevents log-injection and limits PII exposure.
2. Return a structured error response to the caller.
3. Do not pass partial parse results downstream. A partial result is treated as a failed parse.

This contract applies to all four fuzz targets. Any code path that returns a null, panics, or passes a partial result downstream is a bug, not an acceptable error mode.

