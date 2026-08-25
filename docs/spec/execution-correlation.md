# Session-Independent Execution Correlation

Status: proposal for [#565](https://github.com/agentrust-io/cmcp/issues/565), not
adopted. This document does not change the cMCP protocol.

[mcp-2026-roadmap-impact.md](mcp-2026-roadmap-impact.md) lists this as P0 and
first in the issue sequence: "Replace dependence on MCP initialization/session
lifetime with a cMCP execution identifier carried across requests. A TRACE claim
must remain joinable without implying an MCP protocol session."

## What binds evidence today

Worth stating precisely, because the dependence is not where the phrase
"MCP session" suggests.

`initialize` does not create anything. `MCPServer._handle_mcp` answers it at
`server.py:449` by negotiating a protocol version and returning capabilities. No
session is minted, no `Mcp-Session-Id` is issued, and nothing about the handshake
is carried into evidence.

The binding is entirely gateway-side:

| Identifier | Origin | Scope |
|---|---|---|
| `session_id` | `SessionManager.create_session`, `session/manager.py:118`, a `uuid4` | One gateway session |
| `call_id` | `server.py:569`, a fresh `uuid4` per `tools/call` | One tool call |
| `workflow_id` | caller-supplied via `params._cmcp.workflow_id`, `server.py:571-575` | Caller-defined |

`session_id` is what everything joins on. Audit entries carry it, the TRACE Claim
is issued per session on close and stored keyed by it (`manager.py:182`), and the
read paths are `/sessions/{session_id}/trace-claim` and
`/audit/export?session_id=` (`server.py:341`, `server.py:705`). At session
creation the audit chain root is bound into TEE `report_data` where the platform
supports it, and `manager.py` warns explicitly when it could not be.

So a cMCP session is a gateway lifetime with a hardware-anchored chain root and
one claim at the end. It is not an MCP protocol session and never was.

## The gap

The problem is not that sessions disappear from the protocol. It is that
`session_id` is the only cross-request correlation key, and it carries two jobs
that stop being compatible once work arrives as independent requests:

1. It scopes the evidence bundle, one chain root, one claim.
2. It is the only thing relating two calls that belong to the same intent.

With independent requests there are two options and both fail:

**One long-lived session.** Correlation works, but the TRACE Claim grows without
bound and evidence is not available until close. A claim that never closes is not
evidence anyone can act on.

**A session per request.** Claims stay small and prompt, but every call is its
own chain root and nothing relates two calls. Multi-request work becomes
unjoinable, which is exactly what the roadmap requires stay joinable.

`workflow_id` is closest to prior art here, but it is caller-supplied and
unverified, so it cannot carry correlation on its own.

There is a concrete failure already filed. In
[#571](https://github.com/agentrust-io/cmcp/issues/571) a post-upstream fault can
leave a call whose outcome nobody can establish. A caller retrying that intent
gets a fresh `call_id` (`server.py:569` mints one per call, with no
caller-supplied path), so the two attempts are uncorrelated. Under one session
per request they land in different chain roots entirely. An execution identifier
is what would let a verifier see one intent with two attempts rather than two
unrelated calls.

## Proposal

A cMCP `execution_id` that is:

- **caller-asserted, gateway-validated.** The caller supplies it so retries of
  the same intent can carry the same value. The gateway validates shape and
  binds it into the audit entry, so it is evidence rather than a hint.
- **independent of session lifetime.** It appears in audit entries alongside
  `session_id` rather than replacing it. Sessions keep scoping evidence bundles;
  `execution_id` correlates across them.
- **offline-joinable.** A verifier holding two audit bundles from two sessions
  can join them on `execution_id` without contacting the gateway, which is the
  roadmap's stated invariant.

Carried in `params._cmcp` next to the existing `workflow_id`, so it rides a
transport-neutral envelope the gateway already parses rather than a header. The
roadmap lists HTTP-native transport as P1 with no issue filed yet, so anything
depending on header semantics would be making a bet on work that has not been
scoped.

## Against #565's acceptance evidence

**Correlation across retries and multi-request work.** The reason for a
caller-asserted value. A gateway-minted identifier cannot correlate a retry,
since the gateway cannot tell a retry from a new intent, which is the situation
today.

**Explicit collision, replay and missing-context failures.** Caller-asserted
means adversary-asserted, so these are the load-bearing cases.
- *Collision:* two callers assert the same value. Scoping under the authenticated
  agent identity contains this, but it needs deciding whether collision inside
  one identity is refused or recorded.
- *Replay:* an `execution_id` reused after a terminal outcome. Related to #571:
  reuse after `outcome_unknown` is the case that matters and is the one worth
  refusing.
- *Missing context:* absent `execution_id` must stay legal, and the entry records
  its absence rather than synthesising a value, otherwise the field cannot be
  trusted where it is present.

**Protocol-version vectors.** Not answered here. It belongs with the SDK
conformance matrix the roadmap lists as P1, and I would rather not invent a
version-negotiation story ahead of that.

**TRACE records remain offline-joinable.** The join key is in the audit entry, so
two bundles join without the gateway. What is not settled is whether the TRACE
Claim itself should surface the set of `execution_id` values it covers. That
makes joining cheaper and leaks a little about the caller's structure to whoever
holds the claim.

## Open decisions

Flagged rather than assumed:

1. Does `execution_id` go in `AuditEntry` as a field, or in the existing
   `detail` dict? A field is greppable and typed; `detail` avoids a schema change
   on an append-only hashed structure.
2. Collision inside a single agent identity: refuse, or record and let the
   verifier see it?
3. Should the TRACE Claim enumerate covered `execution_id` values?
4. Is a replay window needed, or is "refuse reuse after a terminal outcome"
   enough?
5. Does this interact with `workflow_id` such that one of them should be derived
   from the other, or do they stay independent?

Opened as a draft so the shape can be argued before anything is built. Happy to
implement whichever way these land, or to close this if the direction is wrong.
