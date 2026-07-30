"""
AARM v1.0 decision vocabulary (requirement R4).

AARM R4 requires a policy engine to produce five decision types: ALLOW, DENY,
MODIFY, STEP_UP, DEFER. cMCP's enforcement primitives predate that vocabulary
and are narrower, so the mapping lives here rather than as string literals
scattered across the evaluator, the proxy, and the audit chain.

Crosswalk. The AGT column is the reference AARM Extended listing that AARM
verified on 2026-06-14, whose enum (``agent_os.base_agent.PolicyDecision``) is
ALLOW, DENY, AUDIT, ESCALATE, DEFER and therefore also not a name-for-name
match to AARM. That listing was accepted with the mapping below, so the
same reading applies here.

===========  ==========================================================  ==========
AARM         cMCP mechanism                                              AGT
===========  ==========================================================  ==========
ALLOW        Cedar permit, call forwarded upstream                       ALLOW
DENY         Cedar forbid, call blocked                                  DENY
MODIFY       Response redaction or surplus stripping in the inspection   transform
             pipeline; recorded in the audit chain as ``redact``
STEP_UP      Cedar forbid whose annotations name a human authority, so   ESCALATE
             the call is blocked and the caller receives the escalation
             payload needed to obtain authorization
DEFER        Cedar forbid annotated ``@aarm_decision("defer")``. See     DEFER
             the DEFER note below and LIMITATIONS.md
===========  ==========================================================  ==========

DEFER note. AARM's DEFER means asynchronous evaluation with a callback. cMCP
classifies and records DEFER but does not hold the call open pending an
out-of-band decision, because the gateway has no callback registry and holding
MCP requests open across a policy round trip is a transport design decision
rather than a policy one. A deployment that annotates a policy with
``@aarm_decision("defer")`` gets a blocked call recorded as ``defer`` with the
advice payload attached. Treat DEFER as classified but not asynchronously
enforced until that design lands.

Policy authors can set any decision explicitly with ``@aarm_decision("...")``,
which takes precedence over inference. That gives an assessor an unambiguous
hook and keeps the classification auditable from the hash-pinned bundle rather
than from gateway heuristics.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AARM_DECISION_ANNOTATION",
    "ESCALATION_ADVICE_KEYS",
    "Decision",
    "audit_value",
    "decision_for_deny",
]


class Decision(StrEnum):
    """The five AARM R4 decision types."""

    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    STEP_UP = "step_up"
    DEFER = "defer"


#: Annotation key that lets a policy state its AARM decision outright.
AARM_DECISION_ANNOTATION = "aarm_decision"

#: Advice keys that imply a human authority can authorize the blocked call.
#: ``approver`` is the key already used by the example bundles; the rest are
#: accepted so a deployment does not have to rename its existing annotations.
ESCALATION_ADVICE_KEYS = frozenset({"approver", "escalate", "escalation", "hitl"})


def decision_for_deny(advice: dict[str, str] | None) -> Decision:
    """
    Classify a Cedar deny as DENY, STEP_UP, or DEFER.

    ``advice`` is the annotation set of the forbid policies that produced the
    deny, recovered from the hash-pinned bundle. An explicit
    ``@aarm_decision("...")`` wins. Otherwise the presence of an escalation key
    means a human can authorize the call, which is STEP_UP. Everything else is
    a plain DENY.

    Unknown or malformed ``@aarm_decision`` values fall through to inference
    rather than raising, so a typo in a policy annotation cannot turn a deny
    into a failure to decide.
    """
    if not advice:
        return Decision.DENY

    explicit = advice.get(AARM_DECISION_ANNOTATION, "").strip().lower()
    if explicit:
        try:
            declared = Decision(explicit)
        except ValueError:
            declared = None
        # A policy that denied cannot declare itself ALLOW or MODIFY; ignore
        # those rather than let an annotation override the authorization result.
        if declared in (Decision.DENY, Decision.STEP_UP, Decision.DEFER):
            return declared

    if ESCALATION_ADVICE_KEYS & advice.keys():
        return Decision.STEP_UP

    return Decision.DENY


def audit_value(decision: Decision) -> str:
    """
    Map a Decision onto the audit chain's ``policy_decision`` vocabulary.

    MODIFY is recorded as ``redact`` because that is the mechanism cMCP
    actually applies and the value the audit-entry schema already carries.
    Adding a second value meaning the same thing would make the audit
    vocabulary ambiguous for no gain.
    """
    if decision is Decision.MODIFY:
        return "redact"
    return decision.value
