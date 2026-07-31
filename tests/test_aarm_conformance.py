"""
AARM v1.0 conformance tests for the decision vocabulary (R4) and telemetry
export (R8).

These cover the mapping and plumbing that R4 and R8 add. They do not attempt to
be the AARM Conformance Agent's test suite, which runs against a deployed
gateway and includes timeout behaviour across all five decision types.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.errors import PolicyDeny
from cmcp_runtime.observability.otel import OtelAuditExporter, otel_sink_from_env
from cmcp_runtime.policy.decisions import (
    AARM_DECISION_ANNOTATION,
    Decision,
    audit_value,
    claim_value,
    decision_for_deny,
)

SCHEMA_PATH = pathlib.Path(__file__).parent.parent / "schemas" / "audit-entry.schema.json"


class TestR4DecisionVocabulary:
    """R4: the policy engine must produce five decision types."""

    def test_all_five_aarm_decisions_exist(self) -> None:
        assert {d.value for d in Decision} == {
            "allow",
            "deny",
            "modify",
            "step_up",
            "defer",
        }

    def test_bare_deny_is_deny(self) -> None:
        assert decision_for_deny(None) is Decision.DENY
        assert decision_for_deny({}) is Decision.DENY
        assert decision_for_deny({"reason": "not permitted"}) is Decision.DENY

    @pytest.mark.parametrize("key", ["approver", "escalate", "escalation", "hitl"])
    def test_escalation_annotation_infers_step_up(self, key: str) -> None:
        assert decision_for_deny({key: "risk-desk@example.org"}) is Decision.STEP_UP

    def test_explicit_annotation_wins_over_inference(self) -> None:
        # An approver key would otherwise infer STEP_UP.
        advice = {"approver": "risk-desk", AARM_DECISION_ANNOTATION: "defer"}
        assert decision_for_deny(advice) is Decision.DEFER

    def test_explicit_annotation_cannot_flip_a_deny_to_allow(self) -> None:
        """A policy that denied must not be able to declare itself permitted."""
        for claimed in ("allow", "modify"):
            advice = {AARM_DECISION_ANNOTATION: claimed}
            assert decision_for_deny(advice) is Decision.DENY

    def test_malformed_annotation_falls_back_to_inference(self) -> None:
        """A typo must not become a failure to decide."""
        assert decision_for_deny({AARM_DECISION_ANNOTATION: "stepup"}) is Decision.DENY
        assert (
            decision_for_deny({AARM_DECISION_ANNOTATION: "nonsense", "approver": "x"})
            is Decision.STEP_UP
        )

    def test_annotation_value_is_case_and_space_insensitive(self) -> None:
        assert decision_for_deny({AARM_DECISION_ANNOTATION: "  STEP_UP "}) is Decision.STEP_UP

    def test_modify_records_as_redact(self) -> None:
        """MODIFY reuses the existing audit value for the mechanism cMCP applies."""
        assert audit_value(Decision.MODIFY) == "redact"

    def test_other_decisions_record_under_their_own_name(self) -> None:
        for decision in (Decision.ALLOW, Decision.DENY, Decision.STEP_UP, Decision.DEFER):
            assert audit_value(decision) == decision.value

    def test_policy_deny_classifies_itself(self) -> None:
        plain = PolicyDeny("blocked", advice={"reason": "no"})
        assert plain.aarm_decision is Decision.DENY

        escalating = PolicyDeny("blocked", advice={"approver": "risk-desk"})
        assert escalating.aarm_decision is Decision.STEP_UP

    def test_policy_deny_with_no_advice_classifies_as_deny(self) -> None:
        assert PolicyDeny("blocked").aarm_decision is Decision.DENY


class TestClaimBoundaryNarrowing:
    """
    A TRACE Claim v1.0 cannot carry step_up or defer. The audit chain keeps the
    specific decision and the claim reports the coarser one, so a new decision
    value can never produce a claim that fails schema validation.
    """

    def test_new_decisions_narrow_to_deny(self) -> None:
        assert claim_value("step_up") == "deny"
        assert claim_value("defer") == "deny"

    def test_pinned_vocabulary_passes_through_unchanged(self) -> None:
        for value in ("allow", "deny", "redact", "advisory_deny", "fault", "n/a"):
            assert claim_value(value) == value

    def test_none_becomes_not_applicable(self) -> None:
        assert claim_value(None) == "n/a"

    def test_unrecognised_value_fails_closed_to_deny(self) -> None:
        """A future decision value must not leak into a claim it would invalidate."""
        assert claim_value("some_future_decision") == "deny"

    def test_every_audit_value_narrows_into_the_claim_vocabulary(self) -> None:
        pinned = {"allow", "deny", "redact", "advisory_deny", "fault", "n/a"}
        for decision in Decision:
            assert claim_value(audit_value(decision)) in pinned

    def test_narrowing_preserves_the_blocked_or_allowed_distinction(self) -> None:
        """Narrowing may lose detail; it must not turn a block into an allow."""
        for decision in (Decision.DENY, Decision.STEP_UP, Decision.DEFER):
            assert claim_value(audit_value(decision)) == "deny"
        assert claim_value(audit_value(Decision.ALLOW)) == "allow"


class TestAuditSchemaAcceptsNewDecisions:
    """The recorded vocabulary and the published schema must not drift apart."""

    def test_schema_enum_covers_every_audit_value(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        allowed = set(schema["properties"]["policy_decision"]["enum"])
        for decision in Decision:
            assert audit_value(decision) in allowed, (
                f"{decision.value} maps to {audit_value(decision)!r}, "
                "which audit-entry.schema.json does not permit"
            )

    def test_widening_kept_the_legacy_values(self) -> None:
        """Entries written before the widening must still validate."""
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        allowed = set(schema["properties"]["policy_decision"]["enum"])
        assert {"allow", "deny", "redact", "advisory_deny", "fault", "n/a"} <= allowed


class TestR8TelemetryExport:
    """R8: export action telemetry in a standard format."""

    def test_sinks_receive_every_entry(self) -> None:
        seen: list[str] = []
        chain = AuditChain("session-1", sinks=[lambda e: seen.append(e.entry_type)])
        # session_start is appended by the constructor.
        assert seen == ["session_start"]
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert seen == ["session_start", "tool_call"]

    def test_a_failing_sink_cannot_break_the_chain(self) -> None:
        """Telemetry must never fail a tool call or corrupt the audit chain."""

        def exploding(entry: object) -> None:
            raise RuntimeError("collector down")

        chain = AuditChain("session-2", sinks=[exploding])
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert chain.verify_chain()

    def test_a_failing_sink_does_not_starve_later_sinks(self) -> None:
        seen: list[str] = []

        def exploding(entry: object) -> None:
            raise RuntimeError("collector down")

        chain = AuditChain("session-3", sinks=[exploding, lambda e: seen.append(e.entry_id)])
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert len(seen) == 2  # session_start plus the tool_call

    def test_add_sink_attaches_after_construction(self) -> None:
        chain = AuditChain("session-4")
        seen: list[str] = []
        chain.add_sink(lambda e: seen.append(e.entry_type))
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert seen == ["tool_call"]

    def test_exporter_is_inert_without_opentelemetry_installed(self) -> None:
        """The exporter must be safe to attach whether or not OTel is present."""
        exporter = OtelAuditExporter()
        chain = AuditChain("session-5", sinks=[exporter])
        chain.append("tool_call", tool_name="t", policy_decision="allow")
        assert chain.verify_chain()

    def test_env_sink_is_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CMCP_OTEL_ENABLED", raising=False)
        assert otel_sink_from_env() is None

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
    def test_env_sink_rejects_non_truthy_values(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("CMCP_OTEL_ENABLED", value)
        assert otel_sink_from_env() is None

    def test_exported_fields_exclude_payloads(self) -> None:
        """Digests may leave the enclave; bodies may not."""
        from cmcp_runtime.observability.otel import _EXPORTED_FIELDS

        for field_name in _EXPORTED_FIELDS:
            assert "payload" not in field_name or field_name.endswith("_hash")
        assert "detail" not in _EXPORTED_FIELDS
        assert "external_execution_evidence" not in _EXPORTED_FIELDS
