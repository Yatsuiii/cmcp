"""
OpenTelemetry export of audit-chain entries (AARM requirement R8).

R8 asks that action telemetry be exported in a standard format. This module
mirrors each audit entry as an OTel span, which gives operators the usual
pipeline (OTLP collector, backend of choice) without changing how the entry is
recorded or hashed.

Three properties are deliberate.

**The audit chain stays authoritative.** Export is a read-only mirror attached
as a sink. ``AuditEntry`` gains no field, so entry hashes are unchanged and
existing chains still verify. A telemetry backend that loses data cannot alter
the evidence, and an operator who can write to the telemetry backend still
cannot forge a receipt. Telemetry is for operating the gateway; the chain and
the TRACE Claim are for proving what happened.

**No payloads leave the enclave.** Entries carry SHA-256 digests rather than
request or response bodies, and this exporter forwards only the digest fields
and the decision metadata. That holds even though the collector endpoint is
usually outside the trust boundary.

**Failures are swallowed.** A telemetry outage must not fail a tool call or
break the chain, so every export is wrapped. Errors are logged once at debug
level to avoid a log flood when a collector is down for hours.

OpenTelemetry is an optional dependency. Without it, ``OTEL_AVAILABLE`` is
False and the exporter degrades to a no-op, so ``pip install cmcp-runtime``
stays lean and a deployment opts in with ``pip install cmcp-runtime[otel]``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cmcp_runtime.audit.chain import AuditEntry

logger = logging.getLogger(__name__)

# Bound to the OTel API when it is installed and left as None otherwise, so the
# rest of the module can branch on OTEL_AVAILABLE without import guards at each
# use. Typed Any because the fallback is a different shape from the real API.
_otel_trace: Any = None
_SpanKind: Any = None
_Status: Any = None
_StatusCode: Any = None

try:  # pragma: no cover - import-time branch depends on the environment
    from opentelemetry import trace as _imported_trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _otel_trace = _imported_trace
    _SpanKind, _Status, _StatusCode = SpanKind, Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover
    OTEL_AVAILABLE = False

__all__ = ["OTEL_AVAILABLE", "OtelAuditExporter", "otel_sink_from_env"]

#: Audit entry fields that are safe to export. Everything omitted is either a
#: payload-adjacent value or internal chain bookkeeping that a telemetry
#: backend has no use for. Kept as an allowlist so a future field added to
#: AuditEntry is not exported by accident.
_EXPORTED_FIELDS = (
    "entry_id",
    "sequence_number",
    "session_id",
    "call_id",
    "entry_type",
    "tool_name",
    "server_identity",
    "policy_decision",
    "policy_rule_matched",
    "latency_us",
    "request_payload_hash",
    "response_payload_hash",
    "response_inspection_result",
    "session_sensitivity_before",
    "session_sensitivity_after",
    "workflow_id",
    "evidence_class",
    "entry_hash",
    "prev_entry_hash",
)

#: Decisions and entry types that mark the span as an error, so a dashboard can
#: alert on blocked calls without parsing attributes.
_ERROR_DECISIONS = frozenset({"deny", "advisory_deny", "fault"})


class OtelAuditExporter:
    """
    Mirrors audit entries to OpenTelemetry as spans.

    Attach with ``AuditChain(session_id, sinks=[exporter])`` or by appending
    ``exporter`` to an existing chain's sinks. The instance is callable so it
    satisfies the sink protocol directly.
    """

    def __init__(self, tracer_name: str = "cmcp.audit") -> None:
        self._tracer: Any = _otel_trace.get_tracer(tracer_name) if OTEL_AVAILABLE else None
        self._warned = False

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    def __call__(self, entry: AuditEntry) -> None:
        self.export(entry)

    def export(self, entry: AuditEntry) -> None:
        """Emit one span for ``entry``. Never raises."""
        tracer = self._tracer
        if tracer is None:
            return
        try:
            self._export(tracer, entry)
        except Exception:  # pragma: no cover - defensive
            if not self._warned:
                logger.debug("OTel audit export failed; further failures are silent", exc_info=True)
                self._warned = True

    def _export(self, tracer: Any, entry: AuditEntry) -> None:
        name = f"cmcp.{entry.entry_type}"
        with tracer.start_as_current_span(name, kind=_SpanKind.INTERNAL) as span:
            for field_name in _EXPORTED_FIELDS:
                value = getattr(entry, field_name, None)
                if value is not None:
                    span.set_attribute(f"cmcp.{field_name}", value)
            decision = entry.policy_decision
            if decision in _ERROR_DECISIONS:
                span.set_status(_Status(_StatusCode.ERROR, f"policy_decision={decision}"))


def otel_sink_from_env() -> Callable[[Any], None] | None:
    """
    Build an exporter when the environment asks for one.

    Returns None when OpenTelemetry is absent or when ``CMCP_OTEL_ENABLED`` is
    unset or falsey, so telemetry is opt-in rather than something a deployment
    discovers it is doing. Recognised truthy values are ``1``, ``true``,
    ``yes``, and ``on``, case-insensitively.
    """
    if os.environ.get("CMCP_OTEL_ENABLED", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    if not OTEL_AVAILABLE:
        logger.warning(
            "CMCP_OTEL_ENABLED is set but opentelemetry is not installed; "
            "telemetry export is disabled. Install with: pip install cmcp-runtime[otel]"
        )
        return None
    exporter = OtelAuditExporter()
    logger.info("OTel audit export enabled")
    return exporter
