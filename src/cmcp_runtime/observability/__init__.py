"""Telemetry export for cMCP (AARM requirement R8)."""

from cmcp_runtime.observability.otel import (
    OTEL_AVAILABLE,
    OtelAuditExporter,
    otel_sink_from_env,
)

__all__ = ["OTEL_AVAILABLE", "OtelAuditExporter", "otel_sink_from_env"]
