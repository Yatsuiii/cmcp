"""Config, measurement and reload wiring for the sealed signing key (#462)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from cmcp_runtime.config import ConfigError, load_config
from cmcp_runtime.tee import measurement


def _config(tmp_path: Path, attestation: str) -> Path:
    path = tmp_path / "cmcp-config.yaml"
    path.write_text("attestation:\n" + attestation)
    return path


def test_sealing_is_off_by_default(tmp_path: Path) -> None:
    config = load_config(str(_config(tmp_path, "  provider: tpm\n")))
    assert config.attestation.seal_signing_key is False
    assert config.attestation.sealed_key_dir == "sealed-key"


@pytest.mark.parametrize(
    ("attestation", "message"),
    [
        ("  provider: auto\n  seal_signing_key: true\n", "provider: tpm"),
        ("  provider: sev-snp\n  seal_signing_key: true\n", "provider: tpm"),
        ("  provider: tpm\n  seal_signing_key: yes-please\n", "must be a boolean"),
        ("  provider: tpm\n  sealed_key_dir: ''\n", "non-empty"),
        ("  provider: tpm\n  sealed_key_dir: ../elsewhere\n", r"\.\."),
    ],
)
def test_invalid_sealing_settings_are_refused(
    tmp_path: Path, attestation: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(str(_config(tmp_path, attestation)))


def test_the_sealing_settings_are_measured(tmp_path: Path) -> None:
    """Turning sealing on is a configuration change like any other."""
    off = load_config(str(_config(tmp_path, "  provider: tpm\n")))
    on = load_config(str(_config(tmp_path, "  provider: tpm\n  seal_signing_key: true\n")))
    assert measurement.config_digest(off) != measurement.config_digest(on)


def test_the_digest_from_components_is_the_gateway_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(measurement, "code_digest", lambda: "c" * 64)
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.cedar").write_text("permit(principal, action, resource);")
    config = load_config(str(_config(tmp_path, "  provider: tpm\n")))
    config.policy_bundle_path = str(tmp_path / "policies")

    full = measurement.gateway_measurement(config)
    assert measurement.measurement_from_components(dict(full.components)) == full


def test_components_must_be_exactly_code_policy_and_config() -> None:
    with pytest.raises(ValueError):
        measurement.measurement_from_components({"code": "c", "policy": "p"})


def test_reload_reseals_even_when_the_re_attestation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cmcp_runtime import cli

    calls: list[str] = []

    def failing_refresh(ctx: object) -> bool:
        calls.append("refresh")
        raise RuntimeError("TEE unavailable")

    def reseal(ctx: object) -> bool:
        calls.append("reseal")
        return True

    monkeypatch.setattr("cmcp_runtime.tee.report_binding.refresh_measurement_binding", failing_refresh)
    monkeypatch.setattr("cmcp_runtime.tee.seal.reseal_after_reload", reseal)
    with pytest.raises(RuntimeError):
        cli._after_policy_reload(SimpleNamespace())  # type: ignore[arg-type]
    assert calls == ["refresh", "reseal"]


def test_reseal_after_reload_is_a_no_op_without_a_sealed_key() -> None:
    from cmcp_runtime.tee.seal import reseal_after_reload

    assert reseal_after_reload(SimpleNamespace(sealed_key=None, gateway_measurement=None)) is False
