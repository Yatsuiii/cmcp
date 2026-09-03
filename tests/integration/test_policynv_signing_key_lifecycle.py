"""Live TPM lifecycle proof for a policy-gated signing object (#462).

The test proves the ordering mechanism with a TPM-resident P-256 key: its public
area is available before the gateway measurement, while every signature remains
gated by PolicyNV.  It is deliberately not a cMCP runtime implementation.  The
current TRACE profile is Ed25519-only, and the TPM 2.0 revision 1.59 hardware used
for validation does not expose EdDSA.  Shipping this construction therefore first
requires an explicit TRACE signing-algorithm decision.

The swtpm test is self-contained.  The hardware variant is deliberately opt-in
because it temporarily defines an owner-authorized NV index; see
``docs/testing/hardware-validation.md`` for the collision and cleanup contract.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_REQUIRED_TOOLS = (
    "swtpm",
    "swtpm_ioctl",
    "tpm2_create",
    "tpm2_createprimary",
    "tpm2_flushcontext",
    "tpm2_load",
    "tpm2_nvdefine",
    "tpm2_nvextend",
    "tpm2_nvread",
    "tpm2_nvreadpublic",
    "tpm2_nvundefine",
    "tpm2_policynv",
    "tpm2_readpublic",
    "tpm2_sign",
    "tpm2_startauthsession",
    "tpm2_startup",
)
_SOFTWARE_TOOLS_AVAILABLE = all(shutil.which(tool) for tool in _REQUIRED_TOOLS)
_HARDWARE_TCTI = os.environ.get("CMCP_TPM_POLICY_TCTI")
_HARDWARE_NV_INDEX = os.environ.get("CMCP_TPM_POLICY_NV_INDEX")
_MISSING_HANDLE_MARKERS = ("0x0000018b", "0x18b", "handle is not correct")
_PRODUCTION_MEASUREMENT_INDEX = 0x01500432
_SOFTWARE_TEST_INDEX = 0x01504362


@dataclass(frozen=True)
class LifecycleEvidence:
    """Values that independently check the ordering and usable-key result."""

    fingerprint: bytes
    pre_measurement_value: bytes
    authorized_value: bytes
    post_mutation_value: bytes
    signature: bytes
    public_key_pem: bytes


class TpmTools:
    """Run one isolated TPM lifecycle without leaking CLI sequencing to callers."""

    def __init__(self, *, tcti: str, workdir: Path) -> None:
        self.workdir = workdir
        self.environment = os.environ.copy()
        self.environment["TPM2TOOLS_TCTI"] = tcti

    @property
    def owner_auth(self) -> list[str]:
        if "CMCP_TPM_OWNER_AUTH" in self.environment:
            return ["-P", "env:CMCP_TPM_OWNER_AUTH"]
        return []

    def run(
        self,
        *arguments: str,
        check: bool = True,
        autoflush_objects: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = self.environment.copy()
        if autoflush_objects:
            environment["TPM2TOOLS_AUTOFLUSH"] = "yes"
        completed = subprocess.run(
            arguments,
            cwd=self.workdir,
            env=environment,
            capture_output=True,
            check=False,
        )
        if check and completed.returncode != 0:
            command = " ".join(arguments)
            output = (completed.stdout + completed.stderr).decode(errors="replace")
            raise AssertionError(f"{command} failed with {completed.returncode}:\n{output}")
        return completed


def _output(completed: subprocess.CompletedProcess[bytes]) -> str:
    return (completed.stdout + completed.stderr).decode(errors="replace").lower()


@contextmanager
def _swtpm(workdir: Path) -> Iterator[TpmTools]:
    workdir.mkdir()
    state = workdir / "state"
    state.mkdir()
    command_socket = workdir / "tpm.sock"
    control_socket = workdir / "tpm.sock.ctrl"
    process = subprocess.Popen(
        (
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={state}",
            "--ctrl",
            f"type=unixio,path={control_socket}",
            "--server",
            f"type=unixio,path={command_socket}",
            "--flags",
            "not-need-init",
        ),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not command_socket.exists():
            if process.poll() is not None:
                stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
                raise AssertionError(f"swtpm exited before creating its socket: {stderr}")
            if time.monotonic() >= deadline:
                raise AssertionError("swtpm did not create its command socket within 5 seconds")
            time.sleep(0.02)

        runner = TpmTools(tcti=f"swtpm:path={command_socket}", workdir=workdir)
        runner.run("tpm2_startup", "-c")
        yield runner
    finally:
        subprocess.run(
            ("swtpm_ioctl", "--unix", str(control_socket), "-s"),
            capture_output=True,
            check=False,
        )
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)


@contextmanager
def _temporary_nv_index(runner: TpmTools, index: int) -> Iterator[None]:
    handle = f"{index:#010x}"
    existing = runner.run("tpm2_nvreadpublic", handle, check=False)
    if existing.returncode == 0:
        raise AssertionError(f"refusing to overwrite existing NV index {handle}")
    if not any(marker in _output(existing) for marker in _MISSING_HANDLE_MARKERS):
        raise AssertionError(
            f"could not prove NV index {handle} is unused; refusing to define it:\n{_output(existing)}"
        )

    runner.run(
        "tpm2_nvdefine",
        handle,
        "-C",
        "o",
        *runner.owner_auth,
        "-g",
        "sha256",
        "-s",
        "32",
        "-a",
        "ownerread|ownerwrite|authread|no_da|nt=extend",
    )
    try:
        yield
    finally:
        runner.run("tpm2_nvundefine", handle, "-C", "o", *runner.owner_auth)


def _write_fixture_material(workdir: Path) -> tuple[bytes, bytes]:
    gateway_digest = hashlib.sha256(b"cMCP #462 gateway measurement").digest()
    seed_event = hashlib.sha256(b"cMCP #462 measurement-index seed").digest()
    mutation = hashlib.sha256(b"cMCP #462 mismatched next boot").digest()
    message = b"PolicyNV-authorized cMCP TRACE claim"

    (workdir / "gateway-digest.bin").write_bytes(gateway_digest)
    (workdir / "seed-event.bin").write_bytes(seed_event)
    (workdir / "mutation.bin").write_bytes(mutation)
    (workdir / "message.bin").write_bytes(message)
    return gateway_digest, seed_event


def _p256_jwk_thumbprint(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Return the RFC 7638 thumbprint a P-256 TRACE profile would commit."""
    numbers = public_key.public_numbers()

    def encode_coordinate(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()

    canonical = json.dumps(
        {
            "crv": "P-256",
            "kty": "EC",
            "x": encode_coordinate(numbers.x),
            "y": encode_coordinate(numbers.y),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).digest()


def _read_nv(runner: TpmTools, handle: str, output: str) -> bytes:
    runner.run(
        "tpm2_nvread",
        handle,
        "-C",
        "o",
        *runner.owner_auth,
        "-s",
        "32",
        "-o",
        output,
    )
    return (runner.workdir / output).read_bytes()


def _policy_session(
    runner: TpmTools,
    *,
    handle: str,
    operand: str,
    session: str,
    policy_output: str | None = None,
    trial: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    start = ["tpm2_startauthsession"]
    if not trial:
        start.append("--policy-session")
    runner.run(*start, "-S", session)
    command = [
        "tpm2_policynv",
        "-S",
        session,
        "-C",
        "o",
        *runner.owner_auth,
        "-i",
        operand,
    ]
    if policy_output is not None:
        command.extend(("-L", policy_output))
    command.extend((handle, "eq"))
    return runner.run(*command, check=False)


def _flush_session(runner: TpmTools, session: str) -> None:
    runner.run("tpm2_flushcontext", session, check=False)


def _assert_signing_denied(
    runner: TpmTools, *, handle: str, operand: str, session: str, output: str
) -> None:
    comparison = _policy_session(
        runner,
        handle=handle,
        operand=operand,
        session=session,
    )
    try:
        assert comparison.returncode != 0, "PolicyNV unexpectedly accepted the wrong NV state"
        signing = runner.run(
            "tpm2_sign",
            "-c",
            "signing-key.ctx",
            "-p",
            f"session:{session}",
            "-g",
            "sha256",
            "-f",
            "plain",
            "-o",
            output,
            "message.bin",
            check=False,
        )
        assert signing.returncode != 0, "the TPM signed under an unsatisfied PolicyNV"
        assert not (runner.workdir / output).exists()
    finally:
        _flush_session(runner, session)
        runner.run("tpm2_flushcontext", "-t")


def _sign(runner: TpmTools, *, handle: str) -> bytes:
    session = "matching-policy.ctx"
    comparison = _policy_session(
        runner,
        handle=handle,
        operand="expected-post.bin",
        session=session,
    )
    try:
        if comparison.returncode != 0:
            raise AssertionError(f"PolicyNV rejected the expected NV state:\n{_output(comparison)}")
        runner.run(
            "tpm2_sign",
            "-c",
            "signing-key.ctx",
            "-p",
            f"session:{session}",
            "-g",
            "sha256",
            "-f",
            "plain",
            "-o",
            "signature.der",
            "message.bin",
        )
        return (runner.workdir / "signature.der").read_bytes()
    finally:
        _flush_session(runner, session)
        runner.run("tpm2_flushcontext", "-t")


def exercise_policynv_signing_key_lifecycle(runner: TpmTools, *, nv_index: int) -> LifecycleEvidence:
    """Exercise deploy, pre-measurement load, authorized use, and changed-state denial."""
    if not 0x01000000 <= nv_index <= 0x01FFFFFF:
        raise AssertionError("the lifecycle proof requires an NV-index handle")
    if nv_index == _PRODUCTION_MEASUREMENT_INDEX:
        raise AssertionError("the lifecycle proof must never use cMCP's production NV index")

    gateway_digest, seed_event = _write_fixture_material(runner.workdir)
    handle = f"{nv_index:#010x}"

    with _temporary_nv_index(runner, nv_index):
        runner.run(
            "tpm2_createprimary",
            "-C",
            "o",
            "-G",
            "ecc",
            "-g",
            "sha256",
            "-c",
            "primary.ctx",
            autoflush_objects=True,
        )
        runner.run(
            "tpm2_nvextend",
            handle,
            "-C",
            "o",
            *runner.owner_auth,
            "-i",
            "seed-event.bin",
        )
        pre_measurement = _read_nv(runner, handle, "pre-measurement.bin")
        assert pre_measurement == hashlib.sha256(bytes(32) + seed_event).digest()

        authorized_value = hashlib.sha256(pre_measurement + gateway_digest).digest()
        (runner.workdir / "expected-post.bin").write_bytes(authorized_value)

        trial = _policy_session(
            runner,
            handle=handle,
            operand="expected-post.bin",
            session="trial-policy.ctx",
            policy_output="policy.digest",
            trial=True,
        )
        try:
            if trial.returncode != 0:
                raise AssertionError(
                    f"could not derive the trial PolicyNV digest:\n{_output(trial)}"
                )
        finally:
            _flush_session(runner, "trial-policy.ctx")

        runner.run(
            "tpm2_create",
            "-C",
            "primary.ctx",
            "-G",
            "ecc256:ecdsa-sha256",
            "-g",
            "sha256",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|sign",
            "-L",
            "policy.digest",
            "-u",
            "signing-key.pub",
            "-r",
            "signing-key.priv",
            autoflush_objects=True,
        )
        loaded = runner.run(
            "tpm2_load",
            "-C",
            "primary.ctx",
            "-u",
            "signing-key.pub",
            "-r",
            "signing-key.priv",
            "-c",
            "signing-key.ctx",
            autoflush_objects=True,
        )
        assert b"name:" in loaded.stdout.lower()
        runner.run(
            "tpm2_readpublic",
            "-c",
            "signing-key.ctx",
            "-f",
            "pem",
            "-o",
            "signing-key.pem",
            autoflush_objects=True,
        )
        public_key_pem = (runner.workdir / "signing-key.pem").read_bytes()
        public_key = serialization.load_pem_public_key(public_key_pem)
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        assert isinstance(public_key.curve, ec.SECP256R1)
        fingerprint = _p256_jwk_thumbprint(public_key)

        _assert_signing_denied(
            runner,
            handle=handle,
            operand="expected-post.bin",
            session="pre-measurement-policy.ctx",
            output="pre-measurement-signature.der",
        )

        runner.run(
            "tpm2_nvextend",
            handle,
            "-C",
            "o",
            *runner.owner_auth,
            "-i",
            "gateway-digest.bin",
        )
        assert _read_nv(runner, handle, "post-measurement.bin") == authorized_value

        signature = _sign(runner, handle=handle)
        public_key.verify(
            signature,
            (runner.workdir / "message.bin").read_bytes(),
            ec.ECDSA(hashes.SHA256()),
        )

        runner.run(
            "tpm2_nvextend",
            handle,
            "-C",
            "o",
            *runner.owner_auth,
            "-i",
            "mutation.bin",
        )
        post_mutation = _read_nv(runner, handle, "post-mutation.bin")
        assert post_mutation != authorized_value
        _assert_signing_denied(
            runner,
            handle=handle,
            operand="expected-post.bin",
            session="post-mutation-policy.ctx",
            output="post-mutation-signature.der",
        )

    return LifecycleEvidence(
        fingerprint=fingerprint,
        pre_measurement_value=pre_measurement,
        authorized_value=authorized_value,
        post_mutation_value=post_mutation,
        signature=signature,
        public_key_pem=public_key_pem,
    )


@pytest.mark.skipif(
    not _SOFTWARE_TOOLS_AVAILABLE,
    reason="swtpm and tpm2-tools are required for the live PolicyNV lifecycle proof",
)
def test_swtpm_policynv_gates_the_preloaded_signing_key_lifecycle(tmp_path: Path) -> None:
    with _swtpm(tmp_path / "swtpm") as runner:
        evidence = exercise_policynv_signing_key_lifecycle(runner, nv_index=_SOFTWARE_TEST_INDEX)

    assert len(evidence.fingerprint) == 32
    assert b"BEGIN PUBLIC KEY" in evidence.public_key_pem
    assert 64 <= len(evidence.signature) <= 80
    assert evidence.pre_measurement_value != evidence.authorized_value
    assert evidence.post_mutation_value != evidence.authorized_value


@pytest.mark.skipif(
    not (_HARDWARE_TCTI and _HARDWARE_NV_INDEX),
    reason=(
        "set CMCP_TPM_POLICY_TCTI and CMCP_TPM_POLICY_NV_INDEX to run the "
        "destructive-but-cleaned-up real-TPM lifecycle proof"
    ),
)
def test_real_tpm_policynv_gates_the_preloaded_signing_key_lifecycle(tmp_path: Path) -> None:
    assert _HARDWARE_TCTI is not None
    assert _HARDWARE_NV_INDEX is not None
    nv_index = int(_HARDWARE_NV_INDEX, 0)
    runner = TpmTools(tcti=_HARDWARE_TCTI, workdir=tmp_path)

    evidence = exercise_policynv_signing_key_lifecycle(runner, nv_index=nv_index)

    assert len(evidence.fingerprint) == 32
    assert b"BEGIN PUBLIC KEY" in evidence.public_key_pem
    assert 64 <= len(evidence.signature) <= 80
    assert evidence.pre_measurement_value != evidence.authorized_value
    assert evidence.post_mutation_value != evidence.authorized_value
