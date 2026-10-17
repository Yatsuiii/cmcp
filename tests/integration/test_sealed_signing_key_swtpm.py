"""The sealed signing key against a real TPM 2.0 simulator (#462).

Each test starts its own swtpm, so every TPM state here is fresh unless a test
restarts or clears it on purpose. Skipped where swtpm or tpm2-pytss is missing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from swtpm_lab import Swtpm, swtpm_available

from cmcp_runtime.tee import seal
from cmcp_runtime.tee.seal import (
    GATE_SENTINEL,
    SealedKeyDigestMismatch,
    SealedKeyMissing,
    SealedKeyPublicKeyMismatch,
    SealedKeyStore,
    SealedKeyTpmChanged,
    SealedKeyUnavailable,
)

pytestmark = pytest.mark.skipif(not swtpm_available(), reason="needs swtpm and tpm2-pytss")

DIGEST_A = hashlib.sha256(b"gateway build A").digest()
DIGEST_B = hashlib.sha256(b"gateway build B").digest()
DIGEST_C = hashlib.sha256(b"gateway build C").digest()


@pytest.fixture
def tpm(tmp_path: Path) -> Iterator[Swtpm]:
    instance = Swtpm(tmp_path / "tpm-state").start()
    try:
        yield instance
    finally:
        instance.stop()


@pytest.fixture
def other_tpm(tmp_path: Path) -> Iterator[Swtpm]:
    instance = Swtpm(tmp_path / "other-tpm-state").start()
    try:
        yield instance
    finally:
        instance.stop()


@pytest.fixture
def store(tmp_path: Path) -> SealedKeyStore:
    return SealedKeyStore(tmp_path / "sealed")


def _open(tpm: Swtpm, store: SealedKeyStore, digest: bytes) -> seal.OpenedKey:
    with tpm.context() as ectx:
        return seal.open_sealed_key(ectx, store, digest)


def _gate_value(tpm: Swtpm) -> bytes:
    with tpm.context() as ectx:
        gate = ectx.tr_from_tpmpublic(seal.DEFAULT_GATE_NV_INDEX)
        return bytes(ectx.nv_read(gate, 32, 0))


def _sign_verifies(opened: seal.OpenedKey, public_key: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    signature = Ed25519PrivateKey.from_private_bytes(opened.seed).sign(b"claim")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, b"claim")
    except InvalidSignature:
        return False
    return True


# S1, S12


def test_one_key_survives_restarts_and_the_public_key_is_readable_first(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    first = _open(tpm, store, DIGEST_A)
    assert first.provisioned
    for _ in range(3):
        tpm.restart()
        assert seal.stored_public_key(store) == first.public_key
        again = _open(tpm, store, DIGEST_A)
        assert not again.provisioned
        assert again.public_key == first.public_key
        assert again.seed == first.seed
    assert _sign_verifies(again, seal.stored_public_key(store) or b"")


# S2


def test_a_changed_digest_gets_no_key_and_the_next_legitimate_start_does(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    first = _open(tpm, store, DIGEST_A)
    with pytest.raises(SealedKeyDigestMismatch):
        _open(tpm, store, DIGEST_B)
    assert _gate_value(tpm) == GATE_SENTINEL
    assert _open(tpm, store, DIGEST_A).public_key == first.public_key


def test_the_tpm_enforces_the_policy_whatever_the_store_label_says(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    """Bypass every software check: the TPM itself refuses a gate holding another digest."""
    _open(tpm, store, DIGEST_A)
    blob = store.read().blobs[-1]  # type: ignore[union-attr]
    with tpm.context() as ectx:
        gate = ectx.tr_from_tpmpublic(seal.DEFAULT_GATE_NV_INDEX)
        seal._write_gate(ectx, gate, DIGEST_B)
        relabelled = seal.SealedBlob(digest=DIGEST_B, private=blob.private, public=blob.public)
        with pytest.raises(SealedKeyDigestMismatch):
            seal._unseal(ectx, relabelled, gate)


def test_a_relabelled_blob_is_refused_before_the_gate_is_touched(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    _open(tpm, store, DIGEST_A)
    raw = json.loads(store.path.read_text())
    raw["blobs"][0]["digest"] = DIGEST_B.hex()
    store.path.write_text(json.dumps(raw))
    with pytest.raises(SealedKeyDigestMismatch, match="policy does not match"):
        _open(tpm, store, DIGEST_B)
    assert _gate_value(tpm) == GATE_SENTINEL


# S3


def test_between_starts_the_gate_is_closed_and_passive_unseal_fails(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    _open(tpm, store, DIGEST_A)
    assert _gate_value(tpm) == GATE_SENTINEL
    blob = store.read().blobs[-1]  # type: ignore[union-attr]
    with tpm.context() as ectx:
        gate = ectx.tr_from_tpmpublic(seal.DEFAULT_GATE_NV_INDEX)
        with pytest.raises(SealedKeyDigestMismatch):
            seal._unseal(ectx, blob, gate)


def test_writing_the_approved_digest_with_owner_auth_unseals(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    """The stated limit: owner authorization is enough to open the gate."""
    first = _open(tpm, store, DIGEST_A)
    blob = store.read().blobs[-1]  # type: ignore[union-attr]
    with tpm.context() as ectx:
        gate = ectx.tr_from_tpmpublic(seal.DEFAULT_GATE_NV_INDEX)
        seal._write_gate(ectx, gate, DIGEST_A)
        assert seal._unseal(ectx, blob, gate) == first.seed


# S4


def test_with_an_owner_password_a_process_without_it_cannot_start(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    from tpm2_pytss.constants import ESYS_TR

    _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx:
        ectx.hierarchy_change_auth(ESYS_TR.OWNER, b"owner-secret")
    with pytest.raises(SealedKeyUnavailable):
        _open(tpm, store, DIGEST_A)


# S5


def test_the_software_policy_equals_the_tpm_trial_policy(tpm: Swtpm, store: SealedKeyStore) -> None:
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG, TPM2_EO, TPM2_SE
    from tpm2_pytss.types import TPM2B_OPERAND, TPMT_SYM_DEF

    _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx:
        gate = ectx.tr_from_tpmpublic(seal.DEFAULT_GATE_NV_INDEX)
        _public, name = ectx.nv_read_public(gate)
        assert bytes(name) == seal.gate_nv_name()
        session = ectx.start_auth_session(
            ESYS_TR.NONE,
            ESYS_TR.NONE,
            TPM2_SE.TRIAL,
            TPMT_SYM_DEF(algorithm=TPM2_ALG.NULL),
            TPM2_ALG.SHA256,
        )
        try:
            ectx.policy_nv(gate, gate, session, TPM2B_OPERAND(DIGEST_B), TPM2_EO.EQ)
            trial = bytes(ectx.policy_get_digest(session))
        finally:
            ectx.flush_context(session)
    assert trial == seal.policy_nv_digest(DIGEST_B)


# S6


def test_reseal_upgrade_and_rollback_keep_one_key(tpm: Swtpm, store: SealedKeyStore) -> None:
    first = _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx:
        seal.reseal_held_key(ectx, store, first.seed, DIGEST_B)
    assert _open(tpm, store, DIGEST_B).public_key == first.public_key
    assert _open(tpm, store, DIGEST_A).public_key == first.public_key  # rollback

    with tpm.context() as ectx:
        assert seal.reseal_stored_key(ectx, store, DIGEST_C) == first.public_key
    assert _open(tpm, store, DIGEST_C).public_key == first.public_key
    assert [b.digest for b in store.read().blobs] == [DIGEST_B, DIGEST_C]  # type: ignore[union-attr]
    with pytest.raises(SealedKeyDigestMismatch):
        _open(tpm, store, DIGEST_A)  # dropped: only two are kept
    assert _gate_value(tpm) == GATE_SENTINEL


def test_rotation_replaces_the_key_and_drops_every_old_blob(
    tpm: Swtpm, store: SealedKeyStore
) -> None:
    first = _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx:
        seal.reseal_held_key(ectx, store, first.seed, DIGEST_B)
        rotated = seal.rotate_sealed_key(ectx, store, DIGEST_B)
    assert rotated != first.public_key
    assert [b.digest for b in store.read().blobs] == [DIGEST_B]  # type: ignore[union-attr]
    assert _open(tpm, store, DIGEST_B).public_key == rotated
    with pytest.raises(SealedKeyDigestMismatch):
        _open(tpm, store, DIGEST_A)


# S7, S8


def test_a_blob_from_another_tpm_is_refused(
    tpm: Swtpm, other_tpm: Swtpm, store: SealedKeyStore, tmp_path: Path
) -> None:
    _open(tpm, store, DIGEST_A)
    with pytest.raises(SealedKeyTpmChanged, match="no gate"):
        _open(other_tpm, store, DIGEST_A)

    # Even with a gate defined there, the blob does not load.
    _open(other_tpm, SealedKeyStore(tmp_path / "unrelated"), DIGEST_A)
    with pytest.raises(SealedKeyTpmChanged, match="does not load"):
        _open(other_tpm, store, DIGEST_A)


def test_after_tpm2_clear_the_key_is_gone(tpm: Swtpm, store: SealedKeyStore) -> None:
    from tpm2_pytss.constants import ESYS_TR

    _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx:
        ectx.clear(ESYS_TR.LOCKOUT)
    with pytest.raises(SealedKeyTpmChanged):
        _open(tpm, store, DIGEST_A)


# S9


def test_a_swapped_public_key_is_refused(tpm: Swtpm, store: SealedKeyStore) -> None:
    _open(tpm, store, DIGEST_A)
    raw = json.loads(store.path.read_text())
    raw["public_key"] = seal.ed25519_public_key(b"\x07" * 32).hex()
    store.path.write_text(json.dumps(raw))
    with pytest.raises(SealedKeyPublicKeyMismatch):
        _open(tpm, store, DIGEST_A)


# S10


def test_a_second_deployment_on_one_tpm_cannot_provision(
    tpm: Swtpm, store: SealedKeyStore, tmp_path: Path
) -> None:
    _open(tpm, store, DIGEST_A)
    with pytest.raises(SealedKeyMissing):
        _open(tpm, SealedKeyStore(tmp_path / "second"), DIGEST_A)


def test_rotation_recovers_a_lost_store(tpm: Swtpm, store: SealedKeyStore) -> None:
    _open(tpm, store, DIGEST_A)
    store.path.unlink()
    with pytest.raises(SealedKeyMissing):
        _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx:
        public_key = seal.rotate_sealed_key(ectx, store, DIGEST_A)
    assert _open(tpm, store, DIGEST_A).public_key == public_key


def test_a_gate_index_with_another_profile_is_refused(tpm: Swtpm, store: SealedKeyStore) -> None:
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG, TPMA_NV
    from tpm2_pytss.types import TPM2B_DIGEST, TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC

    with tpm.context() as ectx:
        ectx.nv_define_space(
            b"known",
            TPM2B_NV_PUBLIC(
                nvPublic=TPMS_NV_PUBLIC(
                    nvIndex=seal.DEFAULT_GATE_NV_INDEX,
                    nameAlg=TPM2_ALG.SHA256,
                    attributes=TPMA_NV.parse("authwrite|authread|no_da"),
                    authPolicy=TPM2B_DIGEST(),
                    dataSize=32,
                )
            ),
            auth_handle=ESYS_TR.OWNER,
        )
    # Someone else's index at the gate handle: never provisioned over, and rotation
    # refuses to seal against it.
    with pytest.raises(SealedKeyMissing):
        _open(tpm, store, DIGEST_A)
    with tpm.context() as ectx, pytest.raises(SealedKeyUnavailable, match="profile"):
        seal.rotate_sealed_key(ectx, store, DIGEST_A)
