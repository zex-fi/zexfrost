from zexfrost.custom_types import (
    BaseCryptoCurve,
    BaseCurveWithTweakedSign,
    Commitment,
    NodeID,
    Nonce,
    PrivateKeyPackage,
    PublicKeyPackage,
    SharePackage,
    TweakBy,
)

from .repository import KeyRepository, NonceRepository


def commitment(
    node_id: NodeID,
    curve: BaseCryptoCurve,
    pubkey_package: PublicKeyPackage,
    key_repo: KeyRepository,
    nonce_repo: NonceRepository,
    tweak_by: TweakBy | None = None,
) -> Commitment:
    key_package = PrivateKeyPackage.model_validate(key_repo.get(node_id + pubkey_package.verifying_key))
    assert key_package is not None, "Key not found"
    match curve:
        case BaseCurveWithTweakedSign():
            key_package = curve.key_package_tweak(key_package, tweak_by)
        case BaseCryptoCurve():
            if tweak_by is not None:
                key_package = curve.key_package_tweak(key_package, tweak_by)
    result = curve.round1_commit(key_package.signing_share)
    nonce_repo.set(f"{result.commitments.binding}-{result.commitments.hiding}", result.nonces.model_dump(mode="python"))
    return result.commitments


def sign(
    curve: BaseCryptoCurve,
    node_id: NodeID,
    pubkey_package: PublicKeyPackage,
    commitments: dict[NodeID, Commitment],
    message: bytes,
    key_repo: KeyRepository,
    nonce_repo: NonceRepository,
    tweak_by: TweakBy | None = None,
) -> SharePackage:
    commitment = commitments[node_id]
    key_package = key_repo.get(node_id + pubkey_package.verifying_key)
    assert key_package is not None, "Key not found"
    nonce = nonce_repo.pop(f"{commitment.binding}-{commitment.hiding}")
    assert nonce is not None, "Nonce not found"
    key_package = PrivateKeyPackage.model_validate(key_package)
    nonce = Nonce.model_validate(nonce)
    signing_package = curve.signing_package_new(commitments, message)
    match curve:
        case BaseCurveWithTweakedSign():
            key_package = curve.key_package_tweak(key_package, tweak_by)
            result = curve.round2_sign_with_tweak(signing_package, nonce, key_package, None)
        case BaseCryptoCurve():
            if tweak_by is not None:
                key_package = curve.key_package_tweak(key_package, tweak_by)
            result = curve.round2_sign(signing_package, nonce, key_package)
    return result
