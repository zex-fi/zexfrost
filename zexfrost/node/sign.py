from zexfrost.custom_types import (
    BaseCryptoModule,
    Commitment,
    HexStr,
    PublicKeyPackage,
    SharePackage,
    SigningPackage,
    WithCustomTweak,
)

from .repository import KeyRepository, NonceRepository


def commitment(
    curve: BaseCryptoModule,
    pubkey_package: PublicKeyPackage,
    key_repo: KeyRepository,
    nonce_repo: NonceRepository,
    tweak_by: HexStr | None = None,
) -> Commitment:
    key_package = key_repo.get(pubkey_package.verifying_key)
    assert key_package is not None, "Key not found"
    match curve:
        case WithCustomTweak():
            key_package = curve.key_package_tweak(key_package, tweak_by)
    result = curve.round1_commit(key_package.signing_share)
    nonce_repo.set(f"{result.commitments.binding}-{result.commitments.hiding}", result.nonces)
    return result.commitments


def sign(
    curve: BaseCryptoModule,
    pubkey_package: PublicKeyPackage,
    key_repo: KeyRepository,
    signing_package: SigningPackage,
    nonce_repo: NonceRepository,
    commitment: Commitment,
    tweak_by: HexStr | None = None,
) -> SharePackage:
    key_package = key_repo.get(pubkey_package.verifying_key)
    assert key_package is not None, "Key not found"
    nonce = nonce_repo.get(f"{commitment.binding}-{commitment.hiding}")
    assert nonce is not None, "Nonce not found"
    nonce_repo.delete(f"{commitment.binding}-{commitment.hiding}")
    match curve:
        case WithCustomTweak():
            key_package = curve.key_package_tweak(key_package, tweak_by)
            result = curve.round2_sign_with_tweak(signing_package, nonce, key_package, None)
        case BaseCryptoModule():
            result = curve.round2_sign(signing_package, nonce, key_package)
    return result
