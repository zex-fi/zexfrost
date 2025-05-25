from zexfrost.custom_types import Nonce, PrivateKeyPackage
from zexfrost.repository import RepositoryProtocol

from .custom_types import DKGRepositoryValue

type DKGRepository = RepositoryProtocol[DKGRepositoryValue]
type KeyRepository = RepositoryProtocol[PrivateKeyPackage]
type NonceRepository = RepositoryProtocol[Nonce]

_dkg_repository: DKGRepository | None = None
_nonce_repository: NonceRepository | None = None
_key_repository: KeyRepository | None = None


def set_nonce_repository(nonce: NonceRepository) -> None:
    global _nonce_repository
    _nonce_repository = nonce


def get_nonce_repository() -> NonceRepository:
    assert _nonce_repository is not None, "Nonce repository not set"
    return _nonce_repository


def set_key_repository(key: KeyRepository) -> None:
    global _key_repository
    _key_repository = key


def get_key_repository() -> KeyRepository:
    assert _key_repository is not None, "Key repository not set"
    return _key_repository


def set_dkg_repository(dkg: DKGRepository) -> None:
    global _dkg_repository
    _dkg_repository = dkg


def get_dkg_repository() -> DKGRepository:
    assert _dkg_repository is not None, "DKG repository not set"
    return _dkg_repository
