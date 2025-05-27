from typing import Literal
from uuid import UUID

from frost_lib.types import (
    Commitment,
    DKGPart1Package,
    DKGPart1Result,
    DKGPart2Package,
    DKGPart2Result,
    DKGPart3Result,
    HexStr,
    Nonce,
    PrivateKeyPackage,
    PublicKeyPackage,
    SharePackage,
    SigningPackage,
)
from frost_lib.wrapper import BaseCryptoModule, WithCustomTweak
from pydantic import BaseModel, HttpUrl

type NodeID = HexStr
type DKGID = UUID
type TweakBy = HexStr


__all__ = [
    "Node",
    "DKGRound1NodeResponse",
    "DKGRound2EncryptedPackage",
    "AnnulmentData",
    "DKGPart1Result",
    "DKGPart2Result",
    "DKGPart3Result",
    "DKGPart2Package",
    "BaseCryptoModule",
    "PrivateKeyPackage",
    "WithCustomTweak",
    "Nonce",
    "Commitment",
    "SigningPackage",
    "SharePackage",
]


class Node(BaseModel):
    id: NodeID
    host: str
    port: int
    public_key: HexStr
    curve_name: Literal["secp256k1_tr"] = "secp256k1_tr"

    # @computed_field
    @property
    def url(self) -> HttpUrl:
        return HttpUrl(f"{self.host}:{self.port}")  # type: ignore


class DKGRound1Request(BaseModel):
    max_signers: int
    min_signers: int
    id: DKGID
    party_id: list[NodeID]
    curve: Literal["secp256k1_tr"]


class DKGRound1NodeResponse(BaseModel):
    package: DKGPart1Package
    temp_public_key: HexStr
    signature: HexStr


class DKGRound2Request(BaseModel):
    id: DKGID
    broadcast_data: dict[NodeID, DKGRound1NodeResponse]


class DKGRound2EncryptedPackage(BaseModel):
    encrypted_package: dict[NodeID, str]


class DKGRound3Request(BaseModel):
    id: DKGID
    encrypted_package: DKGRound2EncryptedPackage


class DKGRound3NodeResponse(BaseModel):
    pubkey_package: PublicKeyPackage
    signature: HexStr


class AnnulmentData(BaseModel): ...


class CommitmentRequest(BaseModel):
    pubkey_package: PublicKeyPackage
    curve: Literal["secp256k1_tr"]
    tweak_by: HexStr | None = None


type DataID = str
type SigningMessage = dict[DataID, bytes]
type SigningData = dict[DataID, dict]
type CommitmentsWithTweak = dict[TweakBy, dict[DataID, dict[NodeID, Commitment]]]


class SignRequest(BaseModel):
    pubkey_package: PublicKeyPackage
    curve: Literal["secp256k1_tr"]
    data: SigningData
    commitments: dict[NodeID, Commitment]


class SignTweakRequest(BaseModel):
    pubkey_package: PublicKeyPackage
    curve: Literal["secp256k1_tr"]
    data: dict[TweakBy, SigningData]
    commitments: CommitmentsWithTweak
