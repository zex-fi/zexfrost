from typing import Literal
from uuid import UUID

from frost_lib.abstracts import BaseCryptoCurve, BaseCurveWithTweakedPubkey, BaseCurveWithTweakedSign
from frost_lib.custom_types import (
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
from pydantic import BaseModel, HttpUrl

type NodeID = HexStr
type DKGID = UUID
type TweakBy = bytes
type CurveName = Literal["secp256k1_tr", "secp256k1", "ed25519"]

__all__ = [
    "Node",
    "DKGRound1NodeResponse",
    "DKGRound2EncryptedPackage",
    "AnnulmentData",
    "DKGPart1Result",
    "DKGPart2Result",
    "DKGPart3Result",
    "DKGPart2Package",
    "PrivateKeyPackage",
    "Nonce",
    "Commitment",
    "SigningPackage",
    "SharePackage",
    "BaseCryptoCurve",
    "BaseCurveWithTweakedPubkey",
    "BaseCurveWithTweakedSign",
]


class Node(BaseModel):
    id: NodeID
    host: str
    port: int
    public_key: HexStr
    curve_name: Literal["secp256k1"] = "secp256k1"

    # @computed_field
    @property
    def url(self) -> HttpUrl:
        return HttpUrl(f"{self.host}:{self.port}")  # type: ignore


class DKGRound1Request(BaseModel):
    max_signers: int
    min_signers: int
    id: DKGID
    party_id: list[NodeID]
    curve: CurveName


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
    curve: CurveName
    tweak_by: TweakBy | None = None


type SignatureID = str
type SigningMessage = dict[SignatureID, bytes]
type SigningRequest = dict[SignatureID, SigningData]
type SigningResponse = dict[SignatureID, SharePackage]


class SigningData(BaseModel):
    pubkey_package: PublicKeyPackage
    curve: CurveName
    data: dict
    commitments: dict[NodeID, Commitment]
    tweak_by: TweakBy | None = None


class UserSigningData(BaseModel):
    tweak_by: TweakBy | None = None
    data: dict
    message: bytes

    def to_signing_data(
        self, pubkey_package: PublicKeyPackage, curve: CurveName, commitments: dict[NodeID, Commitment]
    ) -> SigningData:
        return SigningData(
            pubkey_package=pubkey_package,
            curve=curve,
            data=self.data,
            commitments=commitments,
            tweak_by=self.tweak_by,
        )
