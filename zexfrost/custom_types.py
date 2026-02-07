from typing import Annotated, ClassVar, Literal
from uuid import UUID

import httpx
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
from pydantic import BaseModel, BeforeValidator, HttpUrl, PlainSerializer


def bytes_to_hex(value: bytes) -> HexStr:
    return value.hex()


def hex_to_bytes(value: bytes | HexStr) -> bytes:
    match value:
        case bytes():
            return value
    return bytes.fromhex(value)


type NodeID = HexStr
type DKGID = UUID
type TweakBy = Annotated[
    bytes,
    BeforeValidator(hex_to_bytes, json_schema_input_type=bytes | HexStr),
    PlainSerializer(bytes_to_hex, return_type=str, when_used="json"),
]
type CurveName = Literal["secp256k1_tr", "secp256k1", "ed25519", "secp256k1_evm"]

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
    selection_weight: float = 10
    MIN_WEIGHT: ClassVar[float] = 0.1
    ALPHA: ClassVar[float] = 0.7

    def _update_random_weight(self, status_code: int, latency_seconds: float):
        new_weight = self.selection_weight
        if 500 <= status_code < 600:
            new_weight *= 0.1
        elif 400 <= status_code < 500:
            return
        else:
            performance_score = 1.0 / (latency_seconds + 0.01)
            # Exponential Moving Average (EMA)
            # NewWeight = (OldWeight * (1 - ALPHA)) + (CurrentPerf * ALPHA)
            new_weight = (self.selection_weight * (1 - self.ALPHA)) + (performance_score * self.ALPHA)
        self.selection_weight = max(self.MIN_WEIGHT, new_weight)

    async def send_request(self, client: httpx.AsyncClient, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            res = await client.request(method, f"{self.url}{path}", **kwargs)
            self._update_random_weight(res.status_code, res.elapsed.total_seconds())
            return res
        except httpx.TransportError:
            self._update_random_weight(500, 0)
            raise

    @property
    def url(self) -> HttpUrl:
        return HttpUrl(f"{self.host}:{self.port}")


class DKGRound1Request(BaseModel):
    max_signers: int
    min_signers: int
    id: DKGID
    party_ids: list[NodeID]
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
type SigningsData = dict[SignatureID, SigningData]
type SigningResponse = dict[SignatureID, SharePackage]


class SigningRequest(BaseModel):
    metadata: dict | None = None
    pubkey_package: PublicKeyPackage
    curve: CurveName
    signings_data: SigningsData


class SigningData(BaseModel):
    data: dict
    commitments: dict[NodeID, Commitment]
    tweak_by: TweakBy | None = None


class UserSigningData(BaseModel):
    tweak_by: TweakBy | None = None
    data: dict
    message: bytes

    def to_signing_data(self, commitments: dict[NodeID, Commitment]) -> SigningData:
        return SigningData(
            data=self.data,
            commitments=commitments,
            tweak_by=self.tweak_by,
        )
