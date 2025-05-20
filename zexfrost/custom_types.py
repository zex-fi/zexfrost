from typing import Literal
from uuid import UUID

from frost_lib.types import DKGPart1Package, DKGPart1Result, DKGPart2Package, DKGPart2Result, DKGPart3Result, HexStr
from frost_lib.wrapper import BaseCryptoModule
from pydantic import BaseModel, HttpUrl, computed_field

type NodeID = HexStr
type DKGId = UUID


__all__ = [
    "Node",
    "DKGRound1NodeResponse",
    "DKGRound2NodeResponse",
    "AnnulmentData",
    "DKGPart1Result",
    "DKGPart2Result",
    "DKGPart3Result",
    "DKGPart2Package",
    "BaseCryptoModule",
]


class Node(BaseModel):
    id: NodeID
    host: HttpUrl
    port: int
    public_key: HexStr
    curve_name: Literal["secp256k1_tr"] = "secp256k1_tr"

    @computed_field
    @property
    def url(self) -> HttpUrl:
        return HttpUrl(f"{self.host}:{self.port}")


class DKGRound1NodeResponse(BaseModel):
    package: DKGPart1Package
    temp_public_key: HexStr
    signature: HexStr


class DKGRound2NodeResponse(BaseModel):
    encrypted_package: dict[NodeID, str]


class AnnulmentData(BaseModel): ...
