from typing import Literal
from uuid import UUID

from frost_lib.types import DKGPart1Package, DKGPart1Result, DKGPart2Result, DKGPart3Result, HexStr
from frost_lib.wrapper import BaseCryptoModule
from pydantic import BaseModel, HttpUrl, computed_field

from zexfrost.utils import get_curve, single_sign_data

type NodeId = HexStr
type DKGId = UUID


__all__ = [
    "Key",
    "Node",
    "DKGRound1NodeResponse",
    "DKGRound2NodeResponse",
    "AnnulmentData",
    "DKGPart1Result",
    "DKGPart2Result",
    "DKGPart3Result",
]


class Key:
    def __init__(self, curve: BaseCryptoModule | str, private_key: HexStr):
        self._private_key = private_key
        self._curve = get_curve(curve)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Key):
            return False
        return self._private_key == other._private_key and self._curve.curve_name == other._curve.curve_name

    @property
    def public_key(self) -> HexStr:
        return self._curve.get_pubkey(self._private_key)

    def sign_data(self, data: bytes | dict) -> HexStr:
        return single_sign_data(self._curve, self._private_key, data)


class Node(BaseModel):
    id: NodeId
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


class DKGRound2NodeResponse(BaseModel): ...


class AnnulmentData(BaseModel): ...
