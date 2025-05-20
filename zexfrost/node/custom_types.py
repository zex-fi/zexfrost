from typing import TypedDict

from zexfrost.custom_types import HexStr, NodeId


class DKGRepositoryValue(TypedDict):
    curve: str
    temp_private_key: HexStr
    partners: tuple[dict, ...]
    round1_result: dict | None
    round2_result: dict | None
    partners_temp_public_key: dict[NodeId, HexStr] | None
