from typing import TypedDict

from zexfrost.custom_types import CurveName, HexStr, NodeID


class DKGRepositoryValue(TypedDict):
    curve: CurveName
    temp_private_key: HexStr
    partners: tuple[dict, ...]
    round1_result: dict | None
    round2_result: dict | None
    partners_temp_public_key: dict[NodeID, HexStr] | None
    partners_round1_packages: dict[NodeID, dict] | None
