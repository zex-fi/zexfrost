from typing import TypedDict

from zexfrost.custom_types import HexStr


class DKGRepositoryValue(TypedDict):
    curve: str
    temp_private_key: HexStr
    party: tuple[dict, ...]
    round1_result: dict | None
    round2_result: dict | None
