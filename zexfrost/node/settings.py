from typing import Literal

from pydantic import Field

from zexfrost.custom_types import HexStr
from zexfrost.settings import BaseApplicationSettings


class NodeSettings(BaseApplicationSettings):
    """Node settings."""

    model_config = {"env_prefix": "NODE__"}

    ID: HexStr
    CURVE_NAME: Literal["secp256k1_tr"] = Field(default="secp256k1_tr", frozen=True)
    PRIVATE_KEY: HexStr
