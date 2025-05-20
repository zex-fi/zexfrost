from frost_lib.wrapper import BaseCryptoModule

from zexfrost.custom_types import HexStr
from zexfrost.utils import get_curve, single_sign_data


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
