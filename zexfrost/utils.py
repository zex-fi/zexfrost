import json

from frost_lib.wrapper import BaseCryptoModule, secp256k1_tr

from zexfrost.custom_types import HexStr

curves_mapping: dict[str, BaseCryptoModule] = {
    secp256k1_tr.curve_name: secp256k1_tr,
}


def get_curve(curve: str | BaseCryptoModule) -> BaseCryptoModule:
    return curve if isinstance(curve, BaseCryptoModule) else curves_mapping[curve]


def single_sign_data(curve: BaseCryptoModule | str, private_key: HexStr, data: bytes | dict) -> HexStr:
    """
    Sign data using a private key.
    """
    match data:
        case dict():
            data = json.dumps(data, sort_keys=True).encode("utf-8")
        case bytes():
            ...
        case _:
            raise NotImplementedError("Data must be a dict or bytes.")

    result = get_curve(curve).single_sign(private_key, data.hex())
    return result


def single_verify_data(
    curve: BaseCryptoModule | str, public_key: HexStr, data: bytes | dict, signature: HexStr
) -> bool:
    """
    Verify data using a public key.
    """
    match data:
        case dict():
            data = json.dumps(data, sort_keys=True).encode("utf-8")
        case bytes():
            ...
        case _:
            raise NotImplementedError("Data must be a dict or bytes.")
    result = get_curve(curve).single_verify(signature, data.hex(), public_key)
    return result
