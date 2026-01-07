import base64
import json
import random

import frost_lib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastecdsa.curve import secp256k1 as fastecdsa_secp256k1
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.point import Point

from zexfrost.custom_types import BaseCryptoCurve, CurveName, HexStr, Node


def get_curve(curve: CurveName | BaseCryptoCurve) -> BaseCryptoCurve:
    if isinstance(curve, BaseCryptoCurve):
        return curve
    if hasattr(frost_lib, curve):
        _curve = getattr(frost_lib, curve)
        if isinstance(_curve, BaseCryptoCurve):
            return _curve

    raise ValueError("curve not found.")


def pub_to_code(public_key: Point) -> HexStr:
    comp_pub = SEC1Encoder.encode_public_key(public_key, True)
    return comp_pub.hex()


def code_to_pub(key: HexStr) -> Point:
    key_byte = bytes.fromhex(key)
    return SEC1Encoder.decode_public_key(key_byte, fastecdsa_secp256k1)


def dict_to_bytes(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True).encode("utf-8")


def single_sign_data(curve: BaseCryptoCurve | CurveName, private_key: HexStr, data: bytes | dict) -> HexStr:
    """
    Sign data using a private key.
    """
    match data:
        case dict():
            data = dict_to_bytes(data)
        case bytes():
            ...
        case _:
            raise NotImplementedError("Data must be a dict or bytes.")

    result = get_curve(curve).single_sign(private_key, data)
    return result


def single_verify_data(
    curve: BaseCryptoCurve | CurveName, public_key: HexStr, data: bytes | dict, signature: HexStr
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
    result = get_curve(curve).single_verify(signature, data, public_key)
    return result


def generate_hkdf_key(key: HexStr) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"",
        backend=default_backend(),
    )
    return hkdf.derive(bytes.fromhex(key))


def encrypt(data: str | dict, key: bytes) -> str:
    if not isinstance(data, str):
        data = json.dumps(data)
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode(encoding="utf-8")


def decrypt(data: str, key: bytes) -> str:
    encoded_data = data.encode("utf-8")
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.decrypt(encoded_data).decode()


def hexstr_to_int(hexstr: HexStr) -> int:
    return int(hexstr, 16)


def encrypt_with_joint_key(data: str, secret: HexStr, receiver_pubkey: HexStr) -> str:
    encryption_joint_key = pub_to_code(int(secret, 16) * code_to_pub(receiver_pubkey))
    encryption_key = generate_hkdf_key(encryption_joint_key)
    return encrypt(data, encryption_key)


def decrypt_with_joint_key(data: str, secret: HexStr, sender_pubkey: HexStr) -> str:
    encryption_joint_key = pub_to_code(int(secret, 16) * code_to_pub(sender_pubkey))
    encryption_key = generate_hkdf_key(encryption_joint_key)
    return decrypt(data, encryption_key)


def get_random_party(party: tuple[Node, ...], size: int) -> tuple[Node, ...]:
    party_len = len(party)
    if party_len == size:
        return party
    if party_len < size:
        raise ValueError(f"{size=} is bigger than party len {party_len}")
    weighted_pool = [(random.random() ** (1 / node.selection_weight), node) for node in party]
    weighted_pool.sort(reverse=True)
    selected = tuple(node for _, node in weighted_pool[:size])
    return selected
