from unittest.mock import MagicMock

from frost_lib.custom_types import Header

from zexfrost.custom_types import BaseCryptoCurve, Commitment, NodeID, TweakBy
from zexfrost.node import sign


class DummyKeyRepo:
    def get(self, key):
        return {
            "header": Header(version=1, ciphersuite="dummy"),
            "identifier": "node1",
            "signing_share": "share",
            "verifying_share": "vshare",
            "verifying_key": "vk",
            "min_signers": 1,
        }

    def set(self, key, value):
        self.last_set = (key, value)

    def pop(self, key):
        return self.get(key)

    def delete(self, key):
        pass


class DummyCurve(BaseCryptoCurve):
    @property
    def name(self):
        return "dummy"

    def _get_curve(self):
        return None

    def key_package_tweak(self, key_package, tweak_by, merkle_root=None):  # type: ignore
        self.tweaked = True
        return key_package

    def round1_commit(self, key_share):  # type: ignore
        class Result:
            class Commitments:
                binding = "binding"
                hiding = "hiding"

            commitments = Commitments()

            class Nonces:
                def model_dump(self, mode=None):
                    return {"nonce": "value"}

            nonces = Nonces()

        return Result()

    def signing_package_new(self, signing_commitments, msg):  # type: ignore
        return "signing_package"

    def round2_sign(self, signing_package, signer_nonces, key_package):  # type: ignore
        return "share_package"

    def round2_sign_with_tweak(self, signing_package, signer_nonces, key_package, merkle_root=None):
        return "share_package_tweaked"


class DummyNonceRepo:
    def set(self, key, value):
        self.last_set = (key, value)

    def get(self, key):
        return {
            "header": Header(version=1, ciphersuite="dummy"),
            "hiding": "hiding",
            "binding": "binding",
            "commitments": Commitment(
                header=Header(version=1, ciphersuite="dummy"), binding="binding", hiding="hiding"
            ),
        }

    def pop(self, key):
        return self.get(key)

    def delete(self, key):
        pass


def test_commitment():
    curve = DummyCurve()
    key_repo = DummyKeyRepo()
    nonce_repo = DummyNonceRepo()
    pubkey_package = MagicMock(verifying_key="vk")
    node_id = "node1"
    result = sign.commitment(node_id, curve, pubkey_package, key_repo, nonce_repo, tweak_by=None)
    assert hasattr(result, "binding")
    assert hasattr(result, "hiding")
    assert nonce_repo.last_set[0] == f"{result.binding}-{result.hiding}"


def make_commitment(binding, hiding):
    return Commitment(header=Header(version=1, ciphersuite="dummy"), binding=binding, hiding=hiding)


def test_sign():
    curve = DummyCurve()
    key_repo = DummyKeyRepo()
    nonce_repo = DummyNonceRepo()
    pubkey_package = MagicMock(verifying_key="vk")
    node_id: NodeID = "node1"
    commitments: dict[NodeID, Commitment] = {node_id: make_commitment("binding", "hiding")}
    message = b"msg"
    # Test without tweak
    result = sign.sign(curve, node_id, pubkey_package, commitments, message, key_repo, nonce_repo, tweak_by=None)
    assert result == "share_package"
    # Test with tweak (simulate TweakBy as bytes)
    tweak: TweakBy = b"tweak"
    result = sign.sign(curve, node_id, pubkey_package, commitments, message, key_repo, nonce_repo, tweak_by=tweak)
    assert result == "share_package"
