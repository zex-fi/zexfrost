import json
from uuid import uuid4

import pytest
from frost_lib import secp256k1_tr
from frost_lib.types import DKGPart2Package

from zexfrost.custom_types import Node, NodeID, DKGRound2EncryptedPackage
from zexfrost.key import Key
from zexfrost.node.dkg import DKG
from zexfrost.node.settings import NodeSettings
from zexfrost.utils import single_verify_data, decrypt_with_joint_key

settings = (
    NodeSettings(
        ID="0000000000000000000000000000000000000000000000000000000000000001",
        PRIVATE_KEY="4f68a04f9fa036e3d246cc4aad75c25f234d9ee43fd9cf657f27d75edf90f018"
    ),
    NodeSettings(
        ID="0000000000000000000000000000000000000000000000000000000000000002",
        PRIVATE_KEY="88c1ce8446836b17fd0bf3c6f804cb671beda62047ed4dbaeffade513f6ba5eb"
    ),
    NodeSettings(
        ID="0000000000000000000000000000000000000000000000000000000000000003",
        PRIVATE_KEY="2e24a06e86401ae70571a5849e9029728b68d2470348ec69d8305f035be1d5ef"
    )
)

party = (
    Node(
        id="0000000000000000000000000000000000000000000000000000000000000001",
        host="http://localhost",  # type: ignore
        port=2021,
        public_key="03c1ae1d8bf50c86b20abe14ee71fad95904a6291360a02652a00b2823694303d9",
    ),
    Node(
        id="0000000000000000000000000000000000000000000000000000000000000002",
        host="http://localhost",  # type: ignore
        port=2022,
        public_key="02cd21aa0dc62a024419b5f7769f2b964ab9022cda556d2a62d3b55a7242af91b0",
    ),
    Node(
        id="0000000000000000000000000000000000000000000000000000000000000003",
        host="http://localhost",  # type: ignore
        port=2023,
        public_key="02447302ce5050995575419d61244c0f04ad60b7351981823ee81ec802b1fc8fe6",
    ),
)


class DKGRepository:
    def __init__(self):
        self.db = {}

    def set(self, key: str, value):
        self.db[key] = value

    def get(self, key: str):
        return self.db.get(key)

    def delete(self, key: str):
        del self.db[key]


@pytest.fixture
def dkg_repo():
    return DKGRepository()


@pytest.fixture
def dkg(dkg_repo):
    settings = NodeSettings.model_validate({})
    dkg = DKG(
        settings=settings,
        curve=secp256k1_tr,
        id=uuid4(),
        repository=dkg_repo,
        party=party,
    )
    return dkg


def test_store_and_load_dkg(dkg: DKG):
    dkg.store_dkg_object()
    dkg2 = DKG.load_dkg_object(dkg.settings, dkg.id, dkg.repository)
    assert dkg == dkg2


def test_signing_and_verifying_dkg_round1(dkg: DKG):
    result = dkg.round1(3, 2)
    data = result.model_dump(mode="python", exclude={"signature"})
    main_key = Key(dkg.settings.CURVE_NAME, dkg.settings.PRIVATE_KEY)
    assert single_verify_data(main_key._curve, main_key.public_key, data, result.signature)

def test_encryption_dkg_round2():
    dkgs: dict[NodeID, DKG] = {}
    broadcast_packages = {}

    for setting_profile in settings:
        dkgs[setting_profile.ID] = DKG(
            settings=setting_profile,
            curve=secp256k1_tr,
            id=uuid4(),
            repository=DKGRepository(),
            party=party,
        )

    for node in party:
        round1_result = dkgs[node.id].round1(3, 2)

        for receiver_node in party:
            if receiver_node.id == node.id:
                continue
            if broadcast_packages.get(receiver_node.id) is None:
                broadcast_packages[receiver_node.id] = {}
            broadcast_packages[receiver_node.id][node.id] = round1_result

    for node in party:
        round2_result = dkgs[node.id].round2(broadcast_packages[node.id])
        for receiver_id, encrypted_data in round2_result.encrypted_package.items():
            decrypted_package = decrypt_with_joint_key(
                encrypted_data,
                dkgs[receiver_id].temp_key._private_key,
                dkgs[node.id].temp_key.public_key
            )
            decrypted_package = json.loads(decrypted_package)
            decrypted_package = DKGPart2Package(**decrypted_package)
            assert dkgs[node.id].round2_result.packages[receiver_id] == decrypted_package

def test_dkg():
    dkgs: dict[NodeID, DKG] = {}
    broadcast_packages = {}
    peer_exchange_packages = {}
    verifying_key = None

    for setting_profile in settings:
        dkgs[setting_profile.ID] = DKG(
            settings=setting_profile,
            curve=secp256k1_tr,
            id=uuid4(),
            repository=DKGRepository(),
            party=party,
        )

    for node in party:
        round1_result = dkgs[node.id].round1(3, 2)

        for receiver_node in party:
            if receiver_node.id == node.id:
                continue
            if broadcast_packages.get(receiver_node.id) is None:
                broadcast_packages[receiver_node.id] = {}
            broadcast_packages[receiver_node.id][node.id] = round1_result

    for node in party:
        round2_result = dkgs[node.id].round2(broadcast_packages[node.id])
        for receiver_id, encrypted_data in round2_result.encrypted_package.items():
            if peer_exchange_packages.get(receiver_id) is None:
                peer_exchange_packages[receiver_id] = {}
            peer_exchange_packages[receiver_id][node.id] = encrypted_data

    for node in party:
        data = DKGRound2EncryptedPackage(encrypted_package=peer_exchange_packages[node.id])
        round3_result = dkgs[node.id].round3(data)
        if verifying_key is None:
            verifying_key = round3_result["pubkey_package"]["verifying_key"]
        else:
            assert verifying_key == round3_result["pubkey_package"]["verifying_key"]