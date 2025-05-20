from uuid import uuid4

import pytest
from frost_lib import secp256k1_tr

from zexfrost.custom_types import Node
from zexfrost.key import Key
from zexfrost.node.dkg import DKG
from zexfrost.node.settings import NodeSettings
from zexfrost.utils import single_verify_data

party = (
    Node(
        id="0000000000000000000000000000000000000000000000000000000000000002",
        host="http://localhost",  # type: ignore
        port=2020,
        public_key="dfk;j",
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


def test_store_and_load_dkg_round1(dkg: DKG):
    dkg.store_dkg_object()
    dkg2 = DKG.load_dkg_object(dkg.settings, dkg.id, dkg.repository)
    assert dkg == dkg2


def test_signing_and_verifying_dkg_round1(dkg: DKG):
    result = dkg.round1(3, 2)
    data = result.model_dump(mode="python", exclude={"signature"})
    main_key = Key(dkg.settings.CURVE_NAME, dkg.settings.PRIVATE_KEY)
    assert single_verify_data(main_key._curve, main_key.public_key, data, result.signature)
