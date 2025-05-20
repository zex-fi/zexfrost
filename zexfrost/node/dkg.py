from frost_lib.wrapper import BaseCryptoModule

from zexfrost.custom_types import (
    DKGId,
    DKGPart1Result,
    DKGPart2Result,
    DKGRound1NodeResponse,
    HexStr,
    Key,
    Node,
    NodeId,
)
from zexfrost.exceptions import DKGNotFoundError
from zexfrost.node.settings import NodeSettings
from zexfrost.repository import DKGRepository
from zexfrost.utils import get_curve, single_sign_data, single_verify_data

from .custom_types import DKGRepositoryValue


class DKG:
    def __init__(
        self,
        settings: NodeSettings,
        curve: BaseCryptoModule,
        id: DKGId,
        repository: DKGRepository[DKGRepositoryValue],
        party: tuple[Node, ...],
        temp_key: Key | None = None,
        round1_result: DKGPart1Result | None = None,
        round2_result: DKGPart2Result | None = None,
        partners_temp_public_key: dict[NodeId, HexStr] | None = None,
    ):
        self.settings = settings
        self.curve = curve
        self.id = id
        self.temp_key = temp_key or Key(curve=curve, private_key=curve.keypair_new()["signing_key"])
        self.repository = repository
        self.partners = tuple(filter(lambda node: node.id != settings.ID, party))
        self.round1_result = round1_result
        self.round2_result = round2_result
        self.partners_temp_public_key = partners_temp_public_key

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DKG):
            return False
        return (
            self.settings == other.settings
            and self.curve.curve_name == other.curve.curve_name
            and self.id == other.id
            and self.temp_key == other.temp_key
            and self.repository == other.repository
            and self.partners == other.partners
            and self.round1_result == other.round1_result
            and self.round2_result == other.round2_result
            and self.partners_temp_public_key == other.partners_temp_public_key
        )

    @classmethod
    def load_dkg_object(cls, settings: NodeSettings, id: DKGId, repository: DKGRepository) -> "DKG":
        dkg_data = repository.get(id.hex)
        if dkg_data is None:
            raise DKGNotFoundError(f"DKG with dkg_id: {id.hex} is not found")
        load_data = {
            "round1_result": dkg_data["round1_result"],
            "round2_result": dkg_data["round2_result"],
        }
        curve = get_curve(dkg_data["curve"])
        return cls(
            settings=settings,
            id=id,
            curve=curve,
            party=tuple(Node.model_validate(node) for node in dkg_data["partners"]),
            temp_key=Key(curve, dkg_data["temp_private_key"]),
            repository=repository,
            round1_result=None
            if load_data["round1_result"] is None
            else DKGPart1Result.model_validate(load_data["round1_result"]),
            round2_result=None
            if load_data["round2_result"] is None
            else DKGPart2Result.model_validate(load_data["round2_result"]),
            partners_temp_public_key=dkg_data["partners_temp_public_key"],
        )

    def store_dkg_object(self):
        store_data: DKGRepositoryValue = {
            "curve": self.curve.curve_name,
            "temp_private_key": self.temp_key._private_key,
            "partners": tuple(node.model_dump(mode="python") for node in self.partners),
            "round1_result": self.round1_result and self.round1_result.model_dump(mode="python"),
            "round2_result": self.round2_result and self.round2_result.model_dump(mode="python"),
            "partners_temp_public_key": self.partners_temp_public_key,
        }
        self.repository.set(self.id.hex, store_data)

    def round1(self, max_signers: int, min_signers: int) -> DKGRound1NodeResponse:
        result = self.curve.dkg_part1(self.settings.ID, max_signers=max_signers, min_signers=min_signers)
        self.round1_result = result
        self.store_dkg_object()
        data = {"package": result.package.model_dump(mode="python"), "temp_public_key": self.temp_key.public_key}
        signature = single_sign_data(self.settings.CURVE_NAME, self.settings.PRIVATE_KEY, data)
        return DKGRound1NodeResponse(
            package=result.package,
            temp_public_key=self.temp_key.public_key,
            signature=signature,
        )

    def validate_broadcast_data(self, data: dict[NodeId, DKGRound1NodeResponse]):
        result = {}
        for node in self.partners:
            node_result = data[node.id]
            data = node_result.model_dump(mode="python", exclude={"signature"})
            result[node.id] = single_verify_data(node.curve_name, node.public_key, data, node_result.signature)

        assert all(result.values()), result

    def _parse_partners_temp_public_key(
        self, broadcast_data: dict[NodeId, DKGRound1NodeResponse]
    ) -> dict[NodeId, HexStr]:
        return {
            node_id: other_node_round1_result.temp_public_key
            for node_id, other_node_round1_result in broadcast_data.items()
        }

    def round2(self, broadcast_data: dict[NodeId, DKGRound1NodeResponse]):
        self.validate_broadcast_data(broadcast_data)
        self.partners_temp_public_key = self._parse_partners_temp_public_key(broadcast_data)
        assert self.round1_result is not None
        result = self.curve.dkg_part2(
            self.round1_result.secret_package,
            {node_id: other_node_round1_result.package for node_id, other_node_round1_result in broadcast_data.items()},
        )
        self.round2_result = result

        self.store_dkg_object()
        return result

    def round3(self, round3_data): ...
