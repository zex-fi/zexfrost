import json

from frost_lib.wrapper import BaseCryptoModule

from zexfrost.custom_types import (
    DKGID,
    DKGPart1Package,
    DKGPart1Result,
    DKGPart2Package,
    DKGPart2Result,
    DKGRound1NodeResponse,
    DKGRound2EncryptedPackage,
    DKGRound3NodeResponse,
    HexStr,
    Node,
    NodeID,
)
from zexfrost.exceptions import (
    DKGNotFoundError,
    PartnersRound1PackagesMissingError,
    PartnersTempPublicKeyMissingError,
    Round1NotCompletedError,
    Round2NotCompletedError,
    SignatureValidationError,
)
from zexfrost.key import Key
from zexfrost.node.settings import NodeSettings
from zexfrost.utils import (
    decrypt_with_joint_key,
    encrypt_with_joint_key,
    get_curve,
    single_sign_data,
    single_verify_data,
)

from .custom_types import DKGRepositoryValue
from .repository import DKGRepository, KeyRepository


class DKG:
    def __init__(
        self,
        settings: NodeSettings,
        curve: BaseCryptoModule,
        id: DKGID,
        repository: DKGRepository,
        party: tuple[Node, ...],
        temp_key: Key | None = None,
        round1_result: DKGPart1Result | None = None,
        round2_result: DKGPart2Result | None = None,
        partners_temp_public_key: dict[NodeID, HexStr] | None = None,
        partners_round1_packages: dict[NodeID, DKGPart1Package] | None = None,
    ):
        self.settings = settings
        self.curve = curve
        self.id = id
        self.temp_key = temp_key or Key(curve=curve, private_key=curve.keypair_new()["signing_key"])
        self.repository = repository
        self.partners = tuple(filter(lambda node: node.id != settings.ID, party))
        self._round1_result = round1_result
        self._round2_result = round2_result
        self._partners_round1_packages = partners_round1_packages
        self._partners_temp_public_key = partners_temp_public_key

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
            and self._round1_result == other._round1_result
            and self._round2_result == other._round2_result
            and self._partners_temp_public_key == other._partners_temp_public_key
            and self._partners_round1_packages == other._partners_round1_packages
        )

    @property
    def round1_result(self) -> DKGPart1Result:
        if self._round1_result is None:
            raise Round1NotCompletedError("Round 1 has not been completed yet")
        return self._round1_result

    @round1_result.setter
    def round1_result(self, value: DKGPart1Result | None):
        self._round1_result = value

    @property
    def round2_result(self) -> DKGPart2Result:
        if self._round2_result is None:
            raise Round2NotCompletedError("Round 2 has not been completed yet")
        return self._round2_result

    @round2_result.setter
    def round2_result(self, value: DKGPart2Result | None):
        self._round2_result = value

    @property
    def partners_round1_packages(self) -> dict[NodeID, DKGPart1Package]:
        if self._partners_round1_packages is None:
            raise PartnersRound1PackagesMissingError("Partners round 1 packages are missing")
        return self._partners_round1_packages

    @partners_round1_packages.setter
    def partners_round1_packages(self, value: dict[NodeID, DKGPart1Package] | None):
        self._partners_round1_packages = value

    @property
    def partners_temp_public_key(self) -> dict[NodeID, HexStr]:
        if self._partners_temp_public_key is None:
            raise PartnersTempPublicKeyMissingError("Partners temporary public keys are missing")
        return self._partners_temp_public_key

    @partners_temp_public_key.setter
    def partners_temp_public_key(self, value: dict[NodeID, HexStr] | None):
        self._partners_temp_public_key = value

    @classmethod
    def load_dkg_object(cls, settings: NodeSettings, id: DKGID, repository: DKGRepository) -> "DKG":
        dkg_data = repository.get(settings.ID + id.hex)
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
            partners_round1_packages=None
            if dkg_data["partners_round1_packages"] is None
            else {
                node_id: DKGPart1Package(**package) for node_id, package in dkg_data["partners_round1_packages"].items()
            },
        )

    def store_dkg_object(self):
        store_data: DKGRepositoryValue = {
            "curve": self.curve.curve_name,
            "temp_private_key": self.temp_key._private_key,
            "partners": tuple(node.model_dump(mode="python") for node in self.partners),
            "round1_result": self._round1_result and self.round1_result.model_dump(mode="python"),
            "round2_result": self._round2_result and self.round2_result.model_dump(mode="python"),
            "partners_temp_public_key": self._partners_temp_public_key,
            "partners_round1_packages": None
            if self._partners_round1_packages is None
            else {
                node_id: package.model_dump(mode="python") for node_id, package in self.partners_round1_packages.items()
            },
        }
        self.repository.set(self.settings.ID + self.id.hex, store_data)

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

    def validate_broadcast_data(self, data: dict[NodeID, DKGRound1NodeResponse]):
        result = {}
        for node in self.partners:
            node_result = data[node.id]
            verifying_data = node_result.model_dump(mode="python", exclude={"signature"})
            result[node.id] = single_verify_data(
                node.curve_name, node.public_key, verifying_data, node_result.signature
            )

        if not all(result.values()):
            failed_nodes = [node_id for node_id, verified in result.items() if not verified]
            raise SignatureValidationError(
                f"Signature validation failed for nodes: {failed_nodes}. Validation result: {result}"
            )

    def _parse_partners_temp_public_key(
        self, broadcast_data: dict[NodeID, DKGRound1NodeResponse]
    ) -> dict[NodeID, HexStr]:
        return {
            node_id: other_node_round1_result.temp_public_key
            for node_id, other_node_round1_result in broadcast_data.items()
        }

    def _preparing_round2_response(
        self, partners_temp_public_key: dict[NodeID, HexStr], round2_package: dict[NodeID, DKGPart2Package]
    ) -> DKGRound2EncryptedPackage:
        result = {}
        for node in self.partners:
            data_to_encrypt = json.dumps(round2_package[node.id].model_dump(mode="python"), sort_keys=True)
            result[node.id] = encrypt_with_joint_key(
                data_to_encrypt,
                self.temp_key._private_key,
                partners_temp_public_key[node.id],
            )
        return DKGRound2EncryptedPackage(encrypted_package=result)

    def round2(self, broadcast_data: dict[NodeID, DKGRound1NodeResponse]) -> DKGRound2EncryptedPackage:
        self.validate_broadcast_data(broadcast_data)
        self.partners_temp_public_key = self._parse_partners_temp_public_key(broadcast_data)
        self.partners_round1_packages = {node_id: node_resp.package for node_id, node_resp in broadcast_data.items()}
        result = self.curve.dkg_part2(
            self.round1_result.secret_package,
            {node_id: other_node_round1_result.package for node_id, other_node_round1_result in broadcast_data.items()},
        )
        self.round2_result = result
        self.store_dkg_object()
        return self._preparing_round2_response(self.partners_temp_public_key, self.round2_result.packages)

    def _decrypt_round2_package(
        self, partner_temp_public_key: dict[NodeID, HexStr], encrypted_package: DKGRound2EncryptedPackage
    ) -> dict[NodeID, DKGPart2Package]:
        result = {}
        for node_id, encrypted_data in encrypted_package.encrypted_package.items():
            decrypted_package = decrypt_with_joint_key(
                encrypted_data, self.temp_key._private_key, partner_temp_public_key[node_id]
            )
            decrypted_package = json.loads(decrypted_package)
            decrypted_package = DKGPart2Package(**decrypted_package)
            result[node_id] = decrypted_package
        return result

    def round3(self, round3_data: DKGRound2EncryptedPackage, key_repository: KeyRepository) -> DKGRound3NodeResponse:
        round2_package = self._decrypt_round2_package(self.partners_temp_public_key, round3_data)
        result = self.curve.dkg_part3(self.round2_result.secret_package, self.partners_round1_packages, round2_package)
        key_repository.set(
            self.settings.ID + result.pubkey_package.verifying_key, result.key_package.model_dump(mode="python")
        )
        signature = single_sign_data(
            self.settings.CURVE_NAME,
            self.settings.PRIVATE_KEY,
            {"pubkey_package": result.pubkey_package.model_dump(mode="python")},
        )
        return DKGRound3NodeResponse(pubkey_package=result.pubkey_package, signature=signature)
