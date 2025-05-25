import asyncio
from uuid import uuid4

import httpx

from zexfrost.custom_types import (
    DKGID,
    AnnulmentData,
    BaseCryptoModule,
    DKGRound1NodeResponse,
    DKGRound1Request,
    DKGRound2EncryptedPackage,
    DKGRound2Request,
    DKGRound3NodeResponse,
    DKGRound3Request,
    Node,
    NodeID,
    PublicKeyPackage,
)
from zexfrost.exceptions import DKGResultIncompatibilityError
from zexfrost.repository import RepositoryProtocol
from zexfrost.utils import single_verify_data


class DKG:
    def __init__(
        self,
        curve: BaseCryptoModule,
        party: tuple[Node, ...],
        max_signers: int,
        min_singers: int,
        repository: RepositoryProtocol,
        loop: asyncio.AbstractEventLoop | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: int = 10,
    ) -> None:
        self.party = party
        self.id = self._generate_id()
        self.http_client = http_client or httpx.AsyncClient()
        self.timeout = timeout
        self.loop = loop or asyncio.get_running_loop()
        self.curve = curve
        self.max_signers = max_signers
        self.min_singers = min_singers
        self.repository = repository

    def _generate_id(self) -> DKGID:
        return uuid4()

    async def _send_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        res = await self.http_client.request(method, url, **kwargs)
        res.raise_for_status()
        return res

    async def round1(self) -> dict[NodeID, DKGRound1NodeResponse]:
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}dkg/round1",
                    json=DKGRound1Request(
                        id=self.id,
                        max_signers=self.max_signers,
                        min_signers=self.min_singers,
                        party_id=[node.id for node in self.party],
                        curve=self.curve.curve_name,
                    ).model_dump(mode="json"),
                )
            )
            for node in self.party
        }

        result = {node_id: DKGRound1NodeResponse(**(await task).json()) for node_id, task in tasks.items()}
        self.validate_signature(result)

        return result

    def validate_signature[_SIGNATURE_T: (DKGRound1NodeResponse, DKGRound3NodeResponse)](
        self, party_result: dict[NodeID, _SIGNATURE_T]
    ) -> None:
        result = {}
        for node in self.party:
            node_result = party_result[node.id]
            data = node_result.model_dump(mode="python", exclude={"signature"})
            result[node.id] = single_verify_data(node.curve_name, node.public_key, data, node_result.signature)

        assert all(result.values()), result

    def store_round1_result(self, party_result: dict[NodeID, DKGRound1NodeResponse]) -> None:
        for node in self.party:
            self.repository.set(f"{self.id}-{node.id}-round1", party_result[node.id].model_dump(mode="python"))

    def store_round2_result(self, party_result: dict[NodeID, DKGRound2EncryptedPackage]) -> None:
        for node in self.party:
            self.repository.set(f"{self.id}-{node.id}-round2", party_result[node.id].model_dump(mode="python"))

    def _round2_data_parsing(
        self, node: Node, round1_result: dict[NodeID, DKGRound1NodeResponse]
    ) -> dict[NodeID, DKGRound1NodeResponse]:
        data = {}
        for other_node_id, other_node_response in round1_result.items():
            if node.id == other_node_id:
                continue
            data[other_node_id] = other_node_response
        return data

    async def _round2_per_node(
        self, node: Node, round1_result: dict[NodeID, DKGRound1NodeResponse]
    ) -> DKGRound2EncryptedPackage:
        broadcast_data = self._round2_data_parsing(node, round1_result)
        data = DKGRound2Request(id=self.id, broadcast_data=broadcast_data)
        res = await self._send_request(
            "POST",
            f"{node.url}dkg/round2",
            json=data.model_dump(mode="json"),
        )
        return DKGRound2EncryptedPackage.model_validate(res.json())

    async def round2(
        self, round1_result: dict[NodeID, DKGRound1NodeResponse]
    ) -> dict[NodeID, DKGRound2EncryptedPackage]:
        tasks = {node.id: asyncio.create_task(self._round2_per_node(node, round1_result)) for node in self.party}
        return {node_id: (await task) for node_id, task in tasks.items()}

    def _round3_data_parsing(
        self, node: Node, round2_result: dict[NodeID, DKGRound2EncryptedPackage]
    ) -> DKGRound3Request:
        return DKGRound3Request(
            encrypted_package=DKGRound2EncryptedPackage(
                encrypted_package={
                    other_node_id: other_node_response.encrypted_package[node.id]
                    for other_node_id, other_node_response in round2_result.items()
                    if node.id != other_node_id
                }
            ),
            id=self.id,
        )

    async def _round3_per_node(
        self, node: Node, round2_result: dict[NodeID, DKGRound2EncryptedPackage]
    ) -> DKGRound3NodeResponse:
        data = self._round3_data_parsing(node, round2_result).model_dump(mode="json")
        res = await self._send_request(
            "POST",
            f"{node.url}dkg/round3",
            json=data,
        )
        return DKGRound3NodeResponse.model_validate(res.json())

    def _check_round3_result(self, round3_result: dict[NodeID, DKGRound3NodeResponse]) -> None:
        if len({result.pubkey_package.verifying_key for result in round3_result.values()}) == 1:
            return
        raise DKGResultIncompatibilityError(
            "DKG round 3 failed: Public keys from nodes do not match. "
            "This indicates a potential security issue or node misconfiguration."
        )

    async def round3(self, round2_result: dict[NodeID, DKGRound2EncryptedPackage]) -> DKGRound3NodeResponse:
        tasks = {node.id: asyncio.create_task(self._round3_per_node(node, round2_result)) for node in self.party}
        result = {node_id: (await task) for node_id, task in tasks.items()}
        self.validate_signature(result)
        self._check_round3_result(result)
        return list(result.values())[0]

    def annulment(self) -> AnnulmentData: ...

    def dispute(self) -> list[Node]: ...

    async def run(self) -> PublicKeyPackage:
        round1_result = await self.round1()
        self.store_round1_result(round1_result)
        round2_result = await self.round2(round1_result)
        self.store_round2_result(round2_result)
        result = await self.round3(round2_result)
        return result.pubkey_package
