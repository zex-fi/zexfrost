import asyncio
from uuid import uuid4

import httpx

from zexfrost.custom_types import (
    AnnulmentData,
    BaseCryptoModule,
    DKGId,
    DKGRound1NodeResponse,
    DKGRound2EncryptedPackage,
    Node,
    NodeID,
)
from zexfrost.repository import DKGRepository
from zexfrost.utils import single_verify_data


class DKG:
    def __init__(
        self,
        curve: BaseCryptoModule,
        *party: Node,
        max_signers: int,
        min_singers: int,
        timeout: int = 10,
        loop: asyncio.AbstractEventLoop | None = None,
        repository: DKGRepository,
    ) -> None:
        self.party = party
        self.id = self._generate_id()
        self.http_client = httpx.AsyncClient()
        self.timeout = timeout
        self.loop = loop or asyncio.get_running_loop()
        self.curve = curve
        self.max_signers = max_signers
        self.min_singers = min_singers
        self.repository = repository

    def _generate_id(self) -> DKGId:
        return uuid4()

    async def _send_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        return await self.http_client.request(method, url, **kwargs)

    async def round1(self) -> dict[NodeID, DKGRound1NodeResponse]:
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}/dkg/round1",
                    json={"dkg_id": self.id, "max_singers": self.max_signers, "min_singers": self.min_singers},
                )
            )
            for node in self.party
        }

        result = {node_id: DKGRound1NodeResponse(**(await task).json()) for node_id, task in tasks.items()}
        return result

    def validate_round1_result(self, party_result: dict[NodeID, DKGRound1NodeResponse]):
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
    ) -> dict[NodeID, dict]:
        data = {}
        for other_node_id, other_node_response in round1_result.items():
            if node.id == other_node_id:
                continue
            data[other_node_id] = other_node_response.model_dump(mode="python")
        return data

    async def _round2_per_node(
        self, node: Node, round1_result: dict[NodeID, DKGRound1NodeResponse]
    ) -> DKGRound2EncryptedPackage:
        data = self._round2_data_parsing(node, round1_result)
        res = await self._send_request(
            "POST",
            f"{node.url}/dkg/round2",
            json=data,
        )
        return DKGRound2EncryptedPackage.model_validate(res.json())

    async def round2(
        self, round1_result: dict[NodeID, DKGRound1NodeResponse]
    ) -> dict[NodeID, DKGRound2EncryptedPackage]:
        tasks = {node.id: asyncio.create_task(self._round2_per_node(node, round1_result)) for node in self.party}
        return {node_id: (await task) for node_id, task in tasks.items()}

    def _round3_data_parsing(
        self, node: Node, round2_result: dict[NodeID, DKGRound2EncryptedPackage]
    ) -> DKGRound2EncryptedPackage:
        return DKGRound2EncryptedPackage(
            encrypted_package={
                other_node_id: other_node_response.encrypted_package[node.id]
                for other_node_id, other_node_response in round2_result.items()
                if node.id != other_node_id
            }
        )

    async def _round3_per_node(
        self, node: Node, round2_result: dict[NodeID, DKGRound2EncryptedPackage]
    ) -> DKGRound2EncryptedPackage:
        data = self._round3_data_parsing(node, round2_result)
        res = await self._send_request(
            "POST",
            f"{node.url}/dkg/round3",
            json=data,
        )
        return DKGRound2EncryptedPackage.model_validate(res.json())

    async def round3(self, round2_result: dict[NodeID, DKGRound2EncryptedPackage]):
        tasks = {node.id: asyncio.create_task(self._round3_per_node(node, round2_result)) for node in self.party}
        return {node_id: (await task) for node_id, task in tasks.items()}

    def annulment(self) -> AnnulmentData: ...

    def dispute(self) -> list[Node]: ...

    async def run(self) -> None:
        round1_result = await self.round1()
        self.validate_round1_result(round1_result)
        self.store_round1_result(round1_result)
        round2_result = await self.round2(round1_result)
        self.store_round2_result(round2_result)
        await self.round3(round2_result)


async def main(dkg: DKG):
    await dkg.round1()


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    # dkg = DKG(
    #     Node(id="adfkd;fja;fdkj", host="http://127.0.0.1", port=8080),
    #     Node(id="adfkd;fja;fdkj", host="http://127.0.0.1", port=8080),
    #     loop=loop,
    #     timeout=10,
    # )
    # loop.run_until_complete(main(dkg))
