import asyncio
from collections import defaultdict

import httpx

from zexfrost.custom_types import (
    BaseCryptoCurve,
    BaseCurveWithTweakedSign,
    Commitment,
    CommitmentRequest,
    HexStr,
    Node,
    NodeID,
    PublicKeyPackage,
    SharePackage,
    SignatureID,
    SigningPackage,
    TweakBy,
    UserSigningData,
)


class SA:
    def __init__(
        self,
        curve: BaseCryptoCurve,
        party: tuple[Node, ...],
        pubkey_package: PublicKeyPackage,
        http_client: httpx.AsyncClient | None = None,
        timeout: int = 20,
        loop: asyncio.AbstractEventLoop | None = None,
    ):
        self.curve = curve
        self.party = party
        self.timeout = timeout
        self.pubkey_package = pubkey_package
        self.http_client = http_client or httpx.AsyncClient()
        self.loop = loop or asyncio.get_running_loop()

    async def _send_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        res = await self.http_client.request(method, url, **kwargs)
        res.raise_for_status()
        return res

    def _aggregate(
        self, signing_package: SigningPackage, shares: dict[NodeID, SharePackage], tweak_by: TweakBy | None = None
    ) -> HexStr:
        match self.curve:
            case BaseCurveWithTweakedSign():
                pubkey_package = self.curve.pubkey_package_tweak(self.pubkey_package, tweak_by)
                return self.curve.aggregate_with_tweak(signing_package, shares, pubkey_package, None)
            case BaseCryptoCurve():
                return self.curve.aggregate(signing_package, shares, self.pubkey_package)
        raise NotImplementedError("Curve type is unknown")

    def _verify(self, signature: HexStr, msg: bytes, tweak_by: TweakBy | None = None) -> bool:
        pubkey_package = self.pubkey_package
        match self.curve:
            case BaseCurveWithTweakedSign():
                pubkey_package = self.curve.pubkey_package_tweak(
                    self.curve.pubkey_package_tweak(self.pubkey_package, tweak_by)
                )

        return self.curve.verify_group_signature(signature=signature, msg=msg, pubkey_package=pubkey_package)

    async def commitment(self, tweak_by: TweakBy | None) -> dict[NodeID, Commitment]:
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}sign/commitment",
                    json=CommitmentRequest(
                        pubkey_package=self.pubkey_package, tweak_by=tweak_by, curve=self.curve.name
                    ).model_dump(mode="json"),
                )
            )
            for node in self.party
        }
        result = {node_id: Commitment(**(await task).json()) for node_id, task in tasks.items()}
        return result

    async def sign(
        self,
        route: str,
        user_signing_data: dict[SignatureID, UserSigningData],
    ) -> dict[SignatureID, HexStr]:
        # FIXME: capture and raise desire errors

        sigs_commitments = await self._get_commitments_for_sign(user_signing_data)
        signing_data = {}
        signing_request = {}
        signing_packages = {}
        for sig_id, sig_data in user_signing_data.items():
            signing_data[sig_id] = sig_data.to_signing_data(
                self.pubkey_package, self.curve.name, sigs_commitments[sig_id]
            )
            signing_request[sig_id] = signing_data[sig_id].model_dump(mode="json")
            signing_packages[sig_id] = self.curve.signing_package_new(sigs_commitments[sig_id], sig_data.message)
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}{route}",
                    json=signing_request,
                )
            )
            for node in self.party
        }
        nodes_signing_response: dict[SignatureID, dict[NodeID, SharePackage]] = defaultdict(dict)
        for node_id, task in tasks.items():
            for sig_id, share_package_data in (await task).json().items():
                nodes_signing_response[sig_id][node_id] = SharePackage(**share_package_data)
        signatures = {}
        for sig_id, nodes_resp in nodes_signing_response.items():
            signatures[sig_id] = self._aggregate(
                signing_package=signing_packages[sig_id],
                shares=nodes_resp,
                tweak_by=user_signing_data[sig_id].tweak_by,
            )

        for sig_id, signature in signatures.items():
            assert self._verify(
                signature=signature,
                msg=user_signing_data[sig_id].message,
                tweak_by=user_signing_data[sig_id].tweak_by,
            ), "Signature is invalid"
        return signatures

    async def _get_commitments_for_sign(
        self, data: dict[SignatureID, UserSigningData]
    ) -> dict[SignatureID, dict[NodeID, Commitment]]:
        tasks: dict[HexStr, asyncio.tasks.Task[dict[NodeID, Commitment]]] = {}
        for sig_id, _data in data.items():
            tasks[sig_id] = self.loop.create_task(self.commitment(_data.tweak_by))
        return {sig_id: await task for sig_id, task in tasks.items()}
