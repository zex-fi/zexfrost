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
    SigningRequest,
    TweakBy,
    UserSigningData,
)
from zexfrost.utils import get_random_party


class CommitmentGroupError(ExceptionGroup): ...


class SignatureGroupError(ExceptionGroup): ...


class SA:
    def __init__(
        self,
        curve: BaseCryptoCurve,
        party: tuple[Node, ...],
        pubkey_package: PublicKeyPackage,
        min_signer: int,
        http_client: httpx.AsyncClient | None = None,
        timeout: int = 20,
        loop: asyncio.AbstractEventLoop | None = None,
    ):
        self.curve = curve
        self._party = party
        self.timeout = timeout
        self.pubkey_package = pubkey_package
        self.http_client = http_client or httpx.AsyncClient()
        self.loop = loop or asyncio.get_running_loop()
        self.min_signer = min_signer

    def update_party(self, new_party: tuple[Node, ...]) -> None:
        self._party = new_party

    def _aggregate(
        self, signing_package: SigningPackage, shares: dict[NodeID, SharePackage], tweak_by: TweakBy | None = None
    ) -> HexStr:
        pubkey_package = self.pubkey_package
        match self.curve:
            case BaseCurveWithTweakedSign():
                pubkey_package = self.curve.pubkey_package_tweak(pubkey_package, tweak_by)
                return self.curve.aggregate_with_tweak(signing_package, shares, pubkey_package, None)
            case BaseCryptoCurve():
                if tweak_by is not None:
                    pubkey_package = self.curve.pubkey_package_tweak(pubkey_package, tweak_by)
                return self.curve.aggregate(signing_package, shares, pubkey_package)
        raise NotImplementedError("Curve type is unknown")

    def _verify(self, signature: HexStr, msg: bytes, tweak_by: TweakBy | None = None) -> bool:
        pubkey_package = self.pubkey_package
        match self.curve:
            case BaseCurveWithTweakedSign():
                pubkey_package = self.curve.pubkey_package_tweak(
                    self.curve.pubkey_package_tweak(self.pubkey_package, tweak_by)
                )
            case BaseCryptoCurve():
                if tweak_by is not None:
                    pubkey_package = self.curve.pubkey_package_tweak(self.pubkey_package, tweak_by)

        return self.curve.verify_group_signature(signature=signature, msg=msg, pubkey_package=pubkey_package)

    async def commitment(self, random_party: tuple[Node, ...], tweak_by: TweakBy | None) -> dict[NodeID, Commitment]:
        exceptions = []
        tasks = {
            node.id: self.loop.create_task(
                node.send_request(
                    self.http_client,
                    "POST",
                    "sign/commitment",
                    json=CommitmentRequest(
                        pubkey_package=self.pubkey_package, tweak_by=tweak_by, curve=self.curve.name
                    ).model_dump(mode="json"),
                )
            )
            for node in random_party
        }
        result = {}
        for node_id, task in tasks.items():
            try:
                result[node_id] = Commitment(**(await task).json())
            except Exception as e:
                exceptions.append(e)

        if exceptions:
            raise CommitmentGroupError("Error while trying to get commitment", exceptions)

        return result

    async def _get_commitments_for_sign(
        self, random_party: tuple[Node, ...], data: dict[SignatureID, UserSigningData]
    ) -> dict[SignatureID, dict[NodeID, Commitment]]:
        tasks: dict[HexStr, asyncio.tasks.Task[dict[NodeID, Commitment]]] = {}
        for sig_id, _data in data.items():
            tasks[sig_id] = self.loop.create_task(self.commitment(random_party, _data.tweak_by))
        return {sig_id: await task for sig_id, task in tasks.items()}

    async def sign(
        self, route: str, user_signing_data: dict[SignatureID, UserSigningData], meta_data: dict | None = None
    ) -> dict[SignatureID, HexStr]:
        # FIXME: capture and raise desire errors
        random_party = get_random_party(self._party, self.min_signer)
        sigs_commitments = await self._get_commitments_for_sign(random_party, user_signing_data)
        signings_data = {}
        signing_packages = {}
        for sig_id, sig_data in user_signing_data.items():
            signings_data[sig_id] = sig_data.to_signing_data(sigs_commitments[sig_id])
            signing_packages[sig_id] = self.curve.signing_package_new(sigs_commitments[sig_id], sig_data.message)
        signing_request = SigningRequest(
            meta_data=meta_data, signings_data=signings_data, pubkey_package=self.pubkey_package, curve=self.curve.name
        )
        tasks = {
            node.id: self.loop.create_task(
                node.send_request(
                    self.http_client,
                    "POST",
                    route,
                    json=signing_request.model_dump(mode="json"),
                )
            )
            for node in random_party
        }
        nodes_signing_response: dict[SignatureID, dict[NodeID, SharePackage]] = defaultdict(dict)
        exceptions = []
        for node_id, task in tasks.items():
            try:
                result = await task
                result.raise_for_status()
                for sig_id, share_package_data in result.json().items():
                    nodes_signing_response[sig_id][node_id] = SharePackage(**share_package_data)
            except Exception as e:
                exceptions.append(e)
        if exceptions:
            raise SignatureGroupError("Exceptions occurred while trying to sign", exceptions)
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
