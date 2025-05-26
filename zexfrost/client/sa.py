import asyncio

import httpx

from zexfrost.custom_types import (
    BaseCryptoModule,
    Commitment,
    CommitmentRequest,
    HexStr,
    Node,
    NodeID,
    PublicKeyPackage,
    SharePackage,
    SigningData,
    SigningPackage,
    SigningTweakData,
    SignRequest,
    SignTweakRequest,
    WithCustomTweak,
)


class SA:
    def __init__(
        self,
        curve: BaseCryptoModule,
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
        self, signing_package: SigningPackage, shares: dict[NodeID, SharePackage], tweak_by: HexStr | None = None
    ) -> HexStr:
        match self.curve:
            case WithCustomTweak():
                pubkey_package = self.curve.pubkey_package_tweak(self.pubkey_package, tweak_by)
                return self.curve.aggregate_with_tweak(signing_package, shares, pubkey_package, None)
            case BaseCryptoModule():
                return self.curve.aggregate(signing_package, shares, self.pubkey_package)
        raise NotImplementedError("Curve type is unknown")

    def _verify(self, signature: HexStr, msg: bytes, tweak_by: HexStr | None = None) -> bool:
        pubkey_package = self.pubkey_package
        match self.curve:
            case WithCustomTweak():
                pubkey_package = self.curve.pubkey_package_tweak(
                    self.curve.pubkey_package_tweak(self.pubkey_package, tweak_by)
                )

        return self.curve.verify_group_signature(signature=signature, msg=msg.hex(), pubkey_package=pubkey_package)

    async def commitment(self, tweak_by: HexStr | None) -> dict[NodeID, Commitment]:
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}sign/commitment",
                    json=CommitmentRequest(
                        pubkey_package=self.pubkey_package, tweak_by=tweak_by, curve=self.curve.curve_name
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
        data: SigningData,
        commitments: dict[NodeID, Commitment],
        message: bytes,
    ) -> HexStr:
        # FIXME: capture and raise desire errors
        signing_package = self.curve.signing_package_new(commitments, message.hex())
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}{route}",
                    json=SignRequest(
                        data=data,
                        commitments=commitments,
                        curve=self.curve.curve_name,
                        pubkey_package=self.pubkey_package,
                    ).model_dump(mode="json"),
                )
            )
            for node in self.party
        }
        result = {node_id: SharePackage(**(await task).json()) for node_id, task in tasks.items()}
        signature = self._aggregate(signing_package=signing_package, shares=result)
        assert self._verify(signature=signature, msg=message), "Signature is invalid"
        return signature

    async def sign_with_tweak(
        self,
        route: str,
        data: SigningTweakData,
        commitments: dict[NodeID, Commitment],
        message: dict[HexStr, bytes],
    ) -> dict[HexStr, HexStr]:
        # FIXME: capture and raise desire errors
        assert not isinstance(self.curve, WithCustomTweak), "Curve do not support tweak sign."
        tasks = {
            node.id: self.loop.create_task(
                self._send_request(
                    "POST",
                    f"{node.url}{route}",
                    json=SignTweakRequest(
                        data=data,
                        commitments=commitments,
                        curve=self.curve.curve_name,
                        pubkey_package=self.pubkey_package,
                    ).model_dump(mode="json"),
                )
            )
            for node in self.party
        }
        result = {
            node_id: {tweak_by: SharePackage(**data) for tweak_by, data in (await task).json().items()}
            for node_id, task in tasks.items()
        }
        signatures = {}
        for tweak_by, _message in message.items():
            signatures[tweak_by] = self._aggregate(
                signing_package=self.curve.signing_package_new(commitments, _message.hex()),
                shares={node_id: shares[tweak_by] for node_id, shares in result.items()},
                tweak_by=tweak_by,
            )
            assert self._verify(signature=signatures[tweak_by], msg=_message, tweak_by=tweak_by), "Signature is invalid"
        return signatures
