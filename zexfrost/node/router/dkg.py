from fastapi import APIRouter

from zexfrost.custom_types import (
    DKGRound1NodeResponse,
    DKGRound1Request,
    DKGRound2EncryptedPackage,
    DKGRound2Request,
    DKGRound3NodeResponse,
    DKGRound3Request,
)
from zexfrost.utils import get_curve

from ..dkg import DKG
from ..party import get_party
from ..repository import get_dkg_repository, get_key_repository
from ..settings import node_settings as settings

router = APIRouter(prefix="/dkg", tags=["DKG"])


@router.post("/round1", response_model=DKGRound1NodeResponse)
def round1(round1_request: DKGRound1Request):
    party = get_party(round1_request.party_id)
    dkg = DKG(
        settings=settings,
        curve=get_curve(round1_request.curve),
        id=round1_request.id,
        party=party,
        repository=get_dkg_repository(),
    )
    return dkg.round1(max_signers=round1_request.max_signers, min_signers=round1_request.min_signers)


@router.post("/round2", response_model=DKGRound2EncryptedPackage)
def round2(round2_request: DKGRound2Request):
    dkg = DKG.load_dkg_object(settings=settings, id=round2_request.id, repository=get_dkg_repository())
    return dkg.round2(broadcast_data=round2_request.broadcast_data)


@router.post("/round3", response_model=DKGRound3NodeResponse)
def round3(round3_request: DKGRound3Request):
    dkg = DKG.load_dkg_object(settings=settings, id=round3_request.id, repository=get_dkg_repository())
    key_repo = get_key_repository()
    return dkg.round3(round3_request.encrypted_package, key_repo)
