from fastapi import APIRouter

from zexfrost.custom_types import Commitment, CommitmentRequest
from zexfrost.utils import get_curve

from ..repository import get_key_repository, get_nonce_repository
from ..settings import node_settings as settings
from ..sign import commitment as signature_commitment

router = APIRouter(prefix="/sign")


@router.post("/commitment", response_model=Commitment)
async def commitment(commitment_request: CommitmentRequest):
    return signature_commitment(
        node_id=settings.ID,
        curve=get_curve(commitment_request.curve),
        key_repo=get_key_repository(),
        nonce_repo=get_nonce_repository(),
        pubkey_package=commitment_request.pubkey_package,
        tweak_by=commitment_request.tweak_by,
    )
