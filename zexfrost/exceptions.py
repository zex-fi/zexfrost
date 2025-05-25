class ZexFrostBaseException(Exception):
    """
    Base exception for ZexFrost.
    """


class NodeTimeout(ZexFrostBaseException):
    """
    Raised when a node times out.
    """


class DKGNotFoundError(ZexFrostBaseException):
    """
    Raised when a DKG is not found.
    """


class Round1NotCompletedError(ZexFrostBaseException):
    """
    Raised when an operation requires round 1 to be completed, but it isn't.
    """


class Round2NotCompletedError(ZexFrostBaseException):
    """
    Raised when an operation requires round 2 to be completed, but it isn't.
    """


class PartnersRound1PackagesMissingError(ZexFrostBaseException):
    """
    Raised when partners' round 1 packages are required but not available.
    """


class PartnersTempPublicKeyMissingError(ZexFrostBaseException):
    """
    Raised when partners' temporary public keys are required but not available.
    """


class SignatureValidationError(ZexFrostBaseException):
    """
    Raised when signature validation fails.
    """


class DKGResultIncompatibilityError(ZexFrostBaseException):
    """
    Raised when DKG round 3 results are incompatible between nodes.
    This indicates a critical issue with the distributed key generation process,
    as all nodes must rich to the same public key.
    """
