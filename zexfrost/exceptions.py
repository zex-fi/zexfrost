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
