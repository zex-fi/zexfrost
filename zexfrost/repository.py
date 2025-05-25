from typing import Protocol


class RepositoryProtocol[_VALUET](Protocol):
    def get(self, key: str) -> _VALUET | None:
        """Get the nonce for a node"""
        ...

    def set(self, key: str, value: _VALUET) -> None:
        """Set the nonce for a node"""
        ...

    def delete(self, key: str) -> None:
        """Delete the nonce for a node"""
        ...
