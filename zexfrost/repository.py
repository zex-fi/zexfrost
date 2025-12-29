from typing import Protocol


class RepositoryProtocol[_VALUET](Protocol):
    def get(self, key: str) -> _VALUET | None:
        """Get value for the key"""
        ...

    def set(self, key: str, value: _VALUET) -> None:
        """Set value for the key"""
        ...

    def pop(
        self,
        key: str,
    ) -> _VALUET | None:
        """Get and delete the value for the key"""
        ...

    def delete(self, key: str) -> None:
        """Delete the value for the key"""
        ...
