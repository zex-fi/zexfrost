from typing import Protocol


class NonceRepository(Protocol):
    def get(self, public: str) -> str:
        """Get the nonce for a node"""
        ...

    def set(self, public: str, private: int) -> None:
        """Set the nonce for a node"""
        ...

    def delete(self, public: str) -> None:
        """Delete the nonce for a node"""
        ...


class DKGRepository[_DKGValueType](Protocol):
    def get(self, key: str) -> _DKGValueType | None:
        """Get the DKG for a node"""
        ...

    def set(self, key: str, value: _DKGValueType) -> None:
        """Set the DKG for a node"""
        ...

    def delete(self, key: str) -> None:
        """Delete the DKG for a node"""
        ...


class KeyRepository(Protocol):
    def get(self, key: str) -> str:
        """Get the key for a node"""
        ...

    def set(self, key: str, value: str) -> None:
        """Set the key for a node"""
        ...

    def delete(self, key: str) -> None:
        """Delete the key for a node"""
        ...
