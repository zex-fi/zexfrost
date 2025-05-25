from zexfrost.custom_types import Node, NodeID

_party: tuple[Node, ...] | None = None


def get_party(party_id: list[NodeID]) -> tuple[Node, ...]:
    assert _party is not None, "Party not initialized"
    return tuple(filter(lambda node: node.id in party_id, _party))


def set_party(party: tuple[Node, ...]) -> None:
    global _party
    _party = party
