"""Synthetic radio-access topology: cells served by packet-gateway nodes."""

from __future__ import annotations

from dataclasses import dataclass, field

PACKET_GATEWAY_SERVICE = "packet-gateway"


@dataclass(frozen=True)
class Cell:
    cell_id: str
    node_id: str


@dataclass(frozen=True)
class Topology:
    """Cells grouped under packet-gateway nodes (one service instance per node)."""

    cells: tuple[Cell, ...]
    service: str = PACKET_GATEWAY_SERVICE
    node_versions: dict[str, str] = field(default_factory=dict)

    @property
    def cell_ids(self) -> list[str]:
        return [c.cell_id for c in self.cells]

    @property
    def node_ids(self) -> list[str]:
        return sorted({c.node_id for c in self.cells})

    def node_of(self, cell_id: str) -> str:
        for cell in self.cells:
            if cell.cell_id == cell_id:
                return cell.node_id
        raise KeyError(f"unknown cell {cell_id!r}")

    def cells_of(self, node_id: str) -> list[str]:
        cells = [c.cell_id for c in self.cells if c.node_id == node_id]
        if not cells:
            raise KeyError(f"unknown node {node_id!r}")
        return cells

    def has_cell(self, cell_id: str) -> bool:
        return any(c.cell_id == cell_id for c in self.cells)


def default_topology(cells: int = 12, cells_per_node: int = 4) -> Topology:
    """CELL-101.. grouped in blocks of `cells_per_node` under pgw-1, pgw-2, ..."""
    if cells < 1 or cells_per_node < 1:
        raise ValueError("cells and cells_per_node must be positive")
    members = tuple(
        Cell(cell_id=f"CELL-{101 + i}", node_id=f"pgw-{i // cells_per_node + 1}")
        for i in range(cells)
    )
    nodes = sorted({c.node_id for c in members})
    return Topology(cells=members, node_versions={n: "2.4.0" for n in nodes})
