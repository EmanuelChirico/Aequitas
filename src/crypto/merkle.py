import hashlib

def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return _h(left + right)

class MerkleTree:
    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise ValueError("Albero Merkle vuoto: nessuna foglia fornita")
        self._layers: list[list[bytes]] = [list(leaves)]
        self._build()

    def _build(self) -> None:
        current = self._layers[0]
        while len(current) > 1:
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            parent = [
                _hash_pair(current[i], current[i + 1])
                for i in range(0, len(current), 2)
            ]
            self._layers.append(parent)
            current = parent

    def root(self) -> bytes:
        return self._layers[-1][0]

    def proof(self, index: int) -> list[tuple[bytes, str]]:
        path = []
        idx = index
        for layer in self._layers[:-1]:
            # Gestisci il padding dell'ultimo nodo duplicato
            padded = layer if len(layer) % 2 == 0 else layer + [layer[-1]]
            if idx % 2 == 0:
                sibling_idx = idx + 1
                side = "right"
            else:
                sibling_idx = idx - 1
                side = "left"
            path.append((padded[sibling_idx], side))
            idx //= 2
        return path

    @staticmethod
    def verify(leaf: bytes, proof: list[tuple[bytes, str]], root: bytes) -> bool:
        current = leaf
        for sibling, side in proof:
            if side == "left":
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current == root
