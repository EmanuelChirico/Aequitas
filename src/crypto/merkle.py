"""
Albero di Merkle binario con prove di inclusione (§7.4).

Struttura:
  - Le foglie sono i valori SHA-256 delle triple (R, sigma_bytes, C) del VBR
    in ordine canonico lessicografico per R (§4.4).
  - Con un numero dispari di nodi a un livello, l'ultimo viene duplicato
    (convenzione standard; documentata qui perché influenza la verifica).
  - La radice rho è l'hash finale dell'albero.

API:
  MerkleTree(leaves)     — costruisce l'albero; leaves è una lista di bytes
  .root()                — radice rho (bytes)
  .proof(index)          — prova di inclusione per la foglia all'indice dato
  MerkleTree.verify(leaf, proof, root) — verifica statica di una prova
"""

import hashlib


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return _h(left + right)


class MerkleTree:
    def __init__(self, leaves: list[bytes]) -> None:
        if not leaves:
            raise ValueError("Albero Merkle vuoto: nessuna foglia fornita")
        # Livello 0: le foglie
        self._layers: list[list[bytes]] = [list(leaves)]
        self._build()

    def _build(self) -> None:
        current = self._layers[0]
        while len(current) > 1:
            # Con numero dispari di nodi duplica l'ultimo (convenzione standard)
            if len(current) % 2 == 1:
                current = current + [current[-1]]
            parent = [
                _hash_pair(current[i], current[i + 1])
                for i in range(0, len(current), 2)
            ]
            self._layers.append(parent)
            current = parent

    def root(self) -> bytes:
        """Radice dell'albero (rho)."""
        return self._layers[-1][0]

    def proof(self, index: int) -> list[tuple[bytes, str]]:
        """
        Prova di inclusione per la foglia all'indice `index` (0-based).

        Restituisce una lista di (sibling_hash, "left"|"right") che,
        applicata iterativamente dalla foglia alla radice, permette di
        ricostruire e verificare rho.

        "left"  significa che il sibling va a sinistra dell'elemento corrente.
        "right" significa che il sibling va a destra.
        """
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
        """
        Verifica che `leaf` appartenga all'albero con radice `root`.

        Args:
            leaf:  hash della foglia da verificare (bytes).
            proof: lista di (sibling_hash, side) restituita da .proof().
            root:  radice attesa.
        """
        current = leaf
        for sibling, side in proof:
            if side == "left":
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current == root
