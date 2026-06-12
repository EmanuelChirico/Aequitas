"""
Trustee T_i (§4.2).

Ogni fiduciario:
  1. Riceve l'impegno c_i = SHA256(S_i || r_i) pubblicato da E sul VBR.
  2. Riceve da E la coppia (S_i, r_i) e verifica immediatamente l'impegno.
     Risponde con ACK solo se coerente.
  3. In fase di spoglio, rivela (S_i, r_i) alla TallyMachine.
  4. Se dishonest=True rivela una share falsificata (per la demo §8.2).
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from config import Q, SHARE_BYTES


def _commit(S_i: int, r_i: bytes) -> bytes:
    """c_i = SHA256(S_i_bytes || r_i)."""
    return hashlib.sha256(S_i.to_bytes(SHARE_BYTES, "big") + r_i).digest()


@dataclass
class Trustee:
    trustee_id: int           # identificativo 1-based
    name: str
    dishonest: bool = False   # flag per la demo del trustee disonesto (§8.2)

    _commitment: Optional[bytes] = field(default=None, init=False, repr=False)
    _S_i: Optional[int]          = field(default=None, init=False, repr=False)
    _r_i: Optional[bytes]        = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ #

    def set_commitment(self, c_i: bytes) -> None:
        """
        Riceve l'impegno c_i pubblicato da E sul VBR prima della
        distribuzione delle share.
        """
        self._commitment = c_i

    def receive_share(self, S_i: int, r_i: bytes) -> bool:
        """
        Riceve (S_i, r_i) da E e verifica SHA256(S_i || r_i) == c_i.

        Returns:
            True (ACK) se la verifica passa.

        Raises:
            RuntimeError: se l'impegno non è stato impostato.
            ValueError:   se l'impegno non corrisponde (share corrotta o
                          authority disonesta).
        """
        if self._commitment is None:
            raise RuntimeError(
                f"{self.name}: impegno non ricevuto prima della share"
            )
        if _commit(S_i, r_i) != self._commitment:
            raise ValueError(
                f"{self.name}: verifica impegno fallita — "
                "share corrotta o autorità non affidabile"
            )
        self._S_i = S_i
        self._r_i = r_i
        return True

    def reveal(self) -> tuple[int, bytes]:
        """
        Restituisce (S_i, r_i) alla TallyMachine durante lo spoglio.

        Se dishonest=True restituisce una share alterata (+1 mod Q):
        la TallyMachine la scarterà perché l'impegno non tornerà.
        """
        if self._S_i is None:
            raise RuntimeError(
                f"{self.name}: share non ancora ricevuta"
            )
        if self.dishonest:
            # Altera S_i: la TM ricalcolerà SHA256((S_i+1) || r_i) ≠ c_i
            return (self._S_i + 1) % Q, self._r_i
        return self._S_i, self._r_i

    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        ricevuta = "✓" if self._S_i is not None else "✗"
        return (
            f"Trustee(id={self.trustee_id}, name={self.name!r}, "
            f"share={ricevuta}, dishonest={self.dishonest})"
        )
