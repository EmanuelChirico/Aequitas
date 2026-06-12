"""
VBR — Verified Ballot Register (§4.4).

Registro append-only U delle triple (R, sigma, C):
  - R:     token del votante (32 byte)
  - sigma: firma IAP su R   (intero, hash-and-sign)
  - C:     voto cifrato      (bytes, output OAEP)

Invarianti:
  - Unicità di R: ogni token compare al più una volta.
  - Idempotenza: ri-submit con stesso (R, C) restituisce la ricevuta originale.
  - Doppio voto: ri-submit con stesso R e C diverso viene rifiutato.
  - Dopo freeze() i submit vengono rifiutati.
  - Ordinamento canonico: freeze() ordina U lessicograficamente per R
    prima di costruire il Merkle tree (requisito del protocollo).
"""

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Optional

from config import BULLETIN_FILE
from crypto.merkle import MerkleTree
from crypto.rsa_utils import hash_and_verify


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf(R: bytes, sigma: int, C: bytes) -> bytes:
    """Foglia Merkle: SHA256(R || sigma_bytes || C)."""
    sigma_bytes = sigma.to_bytes(256, "big")   # 256 B per RSA-2048
    return _sha256(R + sigma_bytes + C)


@dataclass
class VBR:
    pk_IAP: object              # chiave pubblica IAP per verificare sigma

    _U: list       = field(default_factory=list,  init=False, repr=False)
    _R_spent: dict = field(default_factory=dict,  init=False, repr=False)
    _lock: object  = field(default_factory=threading.Lock, init=False, repr=False)
    _frozen: bool  = field(default=False, init=False, repr=False)
    _tree: Optional[MerkleTree] = field(default=None, init=False, repr=False)
    _rho: Optional[bytes]       = field(default=None, init=False, repr=False)
    _params: Optional[dict]     = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ #
    # §4.4 — Ricezione voti                                                #
    # ------------------------------------------------------------------ #

    def submit(self, R: bytes, sigma: int, C: bytes) -> bytes:
        """
        Registra un voto.

        Controlli eseguiti nell'ordine:
          1. Verifica firma IAP su R (hash_and_verify).
          2. Se R già presente:
             a. C identico → ricevuta originale (idempotenza).
             b. C diverso  → rigetta (tentativo di doppio voto).
          3. Altrimenti: append atomico a U, restituisce h = SHA256(C).

        Returns:
            h = SHA256(C)  — ricevuta da conservare per la verifica individuale.

        Raises:
            PermissionError: firma IAP non valida.
            PermissionError: doppio voto (R già usato con C diverso).
            RuntimeError:    VBR congelato (urne chiuse).
        """
        if self._frozen:
            raise RuntimeError("VBR congelato: le urne sono chiuse")

        if not hash_and_verify(self.pk_IAP, R, sigma):
            raise PermissionError("Firma IAP non valida — voto rifiutato")

        h = _sha256(C)

        with self._lock:
            if R in self._R_spent:
                prev_C, prev_h = self._R_spent[R]
                if C == prev_C:
                    return prev_h      # ritrasmissione idempotente
                raise PermissionError(
                    "Doppio voto: R già presente con un voto diverso"
                )
            # Append atomico
            self._U.append((R, sigma, C))
            self._R_spent[R] = (C, h)

        return h

    # ------------------------------------------------------------------ #
    # §4.4 — Freeze e Merkle tree                                          #
    # ------------------------------------------------------------------ #

    def freeze(self) -> bytes:
        """
        Chiude le urne e costruisce il Merkle tree.

        Ordine canonico: U viene ordinato lessicograficamente per R
        (requisito del protocollo — NON saltare questo passo).

        Returns:
            rho — radice del Merkle tree (bytes).
        """
        with self._lock:
            self._frozen = True
            # Ordinamento canonico per R (bytes)
            self._U.sort(key=lambda triple: triple[0])

        leaves = [_leaf(R, sigma, C) for R, sigma, C in self._U]
        self._tree = MerkleTree(leaves)
        self._rho  = self._tree.root()
        print(f"[VBR] Freeze: {len(self._U)} voti, rho={self._rho.hex()[:24]}…")
        return self._rho

    def inclusion_proof(self, h: bytes) -> tuple[int, list]:
        """
        Restituisce (index, proof) per la verifica individuale.

        Args:
            h: SHA256(C) conservato dal votante come ricevuta.

        Returns:
            (index, proof) dove proof è la lista di (sibling, side)
            da passare a MerkleTree.verify().

        Raises:
            RuntimeError: VBR non ancora congelato.
            KeyError:     nessuna scheda con hash h trovata.
        """
        if not self._frozen or self._tree is None:
            raise RuntimeError("freeze() non ancora chiamato")
        for idx, (_, _, C) in enumerate(self._U):
            if _sha256(C) == h:
                return idx, self._tree.proof(idx)
        raise KeyError(f"Nessuna scheda trovata per h={h.hex()}")

    def verify_inclusion(self, h: bytes, proof: list) -> bool:
        """Verifica che la scheda con ricevuta h sia nel registro (usa MerkleTree.verify)."""
        if self._tree is None:
            raise RuntimeError("freeze() non ancora chiamato")
        triple = next(t for t in self._U if _sha256(t[2]) == h)
        leaf = _leaf(*triple)
        return MerkleTree.verify(leaf, proof, self._rho)

    # ------------------------------------------------------------------ #
    # §4.4 — Pubblicazione bollettino                                       #
    # ------------------------------------------------------------------ #

    def publish_params(self, params: dict) -> None:
        """Memorizza il blocco Params (chiamato da ElectoralAuthority.setup)."""
        self._params = params

    def publish(
        self,
        rho_sigma: int,
        pre_images: list[dict],
        results: dict,
        results_sigma: int,
        path: str = BULLETIN_FILE,
    ) -> None:
        """
        Scrive il bollettino pubblico su file JSON.

        Contenuto:
          - params:       blocco Params firmato da E
          - registro:     lista delle triple (R, sigma, C) in ordine canonico
          - rho:          radice Merkle (hex)
          - rho_sigma:    firma di E su rho
          - pre_images:   lista {R, C, m_prime, v} prodotta dalla TallyMachine
          - results:      conteggi {candidato: n_voti}
          - results_sigma: firma di E sul verbale

        Args:
            rho_sigma:    sigma = E.freeze_and_sign(rho)
            pre_images:   lista di dict con le pre-immagini raw e i voti aperti
            results:      dizionario dei voti aggregati
            results_sigma: sigma = E.certify(results)
            path:         percorso del file JSON di output
        """
        if not self._frozen:
            raise RuntimeError("publish() richiede che freeze() sia già stato chiamato")

        registro = [
            {
                "R":     R.hex(),
                "sigma": sigma,
                "C":     C.hex(),
            }
            for R, sigma, C in self._U
        ]

        bollettino = {
            "params":         self._params,
            "registro":       registro,
            "rho":            self._rho.hex(),
            "rho_sigma":      rho_sigma,
            "pre_images":     pre_images,
            "results":        results,
            "results_sigma":  results_sigma,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(bollettino, f, indent=2, default=str)
        print(f"[VBR] Bollettino pubblicato su {path}")

    # ------------------------------------------------------------------ #

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def rho(self) -> Optional[bytes]:
        return self._rho

    @property
    def registro(self) -> list:
        """Vista del registro in ordine canonico (solo dopo freeze)."""
        return list(self._U)

    def __repr__(self) -> str:
        return (
            f"VBR(voti={len(self._U)}, frozen={self._frozen}, "
            f"rho={'…' if self._rho is None else self._rho.hex()[:16] + '…'})"
        )
