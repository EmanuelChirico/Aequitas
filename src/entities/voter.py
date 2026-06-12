"""
VoterClient — logica lato elettore (§4.6).

DISCLAIMER DI ONESTÀ PROGETTUALE:
  Nel prototipo il VoterClient gira server-side per semplicità
  (niente crittografia in JavaScript). Nel sistema reale dovrebbe
  girare sul dispositivo dell'elettore in modo che il server non
  veda mai il voto in chiaro. Questa limitazione va dichiarata
  esplicitamente in sede d'esame.

Responsabilità:
  make_token()            — genera R = 32 byte casuali
  encrypt_vote(v, pk_e)   — serializza v a lunghezza fissa (64 B),
                             cifra con OAEP, calcola h = SHA256(C)
  delay()                 — attende δ casuale in [DELTA_MIN, DELTA_MAX]
  verify_inclusion(...)   — verifica la prova Merkle per la propria scheda
  verify_opening(...)     — controlla pow(m', e, N)==C e decode_oaep==v
"""

import hashlib
import json
import random
import secrets
import time

from config import DELTA_RANGE, ELECTION_ID, LAMBDA
from crypto.merkle import MerkleTree
from crypto.oaep_decode import decode_oaep, InvalidOAEP
from crypto.rsa_utils import oaep_encrypt

# Dimensione fissa del payload del voto in byte (§4.6)
VOTE_PAYLOAD_SIZE = 64
# k = dimensione chiave RSA in byte
RSA_KEY_BYTES = LAMBDA // 8


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class VoterClient:
    """
    Entità che rappresenta la logica crittografica del votante.
    Istanziata per ogni sessione di voto.
    """

    def __init__(self) -> None:
        self._R: bytes | None      = None
        self._C: bytes | None      = None
        self._h: bytes | None      = None
        self._v_encoded: bytes | None = None

    # ------------------------------------------------------------------ #
    # §4.6 — Token                                                         #
    # ------------------------------------------------------------------ #

    def make_token(self) -> bytes:
        """R = secrets.token_bytes(32) — 256 bit di casualità crittograficamente sicura."""
        self._R = secrets.token_bytes(32)
        return self._R

    # ------------------------------------------------------------------ #
    # §4.6 — Cifratura del voto                                            #
    # ------------------------------------------------------------------ #

    def encrypt_vote(self, v: str, pk_elec) -> tuple[bytes, bytes]:
        """
        Serializza la preferenza `v` a lunghezza fissa (VOTE_PAYLOAD_SIZE byte)
        con JSON + election_id incluso, poi cifra con RSA-OAEP.

        Calcola e memorizza h = SHA256(C) PRIMA della sottomissione
        (serve per la verifica individuale anche se la rete cade).

        Args:
            v:        stringa candidato, es. "Lista A - Rossi"
            pk_elec:  chiave pubblica di elezione

        Returns:
            (C, h) — voto cifrato e ricevuta
        """
        # Serializzazione a lunghezza fissa
        payload = json.dumps({"election_id": ELECTION_ID, "vote": v})
        payload_bytes = payload.encode("utf-8")
        if len(payload_bytes) > VOTE_PAYLOAD_SIZE:
            raise ValueError(
                f"Payload voto troppo lungo: {len(payload_bytes)} > {VOTE_PAYLOAD_SIZE}"
            )
        # Padding a destra con \x00 fino a VOTE_PAYLOAD_SIZE
        padded = payload_bytes.ljust(VOTE_PAYLOAD_SIZE, b"\x00")

        self._v_encoded = padded
        self._C = oaep_encrypt(pk_elec, padded)
        self._h = _sha256(self._C)
        return self._C, self._h

    # ------------------------------------------------------------------ #
    # §4.6 — Ritardo                                                       #
    # ------------------------------------------------------------------ #

    def delay(self) -> None:
        """
        Attende un intervallo casuale in [DELTA_RANGE[0], DELTA_RANGE[1]] secondi.
        Nel sistema reale sarebbe dell'ordine dei minuti per rendere difficile
        la correlazione temporale tra login e invio del voto.
        """
        delta = random.uniform(*DELTA_RANGE)
        time.sleep(delta)

    # ------------------------------------------------------------------ #
    # §4.6 — Verifica individuale                                           #
    # ------------------------------------------------------------------ #

    def verify_inclusion(
        self,
        proof: list,
        rho: bytes,
        R: bytes,
        sigma: int,
        C: bytes,
    ) -> bool:
        """
        Verifica che la propria scheda sia inclusa nel registro.

        Ricostruisce la foglia Merkle SHA256(R || sigma_bytes || C)
        e verifica la prova.
        """
        sigma_bytes = sigma.to_bytes(256, "big")
        leaf = _sha256(R + sigma_bytes + C)
        return MerkleTree.verify(leaf, proof, rho)

    def verify_opening(
        self,
        C: bytes,
        m_prime: int,
        pk_elec,
        expected_v: str,
    ) -> bool:
        """
        Verifica la correttezza della decifratura pubblicata dalla TM.

        Controlli:
          a) pow(m', e, N) == C_int  (correttezza raw RSA)
          b) decode_oaep(m') corrisponde al voto espresso

        Args:
            C:          voto cifrato inviato originariamente
            m_prime:    pre-immagine raw pubblicata dalla TM
            pk_elec:    chiave pubblica di elezione
            expected_v: preferenza che ci aspettiamo di trovare
        """
        pub    = pk_elec.public_numbers()
        C_int  = int.from_bytes(C, "big")

        # Controllo a
        if pow(m_prime, pub.e, pub.n) != C_int:
            return False

        # Controllo b
        try:
            plaintext = decode_oaep(m_prime, RSA_KEY_BYTES)
            info      = json.loads(plaintext.rstrip(b"\x00").decode("utf-8"))
            return info.get("vote") == expected_v
        except (InvalidOAEP, UnicodeDecodeError, json.JSONDecodeError):
            return False

    # ------------------------------------------------------------------ #

    @property
    def R(self) -> bytes | None:
        return self._R

    @property
    def C(self) -> bytes | None:
        return self._C

    @property
    def h(self) -> bytes | None:
        return self._h
