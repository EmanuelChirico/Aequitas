"""
TallyMachine TM (§4.5).

Flusso di spoglio:
  1. load_uvc(vbr, pk_E)        — riceve la vista congelata, verifica la firma
                                   di E su rho e ricalcola la radice Merkle.
  2. collect_shares(trustees,   — raccoglie (S_i, r_i) dai trustee, verifica
                   commitments)    SHA256(S_i || r_i) == c_i; scarta le invalid.
                                   Se le valide sono < T → abort.
  3. reconstruct_key()          — interpolazione di Lagrange → d.
  4. tally(pk_elec)             — per ogni C in ordine canonico:
                                     m'_i = pow(C_int, d, N)  (pubblica m'_i)
                                     v_i  = decode_oaep(m'_i) (→ scheda nulla se fallisce)
                                   Aggrega conteggi.
  5. destroy_key()              — azzera d (chiamare SEMPRE dopo tally).

NOTA DIDATTICA (per l'esame):
  La decifratura avviene in due passi pubblici:
    a) raw RSA: m' = pow(C, d, N) — pubblicata, verificabile da chiunque con pow(m', e, N)==C
    b) decode_oaep(m')           — rimozione del padding OAEP
  Questo separa la correttezza della decifratura (verificabile con la sola pk_elec)
  dall'estrazione del contenuto (che richiede la conoscenza del formato OAEP).
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional

from config import T, SHARE_BYTES, LAMBDA
from crypto.merkle import MerkleTree
from crypto.oaep_decode import decode_oaep, InvalidOAEP
from crypto.rsa_utils import hash_and_verify
from crypto.shamir import reconstruct as shamir_reconstruct
from entities.trustee import Trustee


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _commit(S_i: int, r_i: bytes) -> bytes:
    return _sha256(S_i.to_bytes(SHARE_BYTES, "big") + r_i)


def _leaf(R: bytes, sigma: bytes, C: bytes) -> bytes:
    return _sha256(R + sigma + C)


@dataclass
class TallyMachine:
    _vbr_snapshot: Optional[list]  = field(default=None, init=False, repr=False)
    _rho: Optional[bytes]          = field(default=None, init=False, repr=False)
    _rho_sigma: Optional[bytes]    = field(default=None, init=False, repr=False)
    _valid_shares: list            = field(default_factory=list, init=False, repr=False)
    _d: Optional[int]              = field(default=None, init=False, repr=False)
    _N: Optional[int]              = field(default=None, init=False, repr=False)
    _k: int                        = field(default=LAMBDA // 8, init=False, repr=False)
    _pre_images: list              = field(default_factory=list, init=False, repr=False)

    # ------------------------------------------------------------------ #
    # §4.5 — Caricamento e verifica della vista congelata                  #
    # ------------------------------------------------------------------ #

    def load_uvc(self, vbr, pk_E) -> None:
        """
        Riceve la vista congelata dal VBR e verifica:
          a) firma di E su rho (hash_and_verify);
          b) ricalcola la radice Merkle dalle triple e confronta con rho.
        Se uno dei due controlli fallisce → abort.

        Args:
            vbr:  istanza VBR dopo freeze().
            pk_E: chiave pubblica istituzionale di E.
        """
        if not vbr.frozen:
            raise RuntimeError("Il VBR non è ancora congelato")

        self._rho        = vbr.rho
        self._rho_sigma  = None   # verrà fornita da E.freeze_and_sign
        self._vbr_snapshot = list(vbr.registro)

        # Ricalcola la radice Merkle dalla lista in memoria e confronta
        leaves = [_leaf(R, sigma, C) for R, sigma, C in self._vbr_snapshot]
        tree   = MerkleTree(leaves)
        if tree.root() != self._rho:
            raise RuntimeError("Radice Merkle ricalcolata non corrisponde a rho — abort")

        print(
            f"[TM] Vista caricata: {len(self._vbr_snapshot)} schede, "
            f"rho={self._rho.hex()[:24]}…"
        )

    def set_rho_signature(self, rho_sigma: bytes, pk_E) -> None:
        """
        Verifica la firma di E su rho e la memorizza.
        Da chiamare dopo load_uvc(), con la sigma restituita da E.freeze_and_sign.
        """
        if not hash_and_verify(pk_E, self._rho, rho_sigma):
            raise RuntimeError("Firma di E su rho non valida — abort")
        self._rho_sigma = rho_sigma
        print("[TM] Firma di E su rho verificata.")

    # ------------------------------------------------------------------ #
    # §4.5 — Raccolta e verifica delle share                               #
    # ------------------------------------------------------------------ #

    def collect_shares(
        self,
        trustees: list[Trustee],
        commitments: list[bytes],
    ) -> None:
        """
        Raccoglie (S_i, r_i) da ogni trustee e verifica l'impegno.
        Le share invalide vengono scartate (il trustee viene segnalato).
        Se le share valide sono < T → abort.

        Args:
            trustees:    lista completa dei trustee.
            commitments: lista [c_1, ..., c_n] pubblicata nel blocco Params.
        """
        self._valid_shares = []
        for trustee, c_i in zip(trustees, commitments):
            try:
                S_i, r_i = trustee.reveal()
                if _commit(S_i, r_i) != c_i:
                    raise ValueError("impegno non verificato")
                self._valid_shares.append((trustee.trustee_id, S_i))
                print(f"[TM] {trustee.name}: share valida ✓")
            except Exception as exc:
                print(
                    f"[TM] {trustee.name}: share SCARTATA — {exc}  "
                    "(l'esclusione è registrata pubblicamente)"
                )

        if len(self._valid_shares) < T:
            raise RuntimeError(
                f"Share valide insufficienti: {len(self._valid_shares)} < {T} — abort"
            )
        print(f"[TM] {len(self._valid_shares)} share valide raccolte.")

    # ------------------------------------------------------------------ #
    # §4.5 — Ricostruzione della chiave privata                            #
    # ------------------------------------------------------------------ #

    def reconstruct_key(self, pk_elec) -> None:
        """
        Ricostruisce d tramite interpolazione di Lagrange in x=0 (§7.3).
        d vive solo come attributo privato; non viene mai restituito.

        NOTA: non possiamo fare assert d*e ≡ 1 (mod λ(N)) senza p e q;
        la correttezza sarà verificata indirettamente durante il tally
        (pow(m', e, N) == C per ogni scheda).
        """
        d_reconstructed = shamir_reconstruct(self._valid_shares)
        pub = pk_elec.public_numbers()
        self._d = d_reconstructed
        self._N = pub.n
        print(f"[TM] Chiave d ricostruita (prime {8} bit: {bin(self._d)[:10]}…)")

    # ------------------------------------------------------------------ #
    # §4.5 — Spoglio                                                       #
    # ------------------------------------------------------------------ #

    def tally(self, pk_elec) -> tuple[dict, list]:
        """
        Decifra e conta i voti.

        Per ogni C in ordine canonico:
          1. m'_i = pow(C_int, d, N)        — pre-immagine raw (pubblica)
          2. v_i  = decode_oaep(m'_i, k)   — voto in chiaro
             se decode_oaep fallisce → scheda nulla

        Returns:
            (results, pre_images) dove:
              results    = {candidato: n_voti, "nulle": n_nulle}
              pre_images = lista di dict {R, C, m_prime, v}
        """
        if self._d is None or self._N is None:
            raise RuntimeError("reconstruct_key() non ancora chiamato")

        pub = pk_elec.public_numbers()
        N, e = pub.n, pub.e

        results: dict[str, int] = {}
        self._pre_images = []

        for R, sigma, C in self._vbr_snapshot:
            C_int   = int.from_bytes(C, "big")
            m_prime = pow(C_int, self._d, N)

            # Verifica pubblica: chiunque controlla pow(m', e, N) == C_int
            assert pow(m_prime, e, N) == C_int, "Decifratura incoerente!"

            try:
                plaintext = decode_oaep(m_prime, self._k)
                v = plaintext.decode("utf-8").rstrip("\x00").strip()
            except (InvalidOAEP, UnicodeDecodeError):
                v = None     # scheda nulla

            key = v if v else "nulle"
            results[key] = results.get(key, 0) + 1

            self._pre_images.append({
                "R":       R.hex(),
                "C":       C.hex(),
                "m_prime": m_prime,
                "v":       v if v else "⊥",
            })

        return results, self._pre_images

    def destroy_key(self) -> None:
        """
        Azzera d. CHIAMARE SEMPRE dopo tally().
        In Python non c'è una garanzia di sovrascrittura fisica della memoria,
        ma il set a None rimuove la reference e rende d irraggiungibile.
        """
        self._d = None
        print("[TM] Chiave d distrutta.")

    # ------------------------------------------------------------------ #

    @property
    def pre_images(self) -> list:
        return list(self._pre_images)

    def __repr__(self) -> str:
        return (
            f"TallyMachine(schede={len(self._vbr_snapshot or [])}, "
            f"key={'presente' if self._d else 'assente'})"
        )
