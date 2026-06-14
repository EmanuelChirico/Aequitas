"""
ElectoralAuthority E (§4.1).

Responsabilità (solo setup e certificazione — E non tocca le share dopo il
setup e non partecipa allo spoglio):

  setup(pk_iap, vbr)           — genera (pk_elec, sk_elec), applica Shamir
                                  a d, calcola impegni c_i = SHA256(S_i || r_i),
                                  pubblica il blocco Params sul VBR.
  distribute_shares(trustees)  — consegna (S_i, r_i) a ciascun trustee e
                                  riceve l'ACK; cancella le share dall'oggetto.
                                  (In produzione: canale cifrato autenticato.)
  dissolve()                   — cancella sk_elec, i fattori e le share;
                                  dopo dissolve() qualsiasi accesso ai segreti
                                  solleva RuntimeError.
  freeze_and_sign(rho)         — firma la radice di Merkle (chiusura urne).
  certify(results)             — firma il verbale finale.

La chiave istituzionale sk_E sopravvive a dissolve() perché serve per
freeze_and_sign e certify.

Firma: RSA-PSS con SHA-256 (§7.1).
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Optional

from config import LAMBDA, T, N_TRUSTEES, Q, SHARE_BYTES, ELECTION_ID
from crypto.rsa_utils import gen_rsa_keypair, hash_and_sign, hash_and_verify
from crypto.shamir import split as shamir_split
from entities.trustee import Trustee


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _commit(S_i: int, r_i: bytes) -> bytes:
    return _sha256(S_i.to_bytes(SHARE_BYTES, "big") + r_i)


@dataclass
class ElectoralAuthority:
    name: str = "Autorità Elettorale"

    # Chiave istituzionale (sopravvive a dissolve)
    _sk_E: object = field(init=False, repr=False)

    # Chiave di elezione (azzerata da dissolve)
    _sk_elec: Optional[object] = field(default=None, init=False, repr=False)
    # Chiave pubblica di elezione (rimane dopo dissolve — è pubblica)
    _pk_elec_cache: Optional[object] = field(default=None, init=False, repr=False)

    # Share e salt (azzerati dopo distribute_shares)
    _shares: Optional[list[int]]   = field(default=None, init=False, repr=False)
    _salts:  Optional[list[bytes]] = field(default=None, init=False, repr=False)

    # Impegni (rimangono pubblici anche dopo dissolve)
    _commitments: Optional[list[bytes]] = field(default=None, init=False, repr=False)

    _dissolved: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._sk_E = gen_rsa_keypair(LAMBDA)

    # ------------------------------------------------------------------ #
    # Proprietà pubbliche                                                  #
    # ------------------------------------------------------------------ #

    @property
    def pk_E(self):
        """Chiave pubblica istituzionale (verifica firme hash-and-sign di E)."""
        return self._sk_E.public_key()

    @property
    def pk_elec(self):
        """Chiave pubblica di elezione (distribuita ai votanti; persiste dopo dissolve)."""
        if self._pk_elec_cache is None:
            raise RuntimeError("pk_elec non disponibile: setup() non ancora eseguito")
        return self._pk_elec_cache

    @property
    def commitments(self) -> list[bytes]:
        """Impegni c_i pubblicati nel blocco Params."""
        if self._commitments is None:
            raise RuntimeError("setup() non ancora eseguito")
        return list(self._commitments)

    # ------------------------------------------------------------------ #
    # §4.1 — Metodi principali                                             #
    # ------------------------------------------------------------------ #

    def setup(self, pk_iap, vbr=None) -> dict:
        """
        1. Genera coppia RSA di elezione (pk_elec, sk_elec).
        2. Applica Shamir a d ottenendo le share S_1..S_n.
        3. Per ogni share calcola c_i = SHA256(S_i || r_i) con salt r_i casuale.
        4. Costruisce il blocco Params = {pk_elec, pk_IAP, [c_1..c_n], q, meta}
           e lo firma con sk_E (hash-and-sign).
        5. Pubblica Params sul VBR (se fornito).

        Args:
            pk_iap: chiave pubblica dell'IAP (inclusa in Params).
            vbr:    istanza VBR; se None il blocco viene solo restituito.

        Returns:
            Dizionario Params firmato.
        """
        # 1 — Genera coppia di elezione
        self._sk_elec = gen_rsa_keypair(LAMBDA)
        self._pk_elec_cache = self._sk_elec.public_key()
        pub_nums  = self._sk_elec.public_key().public_numbers()
        priv_nums = self._sk_elec.private_numbers()
        d = priv_nums.d

        # 2 — Shamir split su d
        self._shares = shamir_split(d, N_TRUSTEES, T)

        # 3 — Impegni
        self._salts       = [secrets.token_bytes(32) for _ in range(N_TRUSTEES)]
        self._commitments = [
            _commit(S_i, r_i)
            for S_i, r_i in zip(self._shares, self._salts)
        ]

        # 4 — Costruisce e firma Params
        params: dict = {
            "election_id": ELECTION_ID,
            "pk_elec":     {"n": pub_nums.n, "e": pub_nums.e},
            "pk_iap_n":    pk_iap.public_numbers().n,
            "commitments": [c.hex() for c in self._commitments],
            "q":           Q,
            "t":           T,
            "n":           N_TRUSTEES,
        }
        params_bytes       = _params_canonical_bytes(params)
        params["sigma_E"]  = hash_and_sign(self._sk_E, params_bytes).hex()

        # 5 — Pubblica
        if vbr is not None:
            vbr.publish_params(params)

        n_hex = hex(pub_nums.n)
        print(f"[{self.name}] Setup completato — pk_elec.n = {n_hex[:20]}…")
        return params

    def distribute_shares(self, trustees: list[Trustee]) -> None:
        """
        Consegna (S_i, r_i) a ciascun trustee e verifica il loro ACK.

        NOTA DI PRODUZIONE: in un sistema reale questo avverrebbe su un canale
        cifrato e autenticato (es. TLS mutuo) verso ciascun trustee. Nel
        prototipo è una semplice chiamata di metodo.

        Dopo la consegna, le share vengono cancellate dall'oggetto E: l'authority
        non deve conservarle (sarebbe un single point of failure).
        """
        if self._shares is None:
            raise RuntimeError("setup() non ancora eseguito")
        if len(trustees) != N_TRUSTEES:
            raise ValueError(
                f"Attesi {N_TRUSTEES} trustee, forniti {len(trustees)}"
            )

        for trustee, S_i, r_i, c_i in zip(
            trustees, self._shares, self._salts, self._commitments
        ):
            trustee.set_commitment(c_i)
            ok = trustee.receive_share(S_i, r_i)
            if not ok:
                raise RuntimeError(
                    f"{trustee.name} ha rifiutato la share (impegno non verificato)"
                )

        # Cancella share e salt: E non li possiede più
        self._shares = None
        self._salts  = None
        print(
            f"[{self.name}] Share distribuite a {N_TRUSTEES} trustee e "
            "cancellate dall'authority."
        )

    def dissolve(self) -> None:
        """
        Cancella sk_elec, i fattori primi e le eventuali share residue.
        Dopo questa chiamata:
          - qualsiasi accesso a pk_elec solleva RuntimeError
          - sk_E rimane intatta (serve per freeze_and_sign e certify)
        """
        self._sk_elec = None
        self._shares  = None
        self._salts   = None
        self._dissolved = True
        print(f"[{self.name}] Dissolto: sk_elec e share eliminati.")

    def freeze_and_sign(self, rho: bytes) -> bytes:
        """
        Firma la radice di Merkle rho alla chiusura delle urne.

        Returns:
            sigma = hash_and_sign(sk_E, rho)  (bytes, RSA-PSS)
        """
        sigma = hash_and_sign(self._sk_E, rho)
        print(f"[{self.name}] rho firmata: {rho.hex()[:24]}…")
        return sigma

    def certify(self, results: dict) -> bytes:
        """
        Firma il verbale finale.

        Args:
            results: dizionario {candidato: voti}.

        Returns:
            sigma = hash_and_sign(sk_E, verbale_bytes)  (bytes, RSA-PSS)
        """
        verbale_bytes = str(sorted(results.items())).encode()
        sigma = hash_and_sign(self._sk_E, verbale_bytes)
        print(f"[{self.name}] Verbale certificato.")
        return sigma

    # ------------------------------------------------------------------ #
    # Verifica pubblica                                                    #
    # ------------------------------------------------------------------ #

    def verify_signature(self, message: bytes, sigma: bytes) -> bool:
        """Verifica una firma emessa da questa authority con hash_and_verify."""
        return hash_and_verify(self.pk_E, message, sigma)

    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        return (
            f"ElectoralAuthority(name={self.name!r}, "
            f"dissolved={self._dissolved}, "
            f"election_ready={self._sk_elec is not None})"
        )


# ------------------------------------------------------------------ #
# Utilità interna                                                       #
# ------------------------------------------------------------------ #

def _params_canonical_bytes(params: dict) -> bytes:
    """
    Serializzazione deterministica di Params (esclude sigma_E).
    Usata sia per la firma che per la verifica.
    """
    p = {k: v for k, v in params.items() if k != "sigma_E"}
    return str(sorted(p.items())).encode()
