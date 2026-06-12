"""
IAP — Identity and Authentication Provider (§4.3).

Responsabilità:
  - Wrappa il flusso Authlib/Google OIDC (Authorization Code Flow).
    Google fa da surrogato di SPID: nel sistema reale ci sarebbe SPID;
    nel prototipo l'OP è Google. L'attributo identificativo estratto
    dall'ID Token (email o claim `sub`) fa le veci del codice fiscale.
  - Mantiene `liste_elettorali` (set di identità ammesse) e il registro
    degli accreditati `Acc`.
  - accredit(identity, R): controlla ammissibilità e unicità, firma R con
    hash_and_sign(sk_IAP, R), restituisce AVP = (R, sigma).

NOTA DI SICUREZZA (per l'esame):
  Il token R (32 byte casuali) lo genera il client, non lo IAP.
  Questo protegge la privacy: lo IAP sa CHI ha votato ma non QUANDO
  (il voto viene inoltrato con un ritardo casuale δ dal client).
"""

import threading
from dataclasses import dataclass, field
from typing import Optional

from config import LAMBDA
from crypto.rsa_utils import gen_rsa_keypair, hash_and_sign, hash_and_verify


@dataclass
class IAP:
    liste_elettorali: set = field(default_factory=set)

    _sk_IAP: object = field(init=False, repr=False)
    _Acc: set       = field(default_factory=set, init=False, repr=False)
    _lock: object   = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self._sk_IAP = gen_rsa_keypair(LAMBDA)

    # ------------------------------------------------------------------ #
    # Proprietà pubbliche                                                  #
    # ------------------------------------------------------------------ #

    @property
    def pk_IAP(self):
        """Chiave pubblica IAP (inclusa in Params; usata dal VBR per verificare sigma)."""
        return self._sk_IAP.public_key()

    @property
    def accreditati(self) -> frozenset:
        """Snapshot del registro accreditati (sola lettura)."""
        return frozenset(self._Acc)

    # ------------------------------------------------------------------ #
    # §4.3 — Accreditamento                                                #
    # ------------------------------------------------------------------ #

    def accredit(self, identity: str, R: bytes) -> tuple[bytes, int]:
        """
        Accredita il votante e firma il token R.

        Controlla atomicamente:
          1. identity in liste_elettorali  (è un elettore ammesso?)
          2. identity not in Acc           (non ha già votato?)
        Se entrambe le condizioni sono soddisfatte aggiunge identity ad Acc
        e restituisce AVP = (R, sigma) dove sigma = hash_and_sign(sk_IAP, R).

        Args:
            identity: stringa identificativa estratta dall'ID Token Google
                      (email o claim `sub`).
            R:        token casuale generato dal client (32 byte).

        Returns:
            (R, sigma)  ← AVP da presentare al VBR.

        Raises:
            PermissionError: se identity non è in lista o ha già votato.
        """
        with self._lock:
            if identity not in self.liste_elettorali:
                raise PermissionError(
                    f"Identità '{identity}' non presente nelle liste elettorali"
                )
            if identity in self._Acc:
                raise PermissionError(
                    f"Identità '{identity}' ha già ricevuto un accreditamento"
                )
            # Registra prima di firmare (operazione atomica grazie al lock)
            self._Acc.add(identity)

        sigma = hash_and_sign(self._sk_IAP, R)
        return R, sigma

    # ------------------------------------------------------------------ #
    # Verifica (usata dal VBR)                                             #
    # ------------------------------------------------------------------ #

    def verify(self, R: bytes, sigma: int) -> bool:
        """Verifica la firma IAP su R (delegabile al VBR con la pk_IAP pubblica)."""
        return hash_and_verify(self.pk_IAP, R, sigma)

    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        return (
            f"IAP(liste_elettorali={len(self.liste_elettorali)}, "
            f"accreditati={len(self._Acc)})"
        )
