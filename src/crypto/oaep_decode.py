"""
Decodifica manuale del padding OAEP (§7.2).

Lo spoglio calcola la pre-immagine raw m' = pow(C, d, N) e la pubblica,
rendendo la decifratura verificabile: chiunque controlla pow(m', e, N) == C
con la sola chiave pubblica. Per estrarre il voto da m' è necessario
rimuovere il padding OAEP manualmente, poiché hazmat non espone la
decodifica del solo padding.

Struttura OAEP (RFC 8017 §7.1.2), con k = dimensione chiave in byte:

    EM = 0x00 || maskedSeed || maskedDB
         ────   ────────────   ────────────────────────────────
         1 B     hLen byte     k - hLen - 1 byte

    seed    = maskedSeed XOR MGF1(maskedDB, hLen)
    DB      = maskedDB   XOR MGF1(seed, k - hLen - 1)
    DB      = lHash || 0x00...0x00 || 0x01 || messaggio
              ──────   ───────────   ──────   ─────────
              hLen B    padding       1 B      payload

    lHash   = SHA256(b"")   (label vuota, come usato da hazmat)
    hLen    = 32            (SHA-256)

Parametri OAEP usati ovunque nel prototipo: SHA-256 sia come hash sia in MGF1,
label vuota. Compatibile con oaep_encrypt di rsa_utils.py.
"""

import hashlib
import struct

# Costanti OAEP
H_LEN = 32                                    # lunghezza digest SHA-256 in byte
L_HASH = hashlib.sha256(b"").digest()         # SHA256(label vuota)


class InvalidOAEP(Exception):
    """Padding OAEP non valido: la scheda viene conteggiata come nulla."""


def _mgf1(seed: bytes, length: int) -> bytes:
    """
    Mask Generation Function 1 con SHA-256 (RFC 8017, Appendice B.2.1).

    Produce `length` byte pseudo-casuali dalla seed:
      T = SHA256(seed || 0x00000000) || SHA256(seed || 0x00000001) || ...
    tronca a `length` byte.
    """
    t = b""
    for counter in range(-(-length // H_LEN)):   # ceil(length / H_LEN)
        c = struct.pack(">I", counter)            # counter a 4 byte big-endian
        t += hashlib.sha256(seed + c).digest()
    return t[:length]


def decode_oaep(m_prime: int, k: int) -> bytes:
    """
    Decodifica il padding OAEP dalla pre-immagine raw m' (intero).

    Args:
        m_prime: pre-immagine raw, risultato di pow(C_int, d, N).
        k:       dimensione della chiave RSA in byte (es. 256 per RSA-2048).

    Returns:
        Il messaggio originale (bytes).

    Raises:
        InvalidOAEP: se la struttura OAEP non è valida (→ scheda nulla).
    """
    # Passo 1: converti m' in EM di esattamente k byte (con eventuale zero iniziale)
    try:
        EM = m_prime.to_bytes(k, "big")
    except OverflowError:
        raise InvalidOAEP("m' non sta in k byte")

    # Passo 2: verifica il byte iniziale
    if EM[0] != 0x00:
        raise InvalidOAEP("Primo byte di EM non è 0x00")

    # Passo 3: separa maskedSeed e maskedDB
    masked_seed = EM[1 : 1 + H_LEN]
    masked_db   = EM[1 + H_LEN :]

    # Passo 4: recupera seed e DB
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1(masked_db, H_LEN)))
    db   = bytes(a ^ b for a, b in zip(masked_db,   _mgf1(seed, k - H_LEN - 1)))

    # Passo 5: verifica lHash
    if db[:H_LEN] != L_HASH:
        raise InvalidOAEP("lHash non corrisponde (label sbagliata o corruzione)")

    # Passo 6: attraversa il padding di zeri fino al byte 0x01
    rest = db[H_LEN:]
    sep_idx = rest.find(0x01)
    if sep_idx == -1:
        raise InvalidOAEP("Separatore 0x01 non trovato in DB")
    if any(b != 0x00 for b in rest[:sep_idx]):
        raise InvalidOAEP("Padding non composto interamente da 0x00")

    return rest[sep_idx + 1:]
