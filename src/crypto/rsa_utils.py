"""
Primitive RSA usate nel protocollo Aequitas.

Funzioni esportate:
  gen_rsa_keypair   — generazione coppia RSA
  oaep_encrypt      — cifratura RSA-OAEP (lato votante e IAP→trustee)
  oaep_decrypt      — decifratura RSA-OAEP (solo per verifica, NON per lo spoglio)
  hash_and_sign     — firma textbook: sigma = SHA256(m)^d mod N  (§7.1)
  hash_and_verify   — verifica firma

Nota sulla firma (§7.1):
  Si firma il digest SHA-256 del messaggio, non il messaggio grezzo.
  Con RSA textbook su un messaggio senza struttura chiunque potrebbe
  scegliere sigma a caso e calcolare il messaggio corrispondente a ritroso.
  Firmare il digest elimina questa vulnerabilità perché SHA-256 è
  pre-image resistant.

Nota sullo spoglio (§7.2):
  La decifratura dei voti avviene nella TallyMachine con RSA raw (pow) +
  decode_oaep manuale, NON con oaep_decrypt di questa funzione.
  Questo rende la decifratura verificabile: chiunque controlla
  pow(m', e, N) == C con la sola chiave pubblica.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa

from config import LAMBDA


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def gen_rsa_keypair(key_size: int = LAMBDA):
    """Genera e restituisce una chiave privata RSA con esponente pubblico 65537."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


# ------------------------------------------------------------------ #
# RSA-OAEP                                                            #
# ------------------------------------------------------------------ #

def oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    """Cifra plaintext con RSA-OAEP (SHA-256 / MGF1-SHA-256, label vuota)."""
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    """
    Decifra con RSA-OAEP.
    Usare SOLO per operazioni non-tally (es. verifica da VoterClient).
    Lo spoglio usa pow(C, d, N) + decode_oaep manuale (§7.2).
    """
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ------------------------------------------------------------------ #
# Hash-and-sign (§7.1)                                                #
# ------------------------------------------------------------------ #

def hash_and_sign(private_key, message: bytes) -> int:
    """
    sigma = int(SHA256(message))^d mod N

    Restituisce un intero (dimensione: modulo N, es. 256 byte per RSA-2048).
    """
    digest = sha256(message)
    m_int = int.from_bytes(digest, "big")
    nums = private_key.private_numbers()
    return pow(m_int, nums.d, nums.public_numbers.n)


def hash_and_verify(public_key, message: bytes, sigma: int) -> bool:
    """
    Verifica: pow(sigma, e, N) == int(SHA256(message)).
    """
    digest_int = int.from_bytes(sha256(message), "big")
    pub = public_key.public_numbers()
    return pow(sigma, pub.e, pub.n) == digest_int
