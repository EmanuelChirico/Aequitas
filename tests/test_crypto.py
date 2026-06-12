"""
Test obbligatori (§8 del brief).

Copertura:
  1. Round-trip OAEP: encrypt → pow raw → decode_oaep == plaintext  (§7.2.3)
  2. Shamir split/reconstruct con t su n share                       (§7.3)
  3. Merkle proof: leaf verificata, leaf sbagliata rigettata         (§7.4)
  4. Hash-and-sign: sign/verify round-trip                          (§7.1)
  5. Doppio voto: rigetto con C diverso, idempotenza con C identico  (§4.4)
  6. Trustee disonesto: share scartata dalla TM                      (§8.2)

Per eseguire:
    cd <project_root>
    python -m pytest tests/ -v
"""

import hashlib
import os
import sys

import pytest

# Rende importabili i moduli src/ senza installare il pacchetto
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from config import N_TRUSTEES, T, SHARE_BYTES
from crypto.merkle import MerkleTree
from crypto.oaep_decode import decode_oaep, InvalidOAEP
from crypto.rsa_utils import (
    gen_rsa_keypair,
    hash_and_sign,
    hash_and_verify,
    oaep_encrypt,
)
from crypto.shamir import reconstruct, split
from entities.iap import IAP
from entities.trustee import Trustee
from entities.vbr import VBR


# ---------------------------------------------------------------------------
# Fixture condivisa
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair():
    """Coppia RSA-2048 generata una sola volta per il modulo di test."""
    sk = gen_rsa_keypair()
    return sk, sk.public_key()


# ---------------------------------------------------------------------------
# 1. Round-trip OAEP: encrypt → pow raw → decode_oaep
# ---------------------------------------------------------------------------

def test_oaep_roundtrip(keypair):
    """§7.2.3 — Test obbligatorio: round-trip deve restituire il plaintext."""
    sk, pk = keypair
    plaintext = b"Lista A - Rossi\x00" * 2   # 32 byte

    C_bytes = oaep_encrypt(pk, plaintext)
    C_int   = int.from_bytes(C_bytes, "big")

    nums    = sk.private_numbers()
    pub     = nums.public_numbers
    m_prime = pow(C_int, nums.d, pub.n)
    k       = pub.n.bit_length() // 8  # dimensione chiave in byte

    recovered = decode_oaep(m_prime, k)
    assert recovered == plaintext


def test_oaep_verify_raw(keypair):
    """pow(m', e, N) == C deve valere per qualsiasi ciphertext valido."""
    sk, pk = keypair
    C_bytes = oaep_encrypt(pk, b"test vote payload padded to 64 b"[:32])
    C_int   = int.from_bytes(C_bytes, "big")

    nums    = sk.private_numbers()
    pub     = nums.public_numbers
    m_prime = pow(C_int, nums.d, pub.n)

    assert pow(m_prime, pub.e, pub.n) == C_int


def test_oaep_invalid_raises(keypair):
    """Garbage input deve sollevare InvalidOAEP."""
    _, pk = keypair
    k = pk.public_numbers().n.bit_length() // 8
    with pytest.raises(InvalidOAEP):
        decode_oaep(12345678, k)


# ---------------------------------------------------------------------------
# 2. Shamir split / reconstruct
# ---------------------------------------------------------------------------

def test_shamir_roundtrip_full():
    """Ricostruzione con tutte le n share deve restituire il segreto."""
    secret = 999_999_999_000_000_001
    shares = split(secret, N_TRUSTEES, T)
    indexed = list(enumerate(shares, start=1))
    assert reconstruct(indexed) == secret


def test_shamir_threshold():
    """Ricostruzione con esattamente T share deve funzionare."""
    secret = 2**512 - 1
    shares = split(secret, N_TRUSTEES, T)
    subset = [(i + 1, shares[i]) for i in range(T)]
    assert reconstruct(subset) == secret


def test_shamir_below_threshold():
    """Con T-1 share la ricostruzione dà un valore sbagliato (non il segreto)."""
    secret = 42
    shares = split(secret, N_TRUSTEES, T)
    subset = [(i + 1, shares[i]) for i in range(T - 1)]
    wrong  = reconstruct(subset)
    assert wrong != secret


# ---------------------------------------------------------------------------
# 3. Merkle tree + prove di inclusione
# ---------------------------------------------------------------------------

def test_merkle_proof_valid():
    """La prova Merkle per una foglia presente deve essere verificata."""
    leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(5)]
    tree   = MerkleTree(leaves)
    rho    = tree.root()

    for idx in range(len(leaves)):
        proof = tree.proof(idx)
        assert MerkleTree.verify(leaves[idx], proof, rho), f"Prova fallita per foglia {idx}"


def test_merkle_proof_wrong_leaf():
    """La prova di una foglia NON presente deve fallire."""
    leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(4)]
    tree   = MerkleTree(leaves)
    rho    = tree.root()

    fake_leaf = hashlib.sha256(b"impostor").digest()
    proof     = tree.proof(0)
    assert not MerkleTree.verify(fake_leaf, proof, rho)


def test_merkle_odd_leaves():
    """Con numero dispari di foglie l'albero deve comunque funzionare."""
    leaves = [hashlib.sha256(f"x{i}".encode()).digest() for i in range(7)]
    tree   = MerkleTree(leaves)
    proof  = tree.proof(6)   # ultima foglia (sarà duplicata internamente)
    assert MerkleTree.verify(leaves[6], proof, tree.root())


# ---------------------------------------------------------------------------
# 4. Hash-and-sign round-trip
# ---------------------------------------------------------------------------

def test_hash_and_sign_verify(keypair):
    """Firma e verifica su messaggio arbitrario."""
    sk, pk = keypair
    msg   = b"verbale finale della commissione elettorale"
    sigma = hash_and_sign(sk, msg)
    assert hash_and_verify(pk, msg, sigma)


def test_hash_and_sign_wrong_message(keypair):
    """Firma su messaggio diverso non deve essere verificata."""
    sk, pk = keypair
    sigma  = hash_and_sign(sk, b"msg originale")
    assert not hash_and_verify(pk, b"msg alterato", sigma)


# ---------------------------------------------------------------------------
# 5. Doppio voto: rigetto e idempotenza
# ---------------------------------------------------------------------------

@pytest.fixture
def vbr_with_iap():
    iap = IAP(liste_elettorali={"voter@test.com"})
    vbr = VBR(pk_IAP=iap.pk_IAP)
    return vbr, iap


def test_double_vote_reject(vbr_with_iap, keypair):
    """Stesso R con C diverso deve essere rifiutato (doppio voto)."""
    import secrets
    vbr, iap = vbr_with_iap
    sk, pk   = keypair

    R      = secrets.token_bytes(32)
    _, sigma = iap.accredit("voter@test.com", R)

    C1 = oaep_encrypt(pk, b"Lista A - Rossi\x00" * 2)
    C2 = oaep_encrypt(pk, b"Lista B - Verdi\x00" * 2)

    vbr.submit(R, sigma, C1)

    with pytest.raises(PermissionError, match="Doppio voto"):
        vbr.submit(R, sigma, C2)


def test_idempotent_resubmit(vbr_with_iap, keypair):
    """Stesso (R, C) ritrasmesso deve restituire la ricevuta originale."""
    import secrets
    vbr, iap = vbr_with_iap
    sk, pk   = keypair

    R        = secrets.token_bytes(32)
    _, sigma = iap.accredit("voter@test.com", R)
    C        = oaep_encrypt(pk, b"Lista A - Rossi\x00" * 2)

    h1 = vbr.submit(R, sigma, C)
    h2 = vbr.submit(R, sigma, C)   # ritrasmissione identica
    assert h1 == h2


# ---------------------------------------------------------------------------
# 6. Trustee disonesto: share scartata
# ---------------------------------------------------------------------------

def test_dishonest_trustee_detected():
    """Un trustee con dishonest=True deve essere smascherato dal confronto impegni."""
    import secrets as sec
    from config import Q, SHARE_BYTES

    # Prepara un segreto, una share e il relativo impegno
    S_i = sec.randbelow(Q)
    r_i = sec.token_bytes(32)
    c_i = hashlib.sha256(S_i.to_bytes(SHARE_BYTES, "big") + r_i).digest()

    t = Trustee(trustee_id=1, name="Furbetto", dishonest=True)
    t.set_commitment(c_i)
    t.receive_share(S_i, r_i)   # riceve la share corretta…

    S_rivelata, r_rivelata = t.reveal()   # …ma rivela S_i+1
    c_calcolata = hashlib.sha256(
        S_rivelata.to_bytes(SHARE_BYTES, "big") + r_rivelata
    ).digest()

    # La TM ricalcola l'impegno e trova la discrepanza
    assert c_calcolata != c_i, "Il trustee disonesto non è stato smascherato"
