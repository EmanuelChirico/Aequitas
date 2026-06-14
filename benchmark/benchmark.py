#!/usr/bin/env python3
"""
benchmark.py — Banco di prova prestazionale per Aequitas (WP4).

Scenario simulato: elezione con N_VOTERS = 1000 elettori.

Sezioni:
  1. Costo computazionale delle primitive crittografiche
  2. Dimensione dei messaggi scambiati
  3. Latenza scomposta delle operazioni di verifica
  4. Scalabilita': freeze + tally al variare di N

Uso (dalla root del repo):
    python benchmark/benchmark.py
    python benchmark/benchmark.py --reps 100
    python benchmark/benchmark.py --latex
"""

import argparse
import hashlib
import json
import os
import secrets
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from config import N_TRUSTEES, T, SHARE_BYTES   # noqa: E402
from crypto.rsa_utils import (                   # noqa: E402
    gen_rsa_keypair, oaep_encrypt, oaep_decrypt,
    hash_and_sign, hash_and_verify,
)
from crypto import shamir                        # noqa: E402
from crypto.merkle import MerkleTree             # noqa: E402
from crypto.oaep_decode import decode_oaep, InvalidOAEP  # noqa: E402

N_VOTERS = 1000


# ---------------------------------------------------------------------------
# Cronometro
# ---------------------------------------------------------------------------
def bench(label, op, reps, warmup=3):
    """Esegue op() reps volte, scartando warmup run iniziali."""
    for _ in range(warmup):
        op()
    samples = []
    for _ in range(reps):
        t0 = time.perf_counter()
        op()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {
        "label": label,
        "mean":  statistics.mean(samples),
        "stdev": statistics.stdev(samples) if len(samples) > 1 else 0.0,
    }


# ---------------------------------------------------------------------------
# 1. Costo primitive crittografiche
# ---------------------------------------------------------------------------
def bench_primitives(reps):
    sk = gen_rsa_keypair()
    pk = sk.public_key()
    pub = pk.public_numbers()

    m = b"Lista A - Mario Rossi\x00" * 2
    C = oaep_encrypt(pk, m)
    token_R = secrets.token_bytes(32)
    sig = hash_and_sign(sk, token_R)

    d = sk.private_numbers().d
    shares = shamir.split(d, N_TRUSTEES, T)
    sub_shares = [(i + 1, shares[i]) for i in range(T)]

    leaves = [secrets.token_bytes(32) for _ in range(N_VOTERS)]
    tree = MerkleTree(leaves)
    root = tree.root()
    prf = tree.proof(0)

    C_int = int.from_bytes(C, "big")
    m_prime = pow(C_int, d, pub.n)

    S_i = shares[0].to_bytes(SHARE_BYTES, "big")
    r_i = secrets.token_bytes(32)
    c_i = hashlib.sha256(S_i + r_i).digest()

    return [
        bench("RSA-2048 keygen",
              lambda: gen_rsa_keypair(),                            max(5, reps // 5)),
        bench("OAEP encrypt (voto)",
              lambda: oaep_encrypt(pk, m),                         reps),
        bench("OAEP decrypt",
              lambda: oaep_decrypt(sk, C),                         reps),
        bench("RSA-PSS sign (accredit IAP)",
              lambda: hash_and_sign(sk, token_R),                  reps),
        bench("RSA-PSS verify (VBR)",
              lambda: hash_and_verify(pk, token_R, sig),           reps),
        bench(f"Shamir split (t={T}, n={N_TRUSTEES})",
              lambda: shamir.split(d, N_TRUSTEES, T),              reps),
        bench("Shamir reconstruct (Lagrange)",
              lambda: shamir.reconstruct(sub_shares),              reps),
        bench(f"Merkle build ({N_VOTERS} foglie)",
              lambda: MerkleTree(leaves),                          max(5, reps // 5)),
        bench("Merkle proof gen",
              lambda: tree.proof(0),                               reps),
        bench("Merkle proof verify",
              lambda: MerkleTree.verify(leaves[0], prf, root),    reps),
        bench("Verifica pubblica dec. (m'^e=C)",
              lambda: pow(m_prime, pub.e, pub.n) == C_int,         reps),
        bench("Verifica impegno trustee (SHA-256)",
              lambda: hashlib.sha256(S_i + r_i).digest() == c_i,  reps),
    ]


# ---------------------------------------------------------------------------
# 2. Dimensione dei messaggi
# ---------------------------------------------------------------------------
def bench_message_sizes():
    sk = gen_rsa_keypair()
    pk = sk.public_key()

    R = secrets.token_bytes(32)
    sigma = hash_and_sign(sk, R)
    m = b"Lista A - Mario Rossi\x00" * 2
    C = oaep_encrypt(pk, m)

    leaves = [secrets.token_bytes(32) for _ in range(N_VOTERS)]
    tree = MerkleTree(leaves)
    prf = tree.proof(0)
    prf_json = json.dumps([(s.hex(), side) for s, side in prf]).encode()

    submit_json = json.dumps({
        "R": R.hex(), "sigma": sigma.hex(), "C": C.hex(),
    }).encode()

    return {
        "R (token accredito)":                    len(R),
        "sigma (firma RSA-PSS)":                  len(sigma),
        "C (voto cifrato OAEP)":                  len(C),
        "submit raw (R + sigma + C)":             len(R) + len(sigma) + len(C),
        "submit JSON (hex)":                      len(submit_json),
        f"prova Merkle ({N_VOTERS} foglie, JSON)": len(prf_json),
    }


# ---------------------------------------------------------------------------
# 3. Latenza verifiche
# ---------------------------------------------------------------------------
def bench_verifications(reps):
    sk = gen_rsa_keypair()
    pk = sk.public_key()
    pub = pk.public_numbers()

    R = secrets.token_bytes(32)
    sig = hash_and_sign(sk, R)

    m = b"Lista A - Mario Rossi\x00" * 2
    C = oaep_encrypt(pk, m)
    C_int = int.from_bytes(C, "big")
    m_prime = pow(C_int, sk.private_numbers().d, pub.n)

    leaves = [secrets.token_bytes(32) for _ in range(N_VOTERS)]
    tree = MerkleTree(leaves)
    root = tree.root()
    prf = tree.proof(0)

    S_i = secrets.token_bytes(SHARE_BYTES)
    r_i = secrets.token_bytes(32)
    c_i = hashlib.sha256(S_i + r_i).digest()

    return [
        bench("Firma IAP su R (VBR)",
              lambda: hash_and_verify(pk, R, sig),                  reps),
        bench(f"Inclusione Merkle ({N_VOTERS} foglie)",
              lambda: MerkleTree.verify(leaves[0], prf, root),      reps),
        bench("Verifica pubblica dec. (m'^e=C)",
              lambda: pow(m_prime, pub.e, pub.n) == C_int,          reps),
        bench("Impegno share trustee (SHA-256)",
              lambda: hashlib.sha256(S_i + r_i).digest() == c_i,   reps),
    ]


# ---------------------------------------------------------------------------
# 4. Scalabilita' freeze + tally
# ---------------------------------------------------------------------------
def bench_scalability(sizes=(10, 50, 100, 500, 1000)):
    sk = gen_rsa_keypair()
    pk = sk.public_key()
    pub = pk.public_numbers()
    d = sk.private_numbers().d
    k = pub.n.bit_length() // 8

    results = []
    for N in sizes:
        # Prepara N triple (R, sigma, C) fuori dal timer
        triples = [
            (secrets.token_bytes(32),
             hash_and_sign(sk, secrets.token_bytes(32)),
             oaep_encrypt(pk, f"Cand{i % 5}".encode()))
            for i in range(N)
        ]

        # Freeze reale: sort per R + SHA256(R||sigma||C) per ogni tripla + build tree
        t0 = time.perf_counter()
        triples.sort(key=lambda t: t[0])
        leaves = [hashlib.sha256(r + s + c).digest() for r, s, c in triples]
        tree = MerkleTree(leaves)
        _ = tree.root()
        freeze_ms = (time.perf_counter() - t0) * 1000.0

        # Tally reale: pow(C,d,N) + verifica pubblica pow(m',e,N)==C + decode_oaep
        t0 = time.perf_counter()
        for _, _, c in triples:
            C_int = int.from_bytes(c, "big")
            m_prime = pow(C_int, d, pub.n)
            assert pow(m_prime, pub.e, pub.n) == C_int
            try:
                decode_oaep(m_prime, k)
            except InvalidOAEP:
                pass  # scheda nulla
        tally_ms = (time.perf_counter() - t0) * 1000.0

        results.append((N, freeze_ms, tally_ms))
    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_timing(title, rows, latex):
    print(f"\n== {title} ==")
    if latex:
        for r in rows:
            print(f"{r['label']} & {r['mean']:.3f} & {r['stdev']:.3f} \\\\")
    else:
        print(f"{'Operazione':<48} {'media':>9} {'stdev':>8}  (ms)")
        for r in rows:
            print(f"{r['label']:<48} {r['mean']:>9.3f} {r['stdev']:>8.3f}")


def print_sizes(data, latex):
    print("\n== Dimensione messaggi (byte) ==")
    for name, b in data.items():
        print(f"{name} & {b} \\\\" if latex else f"{name:<50} {b:>7} B")


def print_scalability(results, latex):
    print("\n== Scalabilita': freeze + tally ==")
    if latex:
        for N, fr, ta in results:
            print(f"{N} & {fr:.2f} & {ta:.2f} & {ta/N:.3f} \\\\")
    else:
        print(f"{'N':<7} {'freeze':>10} {'tally':>10} {'tally/voto':>12}  (ms)")
        for N, fr, ta in results:
            print(f"{N:<7} {fr:>10.2f} {ta:>10.2f} {ta/N:>12.3f}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=50)
    ap.add_argument("--latex", action="store_true")
    args = ap.parse_args()

    print(f"# Aequitas WP4 benchmark — {args.reps} reps, {N_VOTERS} elettori simulati\n")
    print_timing("1. Costo primitive crittografiche", bench_primitives(args.reps), args.latex)
    print_sizes(bench_message_sizes(), args.latex)
    print_timing("3. Latenza verifiche", bench_verifications(args.reps), args.latex)
    print_scalability(bench_scalability(), args.latex)
