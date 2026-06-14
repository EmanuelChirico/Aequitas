# Shamir Secret Sharing - schema (t, n)
# usiamo Z_Q con Q = 2^2281 - 1 (primo di Mersenne) cosi' il segreto RSA ci sta dentro
# split -> lista di n share (interi)
# reconstruct -> segreto originale da almeno t share

import secrets
from config import Q, T, N_TRUSTEES


def _eval_poly(coeffs, x):
    # calcola f(x) mod Q 
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % Q
    return result


def split(d, n=N_TRUSTEES, t=T):
    # costruisce un polinomio casuale di grado t-1 con termine noto d
    # e poi valuta in 1, 2, ..., n per ottenere le share
    if not (0 <= d < Q):
        raise ValueError(f"segreto fuori range, d ha {d.bit_length()} bit")
    if t > n:
        raise ValueError("soglia t maggiore del numero di share n")

    # f(x) = d + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    coeffs = [d] + [secrets.randbelow(Q) for _ in range(t - 1)]
    shares = [_eval_poly(coeffs, i) for i in range(1, n + 1)]
    return shares


def reconstruct(indexed_shares):
    # interpolazione di Lagrange in x=0 per recuperare f(0) = d
    # ogni share e' una coppia (i, S_i) dove i e' l'indice del trustee (parte da 1)
    secret = 0
    for i, (xi, si) in enumerate(indexed_shares):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(indexed_shares):
            if i == j:
                continue
            num = (num * (-xj)) % Q
            den = (den * (xi - xj)) % Q
        # coefficiente di Lagrange: L_i(0) = num / den mod Q
        li = si * num % Q * pow(den, -1, Q) % Q
        secret = (secret + li) % Q
    return secret
