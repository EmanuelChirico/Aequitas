"""
Shamir Secret Sharing implementato a mano (§7.3).

Campo finito: Z_Q dove Q = 2^2281 - 1 (primo di Mersenne).
  - Q > d per qualsiasi d prodotto da RSA-2048, quindi il segreto sta nel campo.
  - Usare un Mersenne noto evita di implementare test di primalità.

Funzioni:
  split(d, n, t)              → [S_1, ..., S_n]   (share come interi)
  reconstruct(indexed_shares) → d                  (da ≥ t coppie (i, S_i))
"""

import secrets

from config import Q, T, N_TRUSTEES


def _poly_eval(coefficients: list[int], x: int) -> int:
    """Valuta il polinomio sum(a_k * x^k) mod Q con la regola di Horner."""
    v = 0
    for coeff in reversed(coefficients):
        v = (v * x + coeff) % Q
    return v


def split(d: int, n: int = N_TRUSTEES, t: int = T) -> list[int]:
    """
    Divide il segreto d in n share con soglia t.

    Costruisce un polinomio f di grado t-1 con f(0) = d e
    coefficienti a_1..a_{t-1} casuali in Z_Q.
    Restituisce [S_1, ..., S_n] dove S_i = f(i) mod Q.
    L'indice i (1-based) è l'ascissa implicita della share.

    Args:
        d: segreto (esponente privato RSA), deve essere in [0, Q).
        n: numero di share da produrre.
        t: soglia minima per la ricostruzione.
    """
    if not (0 <= d < Q):
        raise ValueError(f"Il segreto deve essere in [0, Q); d ha {d.bit_length()} bit")
    if t > n:
        raise ValueError("La soglia t non può superare il numero di share n")

    # Polinomio: f(x) = d + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
    coefficients = [d] + [secrets.randbelow(Q) for _ in range(t - 1)]
    return [_poly_eval(coefficients, i) for i in range(1, n + 1)]


def reconstruct(indexed_shares: list[tuple[int, int]]) -> int:
    """
    Ricostruisce il segreto d da ≥ t coppie (i, S_i) tramite
    interpolazione di Lagrange valutata in x = 0.

        d = f(0) = sum_i S_i * L_i(0)   mod Q

    dove L_i(0) = prod_{j≠i} (-x_j) / (x_i - x_j)  mod Q.

    Usa pow(x, -1, Q) (Python 3.8+) per l'inverso modulare.

    Args:
        indexed_shares: lista di (x_i, S_i) con x_i = trustee_id (1-based).
    """
    secret = 0
    for i, (xi, Si) in enumerate(indexed_shares):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(indexed_shares):
            if i != j:
                num = (num * (-xj)) % Q
                den = (den * (xi - xj)) % Q
        # L_i(0) = num * den^{-1} mod Q
        lagrange_i = Si * num % Q * pow(den, -1, Q) % Q
        secret = (secret + lagrange_i) % Q
    return secret
