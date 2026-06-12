"""
benchmark.py — misure di prestazione per il WP4 (§8.4).

Simula M votanti sintetici senza passare dal layer web e misura:
  - Throughput di VBR.submit() (voti/secondo)
  - Tempo totale dello spoglio (TallyMachine.tally): atteso il collo di
    bottiglia, poiché ogni decifratura richiede un'esponenziazione modulare
    RSA-2048 → costo O(M · k^3) dove k è la dimensione del blocco.
  - Tempo della verifica universale (MerkleTree rebuild + controlli)

Utilizzo:
    python benchmark.py [100 | 1000 | 10000]
    python benchmark.py all     ← esegue tutte e tre le dimensioni
    python benchmark.py         ← default: 100

Output: tabella su stdout + CSV in benchmark_results.csv
"""

import csv
import os
import secrets
import sys
import time

# Aggiunge src/ al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from config import N_TRUSTEES, T
from crypto.rsa_utils import gen_rsa_keypair, oaep_encrypt, hash_and_sign
from entities.electoral_auth import ElectoralAuthority
from entities.iap import IAP
from entities.tally_machine import TallyMachine
from entities.trustee import Trustee
from entities.vbr import VBR


def _setup_entities(M: int):
    """Prepara le entità del protocollo e genera M coppie (R, C) sintetiche."""

    # Istanzia le entità
    e  = ElectoralAuthority(name="BenchmarkAuthority")
    iap = IAP(liste_elettorali={f"voter{i}@bench.test" for i in range(M)})
    vbr = VBR(pk_IAP=iap.pk_IAP)
    tm  = TallyMachine()
    trustees = [Trustee(trustee_id=i + 1, name=f"T{i+1}") for i in range(N_TRUSTEES)]

    params = e.setup(pk_iap=iap.pk_IAP, vbr=vbr)
    e.distribute_shares(trustees)
    e.dissolve()

    pk_elec = None   # pk_elec è ora accessibile via params
    from crypto.rsa_utils import gen_rsa_keypair
    # Ricrea pk_elec dai parametri pubblicati (come farebbe un osservatore esterno)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    pub_nums = params["pk_elec"]
    pk_elec_raw = RSAPublicNumbers(
        e=pub_nums["e"], n=pub_nums["n"]
    ).public_key()

    # Genera M voti sintetici
    votes = []
    candidati_flat = ["Lista A - Rossi", "Lista A - Bianchi",
                      "Lista B - Verdi", "Lista B - Neri"]
    for i in range(M):
        identity = f"voter{i}@bench.test"
        R = secrets.token_bytes(32)
        _, sigma = iap.accredit(identity, R)
        v = candidati_flat[i % len(candidati_flat)]
        # Payload a lunghezza fissa (64 B)
        import json
        payload = json.dumps({"election_id": "bench", "vote": v})
        padded  = payload.encode().ljust(64, b"\x00")
        C = oaep_encrypt(pk_elec_raw, padded)
        votes.append((R, sigma, C))

    return e, vbr, tm, trustees, pk_elec_raw, votes


def run_benchmark(M: int) -> dict:
    print(f"\n{'='*55}")
    print(f"  Benchmark M = {M} votanti")
    print(f"{'='*55}")

    print(f"  [1/4] Setup + generazione {M} voti sintetici…")
    t0 = time.perf_counter()
    e, vbr, tm, trustees, pk_elec, votes = _setup_entities(M)
    t_setup = time.perf_counter() - t0
    print(f"        Setup completato in {t_setup:.2f} s")

    # ---- VBR.submit throughput ----
    print(f"  [2/4] Invio {M} voti al VBR…")
    t0 = time.perf_counter()
    for R, sigma, C in votes:
        vbr.submit(R, sigma, C)
    t_submit = time.perf_counter() - t0
    throughput = M / t_submit if t_submit > 0 else float("inf")
    print(f"        submit: {t_submit:.3f} s  ({throughput:.0f} voti/s)")

    # ---- Freeze + spoglio ----
    print("  [3/4] Freeze + spoglio (collo di bottiglia atteso)…")
    t0 = time.perf_counter()
    rho       = vbr.freeze()
    rho_sigma = e.freeze_and_sign(rho)
    tm.load_uvc(vbr, e.pk_E)
    tm.set_rho_signature(rho_sigma, e.pk_E)
    commitments = e.commitments
    tm.collect_shares(trustees, commitments)
    tm.reconstruct_key(pk_elec)
    results, _ = tm.tally(pk_elec)
    tm.destroy_key()
    t_tally = time.perf_counter() - t0
    print(f"        Spoglio: {t_tally:.3f} s  ({M/t_tally:.0f} voti/s)")
    print(f"        Risultati: {results}")

    # ---- Verifica universale ----
    print("  [4/4] Verifica universale…")
    from web.app import _verifica_universale
    import json
    e.certify(results)
    results_sigma = e.certify(results)
    vbr.publish(
        rho_sigma=rho_sigma,
        pre_images=tm.pre_images,
        results=results,
        results_sigma=results_sigma,
        path=f"benchmark_bulletin_{M}.json",
    )
    t0 = time.perf_counter()
    with open(f"benchmark_bulletin_{M}.json") as f:
        bull = json.load(f)
    verifica = _verifica_universale(bull)
    t_verifica = time.perf_counter() - t0
    ok = all(verifica.values())
    print(f"        Verifica: {t_verifica:.3f} s  — {'OK ✓' if ok else 'FALLITA ✗'}")

    return {
        "M":              M,
        "t_setup_s":      round(t_setup, 3),
        "t_submit_s":     round(t_submit, 3),
        "throughput_vps": round(throughput, 1),
        "t_tally_s":      round(t_tally, 3),
        "t_verifica_s":   round(t_verifica, 3),
        "verifica_ok":    ok,
    }


def print_table(rows: list[dict]) -> None:
    cols = ["M", "t_setup_s", "t_submit_s", "throughput_vps",
            "t_tally_s", "t_verifica_s", "verifica_ok"]
    widths = [max(len(c), max(len(str(r[c])) for r in rows)) for c in cols]
    sep = "  ".join("-" * w for w in widths)
    hdr = "  ".join(c.ljust(w) for c, w in zip(cols, widths))
    print(f"\n{'='*len(sep)}")
    print("RIEPILOGO BENCHMARK")
    print(sep)
    print(hdr)
    print(sep)
    for r in rows:
        print("  ".join(str(r[c]).ljust(w) for c, w in zip(cols, widths)))
    print(sep)


def save_csv(rows: list[dict], path: str = "benchmark_results.csv") -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nRisultati CSV salvati in {path}")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "100"
    if arg == "all":
        sizes = [100, 1000, 10000]
    else:
        try:
            sizes = [int(arg)]
        except ValueError:
            print(f"Argomento non valido: {arg}. Uso: python benchmark.py [100|1000|10000|all]")
            sys.exit(1)

    rows = [run_benchmark(M) for M in sizes]
    print_table(rows)
    save_csv(rows)
