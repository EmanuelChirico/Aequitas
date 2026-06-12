# Aequitas — Secure E-Voting Protocol

**Authors:** Autorino Luigi, Emanuel Chirico  
**Course:** Algoritmi e Protocolli di Sicurezza  
**Institution:** Università degli Studi di Salerno

---

## Overview

Aequitas is a cryptographic protocol for secure digital elections with nominal preference voting. The system implements end-to-end verifiable voting with minimal trust assumptions, enabling municipal-scale elections while preserving voter privacy, ensuring ballot integrity, and providing public verifiability of results.

The project is divided into four Work Packages:

| WP | Title | Content |
|----|-------|---------|
| **WP1** | Threat Modeling & Architecture | Security properties, adversarial models, system actors |
| **WP2** | Protocol Specification | Setup, voting, tallying phases; RSA-OAEP, Shamir SSS, Merkle trees |
| **WP3** | Security Analysis | Threat resilience, parameter selection, residual risks |
| **WP4** | Implementation & Performance | Flask prototype, benchmarks, test suite |

---

## Key Properties

- **Minimal Trust** — Private election key never exists in one place: split via Shamir threshold secret sharing across N trustees.
- **End-to-End Verifiability** — Voters verify their ballot inclusion via personal receipt; external observers validate the full tally cryptographically.
- **Voter Privacy** — Token-based authorization decoupled from preference encryption; temporal decorrelation via random delays.
- **Integrity** — Atomic ballot acceptance prevents double voting; publicly verifiable decryption prevents result manipulation.
- **Scalability** — Lightweight per-ballot validation at submission; heavy computation deferred to post-election tallying.

---

## Repository Structure

```
Aequitas/
├── .env                        # Segreti locali (Google OAuth, admin token) — non versionato
├── requirements.txt
├── docs/                       # Papers (tutti i WP)
├── tests/
│   └── test_crypto.py          # Suite di test sui primitivi crittografici
└── src/
    ├── main.py                 # Entry point: init entità + avvio Flask
    ├── config.py               # Parametri globali di protocollo
    ├── crypto/
    │   ├── rsa_utils.py        # Generazione chiavi, OAEP, hash-and-sign
    │   ├── shamir.py           # Shamir Secret Sharing in Z_Q
    │   ├── merkle.py           # Merkle tree + prove di inclusione
    │   └── oaep_decode.py      # Decodifica manuale padding OAEP
    ├── entities/
    │   ├── electoral_auth.py   # ElectoralAuthority (E)
    │   ├── iap.py              # Identity & Authentication Provider (IAP)
    │   ├── vbr.py              # Verified Ballot Register (VBR)
    │   ├── trustee.py          # Trustee (T_i)
    │   ├── tally_machine.py    # TallyMachine (TM)
    │   └── voter.py            # VoterClient (lato client)
    └── web/
        ├── app.py              # Flask app factory + route handlers
        └── templates/          # Template Jinja2 (index, vote, receipt, results, …)
```

---

## Architecture

Il protocollo coinvolge cinque attori principali che interagiscono in tre fasi.

```
                          ┌──────────────────────────┐
                          │  ElectoralAuthority (E)  │
                          │ - genera (pk_elec, sk_E) │
                          │ - divide d via Shamir    │
                          │ - firma ρ e risultati    │
                          └────────────┬─────────────┘
                    distribuisce S_i   │   pubblica Params
                    ┌──────────────────┼──────────────────┐
             ┌──────▼──────┐           │           ┌──────▼──────┐
             │ Trustee T_1 │   ...     │   ...     │ Trustee T_N │
             │  salva S_i  │           │           │  salva S_i  │
             └─────────────┘           │           └─────────────┘
                                ┌──────▼──────┐
                                │     IAP     │
                                │  accredita  │
                                │  il voter   │
                                └──────┬──────┘
                        AVP=(R,σ_IAP)  │
                                ┌──────▼──────┐
                                │   Voter     │
                                │ cifra voto  │
                                │ con pk_elec │
                                └──────┬──────┘
                              (R,σ,C)  │
                                ┌──────▼──────┐
                                │     VBR     │
                                │ verifica σ  │
                                │ salva (R,C) │
                                │ costruisce  │
                                │ albero Merk.│
                                └──────┬──────┘
                              freeze   │
                                ┌──────▼──────┐
                                │TallyMachine │
                                │raccoglie S_i│
                                │ ricostruisce│
                                │ d, decifra  │
                                │ pubblica    │
                                └─────────────┘
```

---

## Class Reference

### `src/config.py` — Parametri globali

| Costante | Valore | Descrizione |
|----------|--------|-------------|
| `LAMBDA` | 2048 | Dimensione chiave RSA (bit) |
| `T` | 3 | Soglia Shamir (minimo share per ricostruire) |
| `N_TRUSTEES` | 5 | Numero totale di trustee |
| `Q` | 2²²⁸¹ − 1 | Primo di Mersenne (campo finito Shamir) |
| `SHARE_BYTES` | 286 | Dimensione share serializzato |
| `ELECTION_ID` | stringa | Identificativo elezione |
| `CANDIDATI` | dict | Liste e candidati |
| `ADMIN_TOKEN` | stringa | Token chiusura urne (in `.env`) |

---

### `src/entities/electoral_auth.py` — `ElectoralAuthority`

Autorità elettorale. Genera le chiavi, divide il segreto, firma il registro e i risultati.

| Metodo | Firma | Descrizione |
|--------|-------|-------------|
| `setup` | `(pk_iap, vbr) → dict` | Genera `(pk_elec, sk_elec)`, divide `d` con Shamir, pubblica `Params` nel VBR |
| `distribute_shares` | `(trustees) → None` | Consegna `(S_i, r_i)` ad ogni trustee; cancella le share locali |
| `dissolve` | `() → None` | Azzera `sk_elec` e le share (forward secrecy) |
| `freeze_and_sign` | `(rho) → int` | Firma la radice Merkle con `sk_E` |
| `certify` | `(results) → int` | Firma i risultati finali con `sk_E` |
| `verify_signature` | `(message, sigma) → bool` | Verifica una firma con `pk_E` |

**Proprietà:** `pk_E`, `pk_elec`, `commitments`

---

### `src/entities/iap.py` — `IAP`

Identity & Authentication Provider. Accredita i votanti e rilascia token firmati.

| Metodo | Firma | Descrizione |
|--------|-------|-------------|
| `accredit` | `(identity, R) → (R, sigma)` | Verifica identità, firma `R` con `sk_IAP`, aggiunge alla lista degli accreditati (thread-safe) |
| `verify` | `(R, sigma) → bool` | Verifica una firma IAP (delegabile al VBR) |

**Proprietà:** `pk_IAP`, `accreditati`

---

### `src/entities/vbr.py` — `VBR`

Verified Ballot Register. Riceve, valida e custodisce le schede; costruisce l'albero di Merkle.

| Metodo | Firma | Descrizione |
|--------|-------|-------------|
| `submit` | `(R, sigma, C) → h` | Verifica σ IAP, controlla doppio voto, salva `(R, σ, C)`, restituisce `h = SHA256(C)` |
| `freeze` | `() → rho` | Congela il registro, ordina le schede per R, costruisce il `MerkleTree` |
| `inclusion_proof` | `(h) → (index, proof)` | Restituisce la prova di Merkle per una ricevuta |
| `verify_inclusion` | `(h, proof) → bool` | Verifica statica della prova |
| `publish` | `(rho_sigma, pre_images, results, results_sigma, path) → None` | Scrive `bulletin.json` pubblico |

**Proprietà:** `frozen`, `rho`, `registro`

---

### `src/entities/trustee.py` — `Trustee`

Custode di uno share della chiave privata di elezione.

| Metodo | Firma | Descrizione |
|--------|-------|-------------|
| `set_commitment` | `(c_i) → None` | Riceve il commitment `c_i = SHA256(S_i ‖ r_i)` prima della share |
| `receive_share` | `(S_i, r_i) → bool` | Verifica il commitment, salva la share; `ValueError` se non corrisponde |
| `reveal` | `() → (S_i, r_i)` | Restituisce la share durante il tallying (se `dishonest=True` restituisce share alterata) |

---

### `src/entities/tally_machine.py` — `TallyMachine`

Macchina di scrutinio. Raccoglie le share, ricostruisce la chiave, decifra i voti.

| Metodo | Firma | Descrizione |
|--------|-------|-------------|
| `load_uvc` | `(vbr, pk_E) → None` | Carica lo snapshot del VBR congelato |
| `set_rho_signature` | `(rho_sigma, pk_E) → None` | Verifica e salva la firma di E sulla radice Merkle |
| `collect_shares` | `(trustees, commitments) → None` | Raccoglie `(S_i, r_i)` da ogni trustee, scarta share non valide |
| `reconstruct_key` | `(pk_elec) → None` | Interpolazione di Lagrange in `x=0` → `d` |
| `tally` | `(pk_elec) → (results, pre_images)` | Decifra ogni `C`, decodifica OAEP, conta i voti, pubblica le pre-immagini |
| `destroy_key` | `() → None` | Azzera `d` (operazione critica) |

---

### `src/entities/voter.py` — `VoterClient`

Logica lato client del votante.

| Metodo | Firma | Descrizione |
|--------|-------|-------------|
| `make_token` | `() → R` | Genera token casuale di 32 byte |
| `encrypt_vote` | `(v, pk_elec) → (C, h)` | Cifra la preferenza con RSA-OAEP; `h = SHA256(C)` |
| `delay` | `() → None` | Attende un intervallo casuale (decorrelazione temporale) |
| `verify_inclusion` | `(proof, rho, R, sigma, C) → bool` | Verifica la prova di Merkle per la propria scheda |
| `verify_opening` | `(C, m_prime, pk_elec, expected_v) → bool` | Verifica `pow(m', e, N) == C` e decodifica OAEP |

---

### `src/crypto/` — Primitivi crittografici

| Modulo | Funzioni principali |
|--------|---------------------|
| `rsa_utils.py` | `gen_rsa_keypair(size)`, `oaep_encrypt(pk, m)`, `oaep_decrypt(sk, C)`, `hash_and_sign(sk, m)`, `hash_and_verify(pk, m, σ)` |
| `shamir.py` | `split(secret, n, t)`, `reconstruct(indexed_shares)` — aritmetica in Z_Q, Q = 2²²⁸¹−1 |
| `merkle.py` | `MerkleTree(leaves)`, `.root()`, `.proof(index)`, `.verify(leaf, proof, root)` |
| `oaep_decode.py` | `decode_oaep(m_prime, k)` — rimozione manuale del padding OAEP con MGF1-SHA256 |

---

### `src/web/app.py` — Flask App Factory

`create_app(e, iap, vbr, tm, trustees) → Flask`

| Route | Metodo | Descrizione |
|-------|--------|-------------|
| `/` | GET | Homepage — stato urne |
| `/login` | GET | Redirect OAuth → Google |
| `/auth` | GET | Callback OAuth (Authlib) |
| `/logout` | GET | Termina la sessione |
| `/vote` | GET / POST | Modulo di voto; accredita, cifra, sottomette al VBR |
| `/receipt/<h>` | GET | Verifica individuale ricevuta |
| `/bulletin` | GET | Bollettino pubblico |
| `/results` | GET | Risultati + verifica universale (4 controlli) |
| `/admin/close` | POST | Chiude le urne, avvia il tallying completo |

---

## Protocol Flow

```
SETUP
  E.setup()  →  (pk_elec, Params pubblicati nel VBR)
  E.distribute_shares(trustees)
  E.dissolve()  →  sk_elec azzerata

VOTING  (per ogni votante)
  R = VoterClient.make_token()
  (R, σ_IAP) = IAP.accredit(identity, R)
  (C, h) = VoterClient.encrypt_vote(v, pk_elec)
  h = VBR.submit(R, σ_IAP, C)
  → ricevuta h consegnata al votante

TALLYING  (trigger: POST /admin/close)
  ρ = VBR.freeze()
  σ_E(ρ) = E.freeze_and_sign(ρ)
  TM.collect_shares(trustees, commitments)
  TM.reconstruct_key(pk_elec)   →  d ricostruito
  (results, pre_images) = TM.tally(pk_elec)
  TM.destroy_key()              →  d azzerato
  σ_E(results) = E.certify(results)
  VBR.publish(…)                →  bulletin.json

VERIFICATION  (pubblica, chiunque)
  ∀ scheda: pow(m', e, N) == C           (correttezza decifratura)
  ∀ R: σ_IAP valida + R compare una sola volta  (eligibilità)
  SHA256(foglie) ricostruisce ρ          (integrità registro)
  Σ voti == len(registro)                (correttezza conteggio)
```

---

## Setup & Run

```bash
# Crea e attiva un virtualenv
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS

# Installa le dipendenze
pip install -r requirements.txt

# Configura le variabili d'ambiente
cp .env.example .env            # poi edita con le credenziali Google OAuth

# Avvia il server
python src/main.py
```

### Variabili d'ambiente (`.env`)

| Variabile | Descrizione |
|-----------|-------------|
| `GOOGLE_CLIENT_ID` | Client ID app Google OAuth |
| `GOOGLE_CLIENT_SECRET` | Client Secret app Google OAuth |
| `FLASK_SECRET_KEY` | Chiave per la firma dei cookie di sessione |

### Esecuzione test

```bash
pytest tests/
```
