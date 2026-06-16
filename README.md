# Aequitas — Secure E-Voting Protocol

![Aequitas Logo](logo/logo.jpg)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?logo=flask)
![Crypto](https://img.shields.io/badge/Crypto-RSA--OAEP%20%7C%20Shamir%20SSS%20%7C%20Merkle-blueviolet)
![Status](https://img.shields.io/badge/Status-Academic%20Prototype-orange)

> M.Sc. Computer Science — Università degli Studi di Salerno, 2025–2026
> Autorino Luigi · Chirico Emanuel

---

Aequitas is a cryptographic protocol for secure digital elections with nominal preference voting. It implements end-to-end verifiable voting with minimal trust assumptions: the election key is never held in full by any single party, voters receive individual inclusion proofs, and the full tally is publicly verifiable by anyone.

## Core properties

- **Minimal trust** — election key split via Shamir threshold secret sharing across independent trustees
- **End-to-end verifiability** — each voter gets a Merkle inclusion receipt; the tally is open to external audit
- **Voter privacy** — authorization token decoupled from the encrypted preference
- **Double-vote prevention** — atomic ballot acceptance enforced at the register level

**Stack** — Python 3.10+, Flask, RSA-OAEP, Shamir SSS, Merkle trees, OpenID Connect (Google, as SPID stand-in)

---

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows — or: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # fill in Google OAuth credentials
python src/main.py
```

`.env` variables:

| Variable | Description |
| --- | --- |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `FLASK_SECRET_KEY` | Flask session signing key |

> Authentication uses Google OpenID Connect as a stand-in for SPID (Sistema Pubblico di Identità Digitale). The flow is structurally equivalent — redirect → token → identity verification — with Google acting as the identity provider in place of a certified SPID IdP.

```bash
pytest tests/
```

---

## Architecture

```text
Voter ──► IAP (authenticate) ──► Token
Voter ──► E   (get ballot)   ──► Encrypted ballot
Voter ──► VBR (submit)       ──► Receipt + Merkle proof
              │
              └──► TallyMachine ──► Trustees (threshold decrypt) ──► Results
```

---

> **Disclaimer** — Proof-of-concept prototype. Not intended for production use.
