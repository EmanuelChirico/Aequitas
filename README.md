# Aequitas: Secure E-Voting Protocol

**Authors:** Autorino Luigi, Emanuel Chirico  
**Course:** Algoritmi e Protocolli di Sicurezza (Security Algorithms and Protocols)  
**Institution:** Università degli Studi di Salerno  

## Project Overview

Aequitas is a cryptographic protocol designed for secure digital elections with nominal preference voting. The system implements end-to-end verifiable voting with minimal trust assumptions, enabling municipal-scale elections while preserving voter privacy, ensuring ballot integrity, and providing public verifiability of results.

The project is structured in four Work Packages (WP):

- **WP1** — Threat Modeling & Architecture: Formal definition of security properties, adversarial models, and system architecture with five key actors (Electoral Authority, Trustees, Voters, Identity Provider, Ballot Register).
- **WP2** — Cryptographic Protocol Specification: Detailed description of setup, voting, and tallying phases using RSA-OAEP, hash-and-sign signatures, Shamir threshold secret sharing, and Merkle tree verification.
- **WP3** — Security Analysis: Resilience evaluation against identified threats, parameter selection, and discussion of residual risks.
- **WP4** — Implementation & Performance: Functional prototype simulating municipal-scale elections.

## Key Features

- **Minimal Trust:** Decentralized key reconstruction via threshold secret sharing
- **End-to-End Verifiability:** Individual voters verify their ballot inclusion via personal receipts; external observers validate the entire tally cryptographically.
- **Privacy:** Voter anonymity guaranteed through token-based authorization decoupled from preference encryption; temporal decorrelation via random delays.
- **Integrity:** Atomic ballot acceptance prevents double voting; publicly verifiable decryption prevents result manipulation.
- **Scalability:** Lightweight per-ballot validation at submission; heavy computation (decryption, verification) deferred to post-election tallying.

## Repository Structure

```
Aequitas/
├── README.md                          # This file
├── docs                               # Complete papers (all WPs)                  
└── src/                               # Source code
    ├── auth
    ├── entities
    ├── functions
    └── main.py
```
