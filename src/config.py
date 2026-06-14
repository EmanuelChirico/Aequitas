"""
Parametri globali del protocollo Aequitas.
"""

# Dimensione chiave RSA in bit.
# La tesi usa 3072 bit; qui usiamo 2048 per velocizzare la demo.
# Con 2048 bit la generazione RSA richiede ~0.1 s anziché ~1 s su hardware tipico.
LAMBDA = 2048

# Parametri Shamir Secret Sharing
T = 3            # soglia minima per la ricostruzione
N_TRUSTEES = 5  # numero totale di trustee

# Campo primo per Shamir: 2^2281 - 1 (primo di Mersenne, verificato).
# È sufficiente che q > d (esponente privato RSA-2048, che è < 2^2048);
# usare un Mersenne noto evita di implementare test di primalità a runtime.
Q = 2**2281 - 1

# Dimensione in byte di una share Shamir: ceil(2281 / 8) = 286
SHARE_BYTES = 286

# Ritardo casuale del voto in secondi (per rendere difficile la correlazione temporale).
# Nel sistema reale sarebbe dell'ordine dei minuti; qui usiamo [2, 5] s per la demo.
DELTA_RANGE = (2, 5)

# Candidati per lista (caricabili anche da file JSON in produzione)
CANDIDATI = {
    "Lista 1": ["Rossi", "Bianchi"],
    "Lista 2": ["Verdi", "Neri"],
}

# Identificativo univoco dell'elezione (incluso in ogni voto cifrato)
ELECTION_ID = "comunali-demo-2026"

# Token di autenticazione banale per le route admin
ADMIN_TOKEN = "aequitas-admin-2026"

# Percorso del bollettino pubblico
BULLETIN_FILE = "bulletin.json"
