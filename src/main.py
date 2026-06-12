"""
main.py — punto di ingresso unico del prototipo Aequitas (§5).

Sequenza di avvio:
  1. Setup: istanzia E, IAP, N_TRUSTEES Trustee, VBR, TM.
  2. E.setup() genera (pk_elec, sk_elec), applica Shamir, calcola impegni,
     pubblica Params sul VBR.
  3. E.distribute_shares() invia (S_i, r_i) a ciascun trustee, poi le cancella.
  4. E.dissolve() elimina sk_elec: da qui in poi E possiede solo sk_E.
  5. Avvio dell'app Flask con le entità iniettate (no variabili globali sparse).

Avvio:
    cd <project_root>
    python src/main.py

Il server ascolta su http://127.0.0.1:5000 in modalità debug (solo demo).
In produzione usare gunicorn o uWSGI con HTTPS.
"""

import os
import sys

# Aggiunge la directory src/ al path in modo che gli import funzionino
# come se src/ fosse il package root (es. "from config import LAMBDA").
sys.path.insert(0, os.path.dirname(__file__))

# Carica le variabili d'ambiente da .env (se presente)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass  # python-dotenv non installato: usa le variabili d'ambiente di sistema

from config import N_TRUSTEES
from entities.electoral_auth import ElectoralAuthority
from entities.iap import IAP
from entities.tally_machine import TallyMachine
from entities.trustee import Trustee
from entities.vbr import VBR
from web.app import create_app


def setup() -> tuple:
    """
    Inizializza tutte le entità e restituisce (e, iap, vbr, tm, trustees).

    Questo corrisponde alla fase di Setup del protocollo (§5, passo 1).
    """
    print("=" * 60)
    print("AEQUITAS — fase di setup")
    print("=" * 60)

    # Entità
    e  = ElectoralAuthority(name="Autorità Elettorale Comunale")
    iap = IAP(liste_elettorali=_carica_liste_elettorali())
    vbr = VBR(pk_IAP=iap.pk_IAP)
    tm  = TallyMachine()
    trustees = [
        Trustee(trustee_id=i + 1, name=f"Trustee-{i + 1}")
        for i in range(N_TRUSTEES)
    ]

    # Setup E: genera chiave elezione, Shamir split, impegni, pubblica Params
    e.setup(pk_iap=iap.pk_IAP, vbr=vbr)

    # Distribuzione share ai trustee + cancellazione dall'authority
    e.distribute_shares(trustees)

    # Dissoluzione: da questo momento E non possiede più sk_elec
    e.dissolve()

    print("=" * 60)
    print("Setup completato. Avvio web app…")
    print("=" * 60)

    return e, iap, vbr, tm, trustees


def _carica_liste_elettorali() -> set:
    """
    In produzione le liste vengono da un sistema esterno (es. anagrafe comunale).
    Nel prototipo carichiamo identità di test da variabile d'ambiente o usiamo
    un set di demo.
    """
    env_identities = os.environ.get("LISTE_ELETTORALI", "")
    if env_identities:
        return set(env_identities.split(","))
    # Set di demo: in un sistema reale sarebbe popolato prima del voto
    return {
        "test@example.com",
        "voter1@gmail.com",
        "voter2@gmail.com",
        # Aggiungere le email Google degli elettori ammessi
    }


if __name__ == "__main__":
    e, iap, vbr, tm, trustees = setup()
    app = create_app(e, iap, vbr, tm, trustees)
    app.run(debug=True, host="127.0.0.1", port=5000)
