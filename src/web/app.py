"""
Flask web app per Aequitas (§6).

Route implementate:
  GET  /                   — home: stato elezione, link login
  GET  /login              — redirect a Google OAuth
  GET  /auth               — callback OAuth (Authlib)
  GET  /vote               — form di voto (richiede login)
  POST /vote               — cifratura + invio al VBR, mostra ricevuta h
  GET  /receipt/<h>        — verifica individuale (inclusione + apertura dopo spoglio)
  GET  /bulletin           — bollettino pubblico leggibile
  POST /admin/close        — chiude le urne ed esegue lo spoglio
  GET  /results            — risultati certificati + verifica universale

Il VoterClient gira server-side per semplicità del prototipo.
In un sistema reale le operazioni crittografiche del votante
(make_token, encrypt_vote, delay) dovrebbero avvenire sul suo dispositivo.

Authlib/Google: segue il demo flask-google-login ufficiale di Authlib
  (https://github.com/authlib/demo-oauth-client/tree/master/flask-google-login).
  Le credenziali OAuth si leggono da variabili d'ambiente (vedi .env.example).
"""

import hashlib
import json
import os

from authlib.integrations.flask_client import OAuth
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
    abort,
    flash,
)

from config import CANDIDATI, ADMIN_TOKEN, BULLETIN_FILE
from crypto.merkle import MerkleTree
from crypto.oaep_decode import decode_oaep, InvalidOAEP
from entities.voter import VoterClient


def create_app(e, iap, vbr, tm, trustees) -> Flask:
    """
    Factory che riceve le entità già inizializzate da main.py
    e le inietta nell'app via app.config.

    Args:
        e:        ElectoralAuthority (già dissolved dopo setup)
        iap:      IAP
        vbr:      VBR
        tm:       TallyMachine
        trustees: lista dei Trustee
    """
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

    # ------------------------------------------------------------------ #
    # Iniezione delle entità                                               #
    # ------------------------------------------------------------------ #
    app.config["E"]        = e
    app.config["IAP"]      = iap
    app.config["VBR"]      = vbr
    app.config["TM"]       = tm
    app.config["TRUSTEES"] = trustees

    # ------------------------------------------------------------------ #
    # Authlib — Google OIDC                                                #
    # ------------------------------------------------------------------ #
    oauth = OAuth(app)
    oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        server_metadata_url=(
            "https://accounts.google.com/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )

    # ------------------------------------------------------------------ #
    # Route §6                                                             #
    # ------------------------------------------------------------------ #

    @app.route("/")
    def index():
        vbr_obj = app.config["VBR"]
        e_obj   = app.config["E"]
        return render_template(
            "index.html",
            frozen=vbr_obj.frozen,
            election_id=e_obj.name,
            user=session.get("user"),
        )

    # -- Login / Auth (Authlib, flow Authorization Code) --

    @app.route("/login")
    def login():
        redirect_uri = url_for("auth_callback", _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route("/auth")
    def auth_callback():
        token    = oauth.google.authorize_access_token()
        userinfo = token.get("userinfo") or oauth.google.userinfo()
        # Usa 'sub' come identificativo stabile (analogo al codice fiscale)
        session["user"]     = userinfo
        session["identity"] = userinfo.get("email") or userinfo["sub"]
        return redirect(url_for("vote"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # -- Voto --

    @app.route("/vote", methods=["GET"])
    def vote():
        if "identity" not in session:
            return redirect(url_for("login"))
        vbr_obj = app.config["VBR"]
        if vbr_obj.frozen:
            flash("Le urne sono chiuse.")
            return redirect(url_for("index"))
        return render_template(
            "vote.html",
            candidati=CANDIDATI,
            user=session["user"],
            accreditato=session.get("accreditato", False),
        )

    @app.route("/vote", methods=["POST"])
    def submit_vote():
        if "identity" not in session:
            abort(403)
        vbr_obj = app.config["VBR"]
        iap_obj = app.config["IAP"]
        e_obj   = app.config["E"]

        if vbr_obj.frozen:
            flash("Le urne sono chiuse.")
            return redirect(url_for("index"))

        lista     = request.form.get("lista", "")
        candidato = request.form.get("candidato", "")
        if lista not in CANDIDATI or candidato not in CANDIDATI.get(lista, []):
            flash("Selezione non valida.")
            return redirect(url_for("vote"))

        identity = session["identity"]
        v_string = f"{lista} - {candidato}"

        # VoterClient: in produzione girerebbe sul dispositivo del votante
        vc = VoterClient()
        R  = vc.make_token()

        # Accreditamento IAP
        try:
            _, sigma = iap_obj.accredit(identity, R)
        except PermissionError as err:
            flash(str(err))
            return redirect(url_for("index"))

        # Cifratura del voto
        try:
            C, h = vc.encrypt_vote(v_string, e_obj.pk_elec)
        except (RuntimeError, ValueError) as err:
            flash(f"Errore cifratura: {err}")
            return redirect(url_for("vote"))

        # Ritardo e invio al VBR
        # NOTA: in un sistema reale il delay sarebbe sul client;
        # qui è omesso per non bloccare la request HTTP del browser.
        try:
            h_returned = vbr_obj.submit(R, sigma, C)
        except PermissionError as err:
            flash(str(err))
            return redirect(url_for("index"))

        session["accreditato"] = True
        session["last_h"]      = h_returned.hex()

        return render_template(
            "receipt.html",
            h=h_returned.hex(),
            user=session["user"],
        )

    # -- Verifica ricevuta --

    @app.route("/receipt/<h_hex>")
    def receipt(h_hex: str):
        vbr_obj = app.config["VBR"]
        e_obj   = app.config["E"]

        try:
            h = bytes.fromhex(h_hex)
        except ValueError:
            abort(400)

        inclusion_ok = None
        opening_info = None

        if vbr_obj.frozen:
            try:
                idx, proof = vbr_obj.inclusion_proof(h)
                R, sigma, C = vbr_obj.registro[idx]
                leaf_ok = vbr_obj.verify_inclusion(h, proof)
                inclusion_ok = leaf_ok
            except (KeyError, RuntimeError):
                inclusion_ok = False

            # Apertura: cerca nelle pre-immagini pubblicate
            if os.path.exists(BULLETIN_FILE):
                with open(BULLETIN_FILE, encoding="utf-8") as f:
                    bull = json.load(f)
                for entry in bull.get("pre_images", []):
                    C_bytes = bytes.fromhex(entry.get("C", ""))
                    if hashlib.sha256(C_bytes).digest() == h:
                        opening_info = entry
                        break

        return render_template(
            "receipt_detail.html",
            h=h_hex,
            inclusion_ok=inclusion_ok,
            opening=opening_info,
            frozen=vbr_obj.frozen,
            user=session.get("user"),
        )

    # -- Bollettino pubblico --

    @app.route("/bulletin")
    def bulletin():
        vbr_obj = app.config["VBR"]
        bull = None
        if os.path.exists(BULLETIN_FILE):
            with open(BULLETIN_FILE, encoding="utf-8") as f:
                bull = json.load(f)
            for entry in bull.get("registro", []):
                entry["h"] = hashlib.sha256(bytes.fromhex(entry["C"])).hexdigest()
        return render_template(
            "bulletin.html",
            bulletin=bull,
            vbr=vbr_obj,
            user=session.get("user"),
        )

    # -- Admin: chiusura urne e spoglio --

    @app.route("/admin/close", methods=["POST"])
    def admin_close():
        token = request.form.get("admin_token", "")
        if token != ADMIN_TOKEN:
            abort(403)

        vbr_obj      = app.config["VBR"]
        e_obj        = app.config["E"]
        tm_obj       = app.config["TM"]
        trustees_obj = app.config["TRUSTEES"]

        if vbr_obj.frozen:
            flash("Le urne sono già chiuse.")
            return redirect(url_for("results"))

        # 1. Freeze VBR + firma E
        rho       = vbr_obj.freeze()
        rho_sigma = e_obj.freeze_and_sign(rho)

        # 2. TM: carica vista, verifica firma E
        tm_obj.load_uvc(vbr_obj, e_obj.pk_E)
        tm_obj.set_rho_signature(rho_sigma, e_obj.pk_E)

        # 3. Raccolta share dai trustee
        commitments = e_obj.commitments
        tm_obj.collect_shares(trustees_obj, commitments)

        # 4. Ricostruzione chiave e tally
        tm_obj.reconstruct_key(e_obj.pk_elec)
        results, pre_images = tm_obj.tally(e_obj.pk_elec)
        tm_obj.destroy_key()

        # 5. Certifica e pubblica
        results_sigma = e_obj.certify(results)
        vbr_obj.publish(
            rho_sigma=rho_sigma,
            pre_images=pre_images,
            results=results,
            results_sigma=results_sigma,
        )

        flash("Spoglio completato. Bollettino pubblicato.")
        return redirect(url_for("results"))

    # -- Risultati + verifica universale --

    @app.route("/results")
    def results():
        bull = None
        verifica_ok = None
        if os.path.exists(BULLETIN_FILE):
            with open(BULLETIN_FILE, encoding="utf-8") as f:
                bull = json.load(f)
            verifica_ok = _verifica_universale(bull)
        return render_template(
            "results.html",
            bulletin=bull,
            verifica_ok=verifica_ok,
            user=session.get("user"),
        )

    # ------------------------------------------------------------------ #

    return app


# ------------------------------------------------------------------ #
# Verifica universale (§5) — usa solo i dati pubblici del bollettino  #
# ------------------------------------------------------------------ #

def _verifica_universale(bull: dict) -> dict:
    """
    Esegue i 4 controlli del WP2 sui dati del bollettino pubblico.

    Controlli:
      1. Integrità registro: ricalcola la radice Merkle e confronta con rho.
      2. Eleggibilità + unicità: ogni R compare esattamente una volta,
         firma IAP su R valida.
      3. Correttezza decifratura: pow(m', e, N) == C per ogni scheda.
      4. Correttezza conteggio: i totali corrispondono alle pre-immagini.

    Returns:
        dict con chiavi booleane per ogni controllo.
    """
    from crypto.rsa_utils import hash_and_verify

    params   = bull.get("params", {})
    registro = bull.get("registro", [])
    rho_hex  = bull.get("rho", "")
    rho      = bytes.fromhex(rho_hex)

    pk_elec_nums = params.get("pk_elec", {})
    n_e  = pk_elec_nums.get("n")
    e_e  = pk_elec_nums.get("e")

    # ---- Controllo 1: integrità registro ----
    import hashlib
    def sha256(d): return hashlib.sha256(d).digest()
    def leaf(R_hex, sigma, C_hex):
        return sha256(
            bytes.fromhex(R_hex)
            + bytes.fromhex(sigma)
            + bytes.fromhex(C_hex)
        )

    try:
        leaves = [leaf(r["R"], r["sigma"], r["C"]) for r in registro]
        tree   = MerkleTree(leaves)
        integrita_ok = tree.root() == rho
    except Exception:
        integrita_ok = False

    # ---- Controllo 2: eleggibilità + unicità ----
    try:
        R_set = set()
        pk_iap_n = params.get("pk_iap_n")

        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        pk_iap = RSAPublicNumbers(e=65537, n=pk_iap_n).public_key()

        unicity_ok = True
        for r in registro:
            R_bytes = bytes.fromhex(r["R"])
            if R_bytes in R_set:
                unicity_ok = False
                break
            # Verifica firma IAP su R
            if not hash_and_verify(pk_iap, R_bytes, bytes.fromhex(r["sigma"])):
                unicity_ok = False
                break
            R_set.add(R_bytes)
    except Exception:
        unicity_ok = False

    # ---- Controllo 3: correttezza decifratura ----
    try:
        decifratura_ok = True
        for entry in bull.get("pre_images", []):
            C_int     = int.from_bytes(bytes.fromhex(entry["C"]), "big")
            m_prime   = int(entry["m_prime"])
            if pow(m_prime, e_e, n_e) != C_int:
                decifratura_ok = False
                break
    except Exception:
        decifratura_ok = False

    # ---- Controllo 4: correttezza conteggio ----
    try:
        conteggio_ok = True
        results_pub  = bull.get("results", {})
        counts: dict = {}
        for entry in bull.get("pre_images", []):
            v = entry.get("v", "⊥")
            if v == "⊥":
                v = "nulle"
            counts[v] = counts.get(v, 0) + 1
        conteggio_ok = counts == results_pub
    except Exception:
        conteggio_ok = False

    return {
        "integrita_registro":   integrita_ok,
        "elegibilita_unicita":  unicity_ok,
        "correttezza_decifratura": decifratura_ok,
        "correttezza_conteggio":   conteggio_ok,
    }
