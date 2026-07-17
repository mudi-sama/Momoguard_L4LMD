"""Serveur central MoMoGuard : Flask + Flask-SocketIO + SQLite.

Ajouts de cette version :
  - compte administrateur (connexion, déconnexion, changement de mot de passe) ;
  - gestion des agents (enregistrer, bloquer/débloquer, retirer) ;
  - les rapports d'un agent bloqué sont refusés, et un agent enregistré avec
    un jeton doit le fournir.
"""

import os  # Variables d'environnement (MOMOGUARD_SECRET) et chemins
import secrets  # Génération de clés secrètes aléatoires
from datetime import datetime, timedelta, timezone  # Horodatages et durée de session
from functools import wraps  # Décorateur login_required

from flask import (Flask, request, jsonify, render_template, redirect,  # Framework web
                   url_for, session, flash, Response)  # Sessions, URLs, messages flash, export CSV
from flask_socketio import SocketIO  # WebSocket temps réel pour le dashboard
from werkzeug.security import generate_password_hash, check_password_hash  # Hachage mots de passe
from werkzeug.middleware.proxy_fix import ProxyFix  # HTTPS réel derrière Dokploy/Traefik
from flask_wtf.csrf import CSRFProtect  # Protection CSRF des formulaires HTML
from flask_limiter import Limiter  # Limitation de débit anti-abus
from flask_limiter.util import get_remote_address  # Identifie le client par IP

import pyotp  # Codes TOTP pour la 2FA administrateur

from . import database, scoring, firebase_auth, threat_intel  # Modules métier du serveur

# --- Configuration sécurité (OWASP A05) ------------------------------------
_PRODUCTION = os.environ.get("MOMOGUARD_ENV", "development").lower() == "production"
_HTTPS = os.environ.get("MOMOGUARD_HTTPS", "1" if _PRODUCTION else "0") == "1"
_MIN_PASSWORD_LEN = 10  # Politique mot de passe renforcée (OWASP A07)
_MAX_REPORT_CONTENT = 65_536  # Limite taille payload /report (anti-DoS)
_MAX_REPORT_METADATA_KEYS = 50
_MAX_LOGIN_FAILURES = 4  # Verrouillage du compte après ce nombre d'échecs consécutifs (OWASP A07)
_LOCKOUT_MINUTES = 15  # Durée du verrouillage temporaire du compte admin
# Fenêtre TOTP élargie (±60 s) : les VPS / conteneurs ont souvent une horloge
# légèrement décalée par rapport au téléphone (Google Authenticator).
_TOTP_WINDOW = 2

_secret = os.environ.get("MOMOGUARD_SECRET")
if _PRODUCTION and not _secret:
    raise SystemExit("[!] MOMOGUARD_SECRET obligatoire en production (MOMOGUARD_ENV=production).")
if not _secret:
    _secret = secrets.token_hex(32)
    print("[!] MOMOGUARD_SECRET non défini — sessions invalidées à chaque redémarrage.")

_cors_origins = os.environ.get(
    "MOMOGUARD_CORS_ORIGINS",
    "http://127.0.0.1:5000,http://localhost:5000",
)

app = Flask(__name__)  # Instance principale de l'application Flask
# Traefik (Dokploy) termine le TLS : Flask doit lire X-Forwarded-Proto / Host
# sinon cookies Secure, redirections et url_for restent en http://.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config["SECRET_KEY"] = _secret  # Signe les cookies et jetons CSRF
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Empêche JavaScript d'accéder au cookie de session
    SESSION_COOKIE_SAMESITE="Lax",  # Limite l'envoi du cookie cross-site
    SESSION_COOKIE_SECURE=_HTTPS,  # Cookie transmis uniquement en HTTPS si activé
    PREFERRED_URL_SCHEME="https" if _HTTPS else "http",  # URLs générées en https derrière Traefik
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # Expiration session admin
    # Derrière Traefik : ne pas exiger le header Referer (certains navigateurs /
    # politiques le retirent). Le jeton CSRF du formulaire reste obligatoire.
    WTF_CSRF_SSL_STRICT=False,
)

socketio = SocketIO(app, cors_allowed_origins=_cors_origins.split(","),
                    async_mode="threading")  # Temps réel — CORS restreint

# Protection CSRF des formulaires (les API JSON des agents sont exemptées plus bas)
csrf = CSRFProtect(app)  # Active la vérification CSRF sur les POST HTML

# Limitation de débit : anti-force brute sur la connexion, anti-abus sur /report
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://",  # Compteur en mémoire
                  default_limits=[])  # Pas de limite globale par défaut


@app.after_request  # Hook exécuté après chaque réponse HTTP
def _entetes_securite(response):  # Ajoute des en-têtes de sécurité
    """Ajoute des en-têtes de sécurité à toutes les réponses."""
    response.headers["X-Content-Type-Options"] = "nosniff"  # Empêche le MIME sniffing
    response.headers["X-Frame-Options"] = "DENY"  # Interdit l'affichage en iframe (clickjacking)
    # same-origin : le Referer est envoyé pour les formulaires du site (CSRF),
    # mais pas vers des sites tiers. "no-referrer" cassait le login (400).
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (  # Restreint les ressources chargées par la page
        "default-src 'self'; "  # Par défaut : même origine uniquement
        "script-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; "  # JS autorisés
        "style-src 'self' 'unsafe-inline'; "  # CSS autorisés
        "connect-src 'self' ws: wss:; "  # WebSocket + API same-origin
        "img-src 'self' data:;"  # Images locales et data-URI
    )
    if _HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response  # Renvoie la réponse enrichie

DEFAULT_ADMIN_USER = "admin"  # Identifiant admin créé au premier démarrage
DEFAULT_ADMIN_PASS = "momoguard"  # Mot de passe par défaut (à changer)


def ensure_default_admin():  # Garantit qu'au moins un admin existe
    """Crée un administrateur par défaut au premier démarrage."""
    if database.count_admins() == 0:  # Première installation
        database.create_admin(
            DEFAULT_ADMIN_USER, generate_password_hash(DEFAULT_ADMIN_PASS)  # Mot de passe haché
        )
        print(f"[!] Admin par défaut créé : {DEFAULT_ADMIN_USER} / {DEFAULT_ADMIN_PASS}")
        print("[!] Change ce mot de passe depuis la page « Compte ».")


def login_required(view):  # Décorateur : page réservée aux admins connectés
    @wraps(view)  # Préserve le nom de la fonction décorée
    def wrapped(*args, **kwargs):  # Wrapper appelé à la place de la vue
        if not session.get("admin"):  # Pas de session admin active
            return redirect(url_for("login"))  # Redirige vers la page de connexion
        return view(*args, **kwargs)  # Admin connecté : exécute la vue
    return wrapped


def _audit(action, target=None, details=None):  # Helper journal d'audit
    """Trace une action administrateur dans le journal d'audit."""
    database.add_audit(session.get("admin"), action, target, details)  # Écrit en base


def _verify_firebase_token(id_token):  # Valide un ID token Firebase (OWASP A01/A07)
    """Vérifie un jeton Firebase et renvoie l'UID ou lève une réponse d'erreur."""
    if not id_token:
        return None, (jsonify({"error": "id_token manquant"}), 401)
    if not firebase_auth.is_ready():
        return None, (jsonify({"error": "Firebase non configuré sur le serveur"}), 503)
    try:
        return firebase_auth.verify_id_token(id_token).get("uid"), None
    except Exception:
        return None, (jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401)


def _user_status_error(status):  # Message d'erreur selon le statut compte client
    return {
        "pending": "Compte en attente d'approbation",
        "rejected": "Compte refusé",
        "blocked": "Compte bloqué",
    }.get(status, "Compte non approuvé")


def _message_verrou(remaining_seconds):  # Message d'erreur de compte verrouillé
    """Formate un message indiquant la durée de verrouillage restante."""
    minutes = max(1, (int(remaining_seconds) + 59) // 60)  # Arrondit à la minute supérieure (>= 1)
    return (f"Trop de tentatives échouées. Compte temporairement verrouillé — "
            f"réessaie dans {minutes} minute(s).")


def _validate_report_payload(content, metadata):  # Limites taille et type (OWASP A04)
    if len(content) > _MAX_REPORT_CONTENT:
        return "Le champ 'content' dépasse la taille maximale autorisée"
    if metadata is not None and not isinstance(metadata, dict):
        return "Le champ 'metadata' doit être un objet JSON"
    if isinstance(metadata, dict) and len(metadata) > _MAX_REPORT_METADATA_KEYS:
        return "Le champ 'metadata' contient trop de clés"
    return None


# --- Authentification ------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])  # Page et traitement de connexion admin
@limiter.limit("10 per minute", methods=["POST"])  # Max 10 tentatives/min (anti brute-force)
def login():  # Authentification administrateur
    if request.method == "POST":  # Soumission du formulaire
        username = (request.form.get("username") or "").strip()  # Nom d'utilisateur saisi
        password = request.form.get("password") or ""  # Mot de passe saisi
        admin = database.get_admin(username)  # Recherche en base
        # Verrouillage temporaire du compte (indépendant de l'IP, complète le rate-limit).
        if admin:
            remaining = database.admin_lock_remaining(username)  # Secondes de verrou restantes
            if remaining > 0:  # Compte encore verrouillé
                database.add_audit(username, "Tentative sur compte verrouillé",  # Trace la tentative
                                   target=username, details=f"{remaining}s restantes")
                return render_template("login.html", erreur=_message_verrou(remaining)), 429  # 429 Too Many Requests
        if admin and check_password_hash(admin["password_hash"], password):  # Identifiants valides
            database.reset_failed_login(username)  # Succès : réinitialise le compteur d'échecs
            if admin.get("totp_secret"):  # 2FA activée pour ce compte
                session["pending_2fa"] = username  # Session intermédiaire avant code TOTP
                return redirect(url_for("login_2fa"))  # Étape 2 : saisie du code
            session["admin"] = username  # Session admin établie
            session.permanent = True  # Applique PERMANENT_SESSION_LIFETIME
            database.add_audit(username, "Connexion réussie")  # Trace dans le journal
            return redirect(url_for("dashboard"))  # Redirige vers le tableau de bord
        # Échec : on comptabilise l'essai sur le compte visé (s'il existe).
        if admin:
            _, locked_until = database.record_failed_login(
                username, _MAX_LOGIN_FAILURES, _LOCKOUT_MINUTES)  # Incrémente / verrouille
            if locked_until:  # Le seuil vient d'être atteint : compte verrouillé
                database.add_audit(username, "Compte verrouillé (échecs répétés)",  # Trace le verrouillage
                                   target=username,
                                   details=f"{_MAX_LOGIN_FAILURES} échecs — verrou {_LOCKOUT_MINUTES} min")
                return render_template("login.html", erreur=_message_verrou(_LOCKOUT_MINUTES * 60)), 429  # Verrou
        return render_template("login.html", erreur="Identifiants incorrects."), 401  # Échec
    return render_template("login.html", erreur=None)  # GET : affiche le formulaire


@app.route("/login/2fa", methods=["GET", "POST"])  # Seconde étape : code TOTP
@limiter.limit("10 per minute", methods=["POST"])  # Limite aussi les essais de code
def login_2fa():  # Vérification du code à 6 chiffres
    username = session.get("pending_2fa")  # Admin en attente de validation 2FA
    if not username:  # Session expirée ou accès direct
        return redirect(url_for("login"))
    if request.method == "POST":
        remaining = database.admin_lock_remaining(username)  # Verrou éventuel sur le compte
        if remaining > 0:  # Compte verrouillé pendant l'étape 2FA
            session.pop("pending_2fa", None)  # Annule l'état intermédiaire
            database.add_audit(username, "Tentative 2FA sur compte verrouillé", target=username)
            return render_template("login.html", erreur=_message_verrou(remaining)), 429
        code = (request.form.get("code") or "").strip()  # Code saisi par l'utilisateur
        admin = database.get_admin(username)
        secret = admin.get("totp_secret") if admin else None  # Clé secrète TOTP
        if secret and pyotp.TOTP(secret).verify(code, valid_window=_TOTP_WINDOW):
            database.reset_failed_login(username)  # Succès : réinitialise le compteur d'échecs
            session.pop("pending_2fa", None)  # Nettoie l'état intermédiaire
            session["admin"] = username  # Connexion finalisée
            session.permanent = True
            database.add_audit(username, "Connexion réussie (2FA)")
            return redirect(url_for("dashboard"))
        # Code invalide : comptabilise l'échec sur le même compte.
        print(f"[2FA] échec pour {username} — heure UTC serveur : "
              f"{datetime.now(timezone.utc).isoformat()} — code reçu len={len(code)}")
        _, locked_until = database.record_failed_login(
            username, _MAX_LOGIN_FAILURES, _LOCKOUT_MINUTES)
        if locked_until:  # Seuil atteint : verrouillage du compte
            session.pop("pending_2fa", None)  # Annule l'état intermédiaire
            database.add_audit(username, "Compte verrouillé (échecs 2FA répétés)",
                               target=username,
                               details=f"{_MAX_LOGIN_FAILURES} échecs — verrou {_LOCKOUT_MINUTES} min")
            return render_template("login.html", erreur=_message_verrou(_LOCKOUT_MINUTES * 60)), 429
        return render_template(
            "login_2fa.html",
            erreur="Code incorrect ou expiré. Vérifie l'heure de ton téléphone "
                   "et du serveur (NTP), ou réinitialise la 2FA.",
        ), 401
    return render_template("login_2fa.html", erreur=None)  # GET : formulaire code


@app.route("/logout")  # Déconnexion admin
def logout():
    _audit("Déconnexion")  # Trace l'action
    session.clear()  # Supprime toutes les données de session
    return redirect(url_for("login"))  # Retour à la page de connexion


@app.route("/account", methods=["GET", "POST"])  # Gestion du compte admin
@login_required  # Admin connecté requis
def account():  # Changement de mot de passe + lien 2FA
    username = session["admin"]  # Admin courant
    tfa = bool((database.get_admin(username) or {}).get("totp_secret"))  # 2FA active ?
    if request.method == "POST":  # Soumission changement mot de passe
        actuel = request.form.get("actuel") or ""  # Mot de passe actuel
        nouveau = request.form.get("nouveau") or ""  # Nouveau mot de passe
        admin = database.get_admin(username)
        if not check_password_hash(admin["password_hash"], actuel):  # Vérifie l'ancien
            return render_template("account.html", username=username, twofa_active=tfa,
                                   erreur="Mot de passe actuel incorrect.", ok=False)
        if len(nouveau) < _MIN_PASSWORD_LEN:  # Règle de longueur minimale
            return render_template("account.html", username=username, twofa_active=tfa,
                                   erreur=f"Le nouveau mot de passe doit faire au moins {_MIN_PASSWORD_LEN} caractères.", ok=False)
        database.update_admin_password(username, generate_password_hash(nouveau))  # Enregistre
        _audit("Changement de son mot de passe")
        return render_template("account.html", username=username, twofa_active=tfa,
                               erreur=None, ok=True)  # Succès
    return render_template("account.html", username=username, twofa_active=tfa,
                           erreur=None, ok=False)  # GET : affiche la page


def _qr_svg(data):  # Génère un QR code pour configurer la 2FA
    """Génère un QR code SVG (inline, sans dépendance image)."""
    import io  # Buffer mémoire pour le SVG
    import qrcode  # Bibliothèque QR code
    import qrcode.image.svg  # Factory SVG
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage)  # Encode l'URI TOTP
    buf = io.BytesIO()  # Buffer binaire
    img.save(buf)  # Écrit le SVG dans le buffer
    return buf.getvalue().decode("utf-8")  # Retourne le SVG en texte


@app.route("/account/2fa/setup")  # Page configuration 2FA (QR code)
@login_required
def twofa_setup():
    username = session["admin"]
    if (database.get_admin(username) or {}).get("totp_secret"):  # Déjà activée
        return redirect(url_for("account"))
    secret = session.get("twofa_tmp") or pyotp.random_base32()  # Génère ou réutilise secret
    session["twofa_tmp"] = secret  # Stocke temporairement en session
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="MoMoGuard")  # URI otpauth
    return render_template("twofa_setup.html", secret=secret, qr_svg=_qr_svg(uri), erreur=None)


@app.route("/account/2fa/enable", methods=["POST"])  # Confirme l'activation 2FA
@login_required
def twofa_enable():
    username = session["admin"]
    secret = session.get("twofa_tmp")  # Secret en attente de validation
    code = (request.form.get("code") or "").strip()  # Code de l'app authenticator
    if not secret:
        return redirect(url_for("twofa_setup"))
    if not pyotp.TOTP(secret).verify(code, valid_window=_TOTP_WINDOW):  # Code incorrect
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="MoMoGuard")
        return render_template("twofa_setup.html", secret=secret, qr_svg=_qr_svg(uri),
                               erreur="Code incorrect. Vérifie l'heure automatique (NTP) "
                                      "sur le téléphone et le serveur."), 400
    database.set_admin_totp(username, secret)  # Enregistre le secret en base
    session.pop("twofa_tmp", None)  # Nettoie la session temporaire
    _audit("Activation de la 2FA")
    return redirect(url_for("account"))


@app.route("/account/2fa/disable", methods=["POST"])  # Désactive la 2FA
@login_required
def twofa_disable():
    username = session["admin"]
    admin = database.get_admin(username)
    password = request.form.get("password") or ""
    code = (request.form.get("code") or "").strip()
    secret = (admin or {}).get("totp_secret")
    if not admin or not secret:
        return redirect(url_for("account"))
    if not check_password_hash(admin["password_hash"], password):
        return render_template("account.html", username=username, twofa_active=True,
                               erreur="Mot de passe incorrect — 2FA non désactivée.", ok=False), 401
    if not pyotp.TOTP(secret).verify(code, valid_window=_TOTP_WINDOW):
        return render_template("account.html", username=username, twofa_active=True,
                               erreur="Code 2FA incorrect — 2FA non désactivée.", ok=False), 401
    database.set_admin_totp(username, None)  # Supprime le secret TOTP
    _audit("Désactivation de la 2FA")
    return redirect(url_for("account"))


def _maybe_reset_admin_2fa():
    """Réinitialise la 2FA admin si MOMOGUARD_RESET_ADMIN_2FA=1 (secours VPS).

    À utiliser UNE FOIS après un redeploy qui a cassé le secret Authenticator,
    puis retirer immédiatement la variable et redéployer.
    """
    if os.environ.get("MOMOGUARD_RESET_ADMIN_2FA", "").strip() != "1":
        return
    cible = os.environ.get("MOMOGUARD_RESET_ADMIN_USER", DEFAULT_ADMIN_USER).strip()
    admin = database.get_admin(cible)
    if not admin:
        print(f"[2FA] reset demandé mais admin inconnu : {cible}")
        return
    if not admin.get("totp_secret"):
        print(f"[2FA] reset demandé — {cible} n'avait déjà pas de 2FA")
        return
    database.set_admin_totp(cible, None)
    database.reset_failed_login(cible)  # Déverrouille aussi le compte
    print(f"[2FA] RÉINITIALISÉE pour « {cible} » — retire MOMOGUARD_RESET_ADMIN_2FA=1 "
          "des variables Dokploy puis redeploy.")


# --- Santé / diagnostic (Dokploy, monitoring) ------------------------------

@app.route("/health")  # Public : vérifie que le conteneur répond + quels services sont actifs
@csrf.exempt
def health():
    """État des services pour diagnostiquer un déploiement Dokploy."""
    return jsonify({
        "ok": True,
        "env": "production" if _PRODUCTION else "development",
        "https_cookies": _HTTPS,
        "firebase": firebase_auth.is_ready(),
        "safe_browsing": threat_intel.is_ready(),
        "database": database.DATABASE_URL.split("://", 1)[0],  # sqlite / postgresql / mysql
        "data_dir": database._DATA_DIR,
    })


# --- Dashboard -------------------------------------------------------------

@app.route("/")  # Page d'accueil = dashboard de supervision
@login_required
def dashboard():  # Affiche le flux d'alertes temps réel
    admin = database.get_admin(session["admin"])  # Infos admin connecté
    mdp_par_defaut = check_password_hash(admin["password_hash"], DEFAULT_ADMIN_PASS)  # Alerte si mdp par défaut
    return render_template("dashboard.html", mdp_par_defaut=mdp_par_defaut)


# Messages frauduleux types pour la démonstration en soutenance.
DEMO_SAMPLES = [  # Échantillons SMS d'arnaque Mobile Money RDC
    "URGENT: votre compte Orange Money sera suspendu. Reactivez sur http://0range-money.tk",
    "M-Pesa: votre carte SIM va etre remplacee. Communiquez votre code PUK pour confirmer.",
    "Felicitations ! Vous avez gagne 5.000.000 FC, envoyez 50$ de frais pour recevoir.",
    "Bonjour, je suis agent Airtel Money. Donnez le code de validation recu pour securiser votre compte.",
    "Securite Vodacom: activite suspecte. Confirmez votre identite sur http://v0dacom-secure.xyz",
]


@app.route("/demo", methods=["POST"])  # Bouton « Simuler une alerte » (soutenance)
@login_required
def demo_alert():  # Insère une fausse alerte et la pousse en temps réel
    """Génère une alerte frauduleuse de démonstration (utile en soutenance)."""
    import random  # Choix aléatoire d'un échantillon
    content = random.choice(DEMO_SAMPLES)  # Message frauduleux tiré au sort
    score, level, reasons = scoring.score_event(  # Analyse par le moteur de règles
        "sms", content, {}, database.get_thresholds()
    )
    saved = database.insert_report(  # Enregistre en base
        "demo-jury", "demo", "sms", content, {}, score, level, reasons, uid=None
    )
    socketio.emit("new_report", saved)  # Notifie les dashboards connectés
    _audit("Alerte de démonstration générée")
    return jsonify({"ok": True, "level": level, "id": saved["id"]})  # Réponse JSON au bouton


@app.route("/api/reports")  # API JSON : liste des alertes + statistiques
@login_required
def api_reports():  # Chargement initial du dashboard
    return jsonify({
        "reports": database.get_recent(limit=100),  # 100 dernières alertes
        "stats": database.get_stats(),  # Compteurs par niveau
        "categories": database.get_category_stats(),  # Répartition par type d'arnaque
    })


# --- Analyseur interactif (test en direct) ---------------------------------

@app.route("/analyzer")  # Page d'analyse manuelle d'un message
@login_required
def analyzer():  # Permet de tester un SMS/lien devant le jury
    """Affiche l'analyseur : on colle un message, on obtient le verdict en direct."""
    return render_template("analyzer.html")


@app.route("/api/analyze", methods=["POST"])  # API : analyse un message à la volée
@login_required
def api_analyze():  # Analyse sans persistance (outil de démonstration)
    """Analyse un contenu fourni par l'admin, sans l'enregistrer en base."""
    data = request.get_json(silent=True) or {}  # Corps JSON
    content = (data.get("content") or "").strip()  # Message à analyser
    event_type = (data.get("event_type") or "sms").strip()  # Type d'évènement choisi
    if not content:  # Rien à analyser
        return jsonify({"error": "Le message à analyser est vide."}), 400
    payload_err = _validate_report_payload(content, {})  # Limites de taille (anti-DoS)
    if payload_err:
        return jsonify({"error": payload_err}), 400
    score, level, reasons = scoring.score_event(  # Passe par le moteur de règles existant
        event_type, content, {}, database.get_thresholds()
    )
    return jsonify({  # Verdict complet renvoyé au front
        "score": score, "level": level, "reasons": reasons,
        "conseil": database._conseil(reasons),  # Conseil de prévention
        "categorie": database._categorie(reasons),  # Type d'arnaque déduit
    })


# --- Statistiques & export -------------------------------------------------

EVALUATION = {  # Résultats du benchmark hors ligne (voir evaluation/resultats.md)
    "dataset": 48, "fraude": 26, "legitime": 22,  # Composition du jeu de test étiqueté
    "rappel": 96.2, "faux_positifs": 0.0, "precision": 100.0,  # Rappel, taux de FP, précision
    "f1": 98.0, "exactitude": 97.9,  # F1-score et exactitude globale
}


@app.route("/stats")  # Page d'analyse statistique
@login_required
def stats_page():  # Synthèse chiffrée pour la soutenance
    """Tableau de synthèse : métriques d'évaluation + répartition en base."""
    return render_template(
        "stats.html", evaluation=EVALUATION,  # Métriques du benchmark
        stats=database.get_stats(),  # Compteurs par niveau
        categories=database.get_category_stats(),  # Répartition par type d'arnaque
    )


@app.route("/api/reports.csv")  # Export CSV des alertes
@login_required
def export_reports_csv():  # Télécharge l'historique des alertes
    """Exporte les alertes enregistrées au format CSV (utile pour le rapport écrit)."""
    import csv  # Écriture CSV
    import io  # Tampon mémoire texte
    rows = database.get_recent(limit=1000)  # Jusqu'à 1000 dernières alertes
    buf = io.StringIO()  # Tampon en mémoire
    writer = csv.writer(buf, delimiter=";")  # Séparateur « ; » (compatible Excel FR)
    writer.writerow(["id", "date", "agent", "plateforme", "type",  # En-tête des colonnes
                     "niveau", "score", "categorie", "contenu", "raisons"])
    for r in rows:  # Une ligne par alerte
        writer.writerow([
            r["id"], r["created_at"], r["agent_id"], r["platform"],
            r["event_type"], r["level"], r["score"], r.get("categorie") or "",
            r["content"], " | ".join(r.get("reasons") or []),
        ])
    _audit("Export CSV des alertes", details=f"{len(rows)} lignes")  # Trace dans l'audit
    return Response(  # Réponse téléchargeable
        "\ufeff" + buf.getvalue(),  # BOM UTF-8 pour l'ouverture correcte dans Excel
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=momoguard_alertes.csv"},
    )


# --- Menaces (threat intelligence) -----------------------------------------

def _domaines_suspects(limit=100):  # Extrait les domaines des alertes à risque
    """Liste les domaines uniques présents dans les alertes moyennes/élevées."""
    import re  # Extraction des URLs
    rx = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)  # Motif d'URL
    vus, seen = [], set()  # Résultats et ensemble de déduplication
    for r in database.get_recent(limit=limit):  # Parcourt les alertes récentes
        if r["level"] == "faible":  # On ignore les évènements faibles (RAS)
            continue
        for m in rx.findall(r["content"] or ""):  # Chaque URL trouvée dans le contenu
            url = m[0] if isinstance(m, tuple) else m  # Normalise le format de capture
            dom = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)  # Retire le schéma
            dom = re.sub(r"^www\.", "", dom, flags=re.IGNORECASE).split("/")[0].lower()  # Hôte seul
            dom = dom.rstrip(".,;)")  # Nettoie la ponctuation finale
            if dom and dom not in seen:  # Domaine nouveau
                seen.add(dom)  # Mémorise pour éviter les doublons
                vus.append({"domaine": dom, "niveau": r["level"],  # Fiche du domaine suspect
                            "date": r["created_at"], "extrait": (r["content"] or "")[:120]})
    return vus  # Liste de domaines suspects


@app.route("/threats")  # Page état de la threat intelligence
@login_required
def threats_page():  # Réputation d'URL + domaines repérés
    """État du service de réputation d'URL et domaines suspects observés."""
    return render_template(
        "threats.html",
        ti_ready=threat_intel.is_ready(),  # Service Safe Browsing configuré ?
        domaines=_domaines_suspects(),  # Domaines suspects extraits des alertes
    )


# --- Guide de prévention ---------------------------------------------------

GUIDE_ITEMS = [  # Fiches pédagogiques : type d'arnaque → mécanisme → bon réflexe
    {"titre": "Phishing (lien piégé)",
     "comment": "Un SMS imite votre opérateur et vous pousse à cliquer sur un lien pour « réactiver » ou « sécuriser » votre compte. Le faux site copie la vraie page pour voler vos identifiants.",
     "reflexe": "Ne cliquez jamais sur un lien reçu par SMS : ouvrez vous-même l'application officielle."},
    {"titre": "SIM swap / code PUK",
     "comment": "L'escroc prétend que votre carte SIM doit être remplacée et réclame votre code PUK pour prendre le contrôle de votre numéro et des comptes qui y sont liés.",
     "reflexe": "Un opérateur ne demande jamais votre code PUK par message. Ne le communiquez à personne."},
    {"titre": "Vol de code / OTP",
     "comment": "On vous demande de « confirmer » ou « partager » un code reçu par SMS ; ce code valide en réalité une opération sur VOTRE compte.",
     "reflexe": "Un code de confirmation ne se partage jamais, même avec une personne se disant agent."},
    {"titre": "Faux agent Mobile Money",
     "comment": "Une personne se présente comme agent Orange, Airtel ou Vodacom et vous « guide » pour régler un problème via un code ou une manipulation.",
     "reflexe": "Un vrai agent ne vous fait jamais réaliser une opération à distance avec un code."},
    {"titre": "Loterie / faux gain",
     "comment": "Vous auriez gagné une grosse somme, mais devez payer des « frais » à l'avance pour la recevoir.",
     "reflexe": "Aucun gain légitime n'exige de payer d'abord. C'est une arnaque."},
    {"titre": "Arnaque au remboursement",
     "comment": "Quelqu'un affirme vous avoir envoyé de l'argent « par erreur » et vous demande de le lui renvoyer.",
     "reflexe": "Ne renvoyez rien : vérifiez votre solde et contactez votre opérateur."},
    {"titre": "Frais fictifs de déblocage",
     "comment": "On vous dit que votre compte est bloqué et qu'un petit paiement débloquera la situation.",
     "reflexe": "Aucun déblocage de compte ne se paie par transfert Mobile Money."},
    {"titre": "Multiplication d'argent",
     "comment": "« Envoyez X, recevez le double » : promesse de multiplier votre argent instantanément.",
     "reflexe": "Aucun service ne multiplie votre argent. Ignorez et signalez ces messages."},
]


@app.route("/guide")  # Page pédagogique de prévention
@login_required
def guide_page():  # Sensibilisation des utilisateurs (axe « humains »)
    """Guide pédagogique : types d'arnaques Mobile Money et bons réflexes."""
    return render_template("guide.html", items=GUIDE_ITEMS)


# --- Réception des rapports (agents) ---------------------------------------

@app.route("/report", methods=["POST"])  # Endpoint principal : réception des rapports agents
@csrf.exempt  # Les agents envoient du JSON, pas de token CSRF
@limiter.limit("120 per minute")  # Limite le volume pour éviter le spam
def report():  # Traite un événement suspect remonté par un agent
    data = request.get_json(silent=True)  # Parse le corps JSON
    if not data:  # Corps absent ou JSON invalide
        return jsonify({"error": "Corps JSON manquant ou invalide"}), 400

    agent_id = data.get("agent_id", "inconnu")  # Identifiant de l'agent émetteur
    platform = data.get("platform", "inconnu")  # windows, android, demo…
    event_type = data.get("event_type", "message")  # sms, link, file, clipboard…
    content = data.get("content", "")  # Texte ou URL analysé
    metadata = data.get("metadata", {})  # Infos complémentaires (expéditeur, navigateur…)
    token = data.get("token")  # Jeton d'authentification agent
    id_token = data.get("id_token")  # Jeton Firebase (obligatoire pour Android)

    if not content:  # Contenu obligatoire
        return jsonify({"error": "Le champ 'content' est requis"}), 400

    payload_err = _validate_report_payload(content, metadata)
    if payload_err:
        return jsonify({"error": payload_err}), 400

    # OWASP A01 : l'UID provient du jeton Firebase vérifié, jamais du champ uid libre.
    uid = None
    if platform == "android":
        uid, err = _verify_firebase_token(id_token)
        if err:
            return err
        declared_uid = data.get("uid")
        if declared_uid and declared_uid != uid:
            return jsonify({"error": "uid incohérent avec le jeton Firebase"}), 401
    elif id_token:
        uid, err = _verify_firebase_token(id_token)
        if err:
            return err

    # Contrôle d'adhésion : le compte client doit être approuvé.
    user = database.get_user_by_uid(uid) if uid else None
    if user and user["status"] != "approved":
        return jsonify({"error": _user_status_error(user["status"])}), 403

    if platform == "android":
        # Authentification par le COMPTE uniquement (Firebase) : pas de jeton d'agent.
        # L'identité vient de l'UID Firebase déjà vérifié ; le compte doit exister et être approuvé.
        if not user:
            return jsonify({"error": "Compte non reconnu — connectez-vous d'abord"}), 403
        # L'appareil est rattaché au compte : identifiant dérivé de l'UID (anti-usurpation).
        agent_id = f"android-{uid}"
        agent = database.get_agent(agent_id)
        if agent and agent["status"] == "blocked":
            return jsonify({"error": "Agent bloqué"}), 403
        if not agent:  # Auto-enregistrement léger pour l'affichage dans le dashboard (aucune config côté téléphone)
            libelle = user.get("display_name") or user.get("email") or agent_id
            database.register_agent(agent_id, f"{libelle} (Android)", "android", token=None)
        database.touch_agent(agent_id)
    else:
        # OWASP A01/A04 : agent pré-enregistré avec jeton obligatoire (pas d'auto-enregistrement).
        agent = database.get_agent(agent_id)
        if not agent:
            return jsonify({"error": "Agent non enregistré — déclarez-le depuis le dashboard"}), 403
        if agent["status"] == "blocked":
            return jsonify({"error": "Agent bloqué"}), 403
        if not agent.get("token"):
            return jsonify({"error": "Agent sans jeton — régénérez-le depuis le dashboard"}), 401
        if not token or token != agent["token"]:
            return jsonify({"error": "Jeton d'agent invalide"}), 401
        database.touch_agent(agent_id)

    score, level, reasons = scoring.score_event(  # Calcul du score par règles
        event_type, content, metadata, database.get_thresholds()
    )

    # Enrichissement par réputation d'URL via une API externe (si configurée).
    if threat_intel.is_ready():  # Clé Safe Browsing présente
        urls = threat_intel.extract_urls(content)  # Extrait les liens du texte
        if urls and threat_intel.check_urls(urls) == "malicious":  # URL connue dangereuse
            score = min(score + 40, 100)  # Bonus de score plafonné à 100
            level = "eleve"  # Force le niveau élevé
            reasons.append("URL signalée comme malveillante par le service de réputation externe")

    saved = database.insert_report(  # Persiste l'alerte en base
        agent_id, platform, event_type, content, metadata, score, level, reasons,
        uid=uid,
    )
    socketio.emit("new_report", saved)  # Push temps réel vers le dashboard

    # Notification push de danger au client concerné (alerte de niveau élevé).
    if level == "eleve" and user and user.get("fcm_token"):  # Alerte critique + push possible
        firebase_auth.send_push(
            user["fcm_token"],  # Jeton FCM du téléphone
            "MoMoGuard — danger détecté",
            "Un message à haut risque a été repéré sur ton appareil. Vérifie tes alertes.",
        )

    return jsonify({  # Réponse à l'agent avec le verdict
        "ok": True, "id": saved["id"], "score": score,
        "level": level, "reasons": reasons,
        "categorie": database._categorie(reasons),  # Type d'arnaque déduit (pour la notification agent)
        "conseil": database._conseil(reasons),  # Conseil de prévention (« en savoir plus »)
    }), 201  # 201 Created


# --- Gestion des agents ----------------------------------------------------

def _annotate_online(agents, window_seconds=120):  # Enrichit chaque agent avec un indicateur en ligne/hors ligne
    """Marque chaque agent en ligne s'il a été vu dans la fenêtre donnée."""
    now = datetime.now(timezone.utc)  # Horodatage actuel en UTC pour la comparaison
    for a in agents:  # Parcourt tous les agents de la liste
        online = False  # Par défaut, l'agent est considéré hors ligne
        if a.get("last_seen"):  # Si une date de dernière activité existe
            try:  # Tente de parser la date ISO stockée en base
                seen = datetime.fromisoformat(a["last_seen"])  # Conversion de last_seen en datetime
                if seen.tzinfo is None:  # Si la date n'a pas de fuseau horaire
                    seen = seen.replace(tzinfo=timezone.utc)  # Normalise en UTC
                online = (now - seen).total_seconds() <= window_seconds  # En ligne si vu dans la fenêtre
            except Exception:  # Date invalide ou format inattendu
                online = False  # En cas d'erreur, considère l'agent hors ligne
        a["online"] = online  # Ajoute le booléen au dictionnaire de l'agent
    return agents  # Retourne la liste annotée


@app.route("/agents", methods=["GET", "POST"])  # Page de gestion des agents (liste et ajout)
@login_required  # Réservé à l'administrateur connecté
def agents():  # Affiche la liste ou enregistre un nouvel agent via formulaire
    if request.method == "POST":  # Soumission du formulaire d'enregistrement
        agent_id = (request.form.get("agent_id") or "").strip()  # Identifiant unique de l'agent
        label = (request.form.get("label") or "").strip()  # Libellé descriptif (nom, poste, etc.)
        platform = (request.form.get("platform") or "").strip()  # Plateforme (Windows, Android, etc.)
        if not agent_id:  # L'identifiant est obligatoire
            return render_template("agents.html",  # Réaffiche la page avec message d'erreur
                                   agents=_annotate_online(database.get_agents()),  # Liste avec statut en ligne
                                   erreur="L'identifiant de l'agent est requis."), 400  # Code HTTP bad request
        token = secrets.token_urlsafe(32)  # Jeton agent fort (OWASP A02)
        database.register_agent(agent_id, label or "(sans nom)", platform or "inconnu", token)
        _audit("Agent enregistré", target=agent_id)
        session["new_agent_token"] = {"id": agent_id, "token": token}  # Affichage unique
        return redirect(url_for("agents"))
    new_token = session.pop("new_agent_token", None)
    return render_template("agents.html",
                           agents=_annotate_online(database.get_agents()),
                           erreur=None, new_token=new_token)


@app.route("/agents/<agent_id>/block", methods=["POST"])  # Route POST pour bloquer un agent
@login_required  # Admin requis
def agent_block(agent_id):  # Passe l'agent au statut « bloqué »
    database.set_agent_status(agent_id, "blocked")  # Met à jour le statut en base de données
    _audit("Agent bloqué", target=agent_id)  # Journalise le blocage
    return redirect(url_for("agents"))  # Retour à la liste des agents


@app.route("/agents/<agent_id>/unblock", methods=["POST"])  # Route POST pour débloquer un agent
@login_required  # Admin requis
def agent_unblock(agent_id):  # Réactive un agent précédemment bloqué
    database.set_agent_status(agent_id, "active")  # Remet le statut à « actif »
    _audit("Agent débloqué", target=agent_id)  # Journalise le déblocage
    return redirect(url_for("agents"))  # Retour à la liste des agents


@app.route("/agents/<agent_id>/remove", methods=["POST"])  # Route POST pour supprimer un agent
@login_required  # Admin requis
def agent_remove(agent_id):  # Retire définitivement l'agent du système
    database.delete_agent(agent_id)  # Suppression en base de données
    _audit("Agent retiré", target=agent_id)  # Journalise la suppression
    return redirect(url_for("agents"))  # Retour à la liste des agents


# --- Authentification client (Firebase) ------------------------------------

@app.route("/api/auth/firebase", methods=["POST"])  # API de connexion client via Firebase
@csrf.exempt  # Exemptée du jeton CSRF (app mobile / JSON)
@limiter.limit("30 per minute")
def auth_firebase():  # Vérifie le jeton Firebase et crée ou met à jour l'utilisateur local
    """L'app envoie son ID token Firebase. On le vérifie, puis on crée/relie
    l'utilisateur dans MySQL (statut 'pending' tant que l'admin n'a pas approuvé)."""
    if not firebase_auth.is_ready():  # Firebase non configuré sur le serveur
        return jsonify({"error": "Firebase non configuré sur le serveur"}), 503  # Service indisponible

    data = request.get_json(silent=True) or {}  # Corps JSON de la requête (dict vide si absent)
    id_token = data.get("id_token")  # Jeton ID Firebase envoyé par l'application cliente
    if not id_token:  # Le jeton est obligatoire
        return jsonify({"error": "id_token manquant"}), 400  # Requête mal formée

    try:  # Vérification cryptographique du jeton auprès de Firebase
        decoded = firebase_auth.verify_id_token(id_token)  # Décode et valide le jeton
    except Exception:  # Jeton expiré, signature invalide, etc.
        return jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401  # Non autorisé

    uid = decoded.get("uid")  # Identifiant Firebase unique de l'utilisateur
    email = decoded.get("email", "")  # Adresse courriel du compte Firebase
    name = decoded.get("name", "")  # Nom affiché du profil Firebase
    # IP du client (gère le cas d'un proxy via X-Forwarded-For)
    ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()  # Première IP si proxy
          or request.remote_addr)  # Sinon adresse IP directe du client
    user = database.upsert_user(uid, email, name, ip=ip)  # Crée ou met à jour l'utilisateur en base

    return jsonify({  # Réponse JSON avec l'état du compte
        "ok": True,  # Authentification réussie
        "uid": user["uid"],  # UID renvoyé à l'application
        "email": user["email"],  # Courriel enregistré
        "status": user["status"],  # Statut d'approbation (pending, approved, etc.)
    })


@app.route("/api/my-reports", methods=["POST"])  # API pour récupérer les alertes du client connecté
@csrf.exempt  # Exemptée du CSRF (app mobile)
@limiter.limit("60 per minute")
def my_reports():  # Renvoie les rapports associés à l'UID Firebase authentifié
    """L'app envoie son ID token ; on renvoie les alertes de CE client."""
    if not firebase_auth.is_ready():  # Firebase non configuré
        return jsonify({"error": "Firebase non configuré sur le serveur"}), 503  # Service indisponible
    data = request.get_json(silent=True) or {}  # Corps JSON de la requête
    id_token = data.get("id_token")  # Jeton Firebase pour identifier le client
    if not id_token:  # Jeton obligatoire
        return jsonify({"error": "id_token manquant"}), 400  # Requête invalide
    try:  # Validation du jeton Firebase
        decoded = firebase_auth.verify_id_token(id_token)  # Décode le jeton
    except Exception:  # Jeton invalide ou expiré
        return jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401  # Non autorisé

    uid = decoded.get("uid")  # UID du client authentifié
    user = database.get_user_by_uid(uid)  # Récupère le profil utilisateur local
    if not user or user["status"] != "approved":
        return jsonify({
            "error": _user_status_error(user["status"] if user else "unknown"),
            "status": user["status"] if user else "unknown",
        }), 403
    reports = database.get_reports_for_user(uid, limit=100)  # Derniers rapports de ce client
    counts = {"total": len(reports), "faible": 0, "moyen": 0, "eleve": 0}  # Compteurs par niveau
    for r in reports:  # Parcourt chaque rapport pour agréger les statistiques
        counts[r["level"]] = counts.get(r["level"], 0) + 1  # Incrémente le compteur du niveau
    return jsonify({  # Réponse avec statut, stats et liste des rapports
        "status": user["status"] if user else "unknown",  # Statut d'approbation du compte
        "stats": counts,  # Nombre d'alertes par niveau de risque
        "reports": reports,  # Liste détaillée des rapports
    })


@app.route("/api/fcm-token", methods=["POST"])  # API d'enregistrement du jeton push FCM
@csrf.exempt  # Exemptée du CSRF (app mobile)
@limiter.limit("30 per minute")
def fcm_token():  # Enregistre ou met à jour le jeton FCM pour les notifications push
    """L'app enregistre (ou met à jour) son jeton FCM pour recevoir les push."""
    if not firebase_auth.is_ready():  # Firebase non configuré
        return jsonify({"error": "Firebase non configuré sur le serveur"}), 503  # Service indisponible
    data = request.get_json(silent=True) or {}  # Corps JSON de la requête
    id_token = data.get("id_token")  # Jeton Firebase pour authentifier le client
    fcm = data.get("fcm_token")  # Jeton FCM de l'appareil pour les push
    if not id_token or not fcm:  # Les deux champs sont requis
        return jsonify({"error": "id_token et fcm_token requis"}), 400  # Requête incomplète
    try:  # Validation du jeton Firebase
        decoded = firebase_auth.verify_id_token(id_token)  # Décode le jeton
    except Exception:  # Jeton invalide ou expiré
        return jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401  # Non autorisé
    uid = decoded.get("uid")
    user = database.get_user_by_uid(uid)
    if not user or user["status"] != "approved":
        return jsonify({"error": _user_status_error(user["status"] if user else "unknown")}), 403
    database.set_user_fcm_token(uid, fcm)  # Persiste le jeton FCM en base
    return jsonify({"ok": True})  # Confirmation de l'enregistrement


# --- Gestion des utilisateurs clients --------------------------------------

@app.route("/users")  # Page listant les utilisateurs clients Firebase
@login_required  # Réservé à l'administrateur
def users():  # Affiche tous les comptes clients enregistrés
    sync_msg = session.pop("users_sync_msg", None)  # Message éventuel après une synchro Firebase
    return render_template("users.html", users=database.get_users(),  # Template avec la liste
                           firebase_ready=firebase_auth.is_ready(),  # Bouton de synchro si Firebase actif
                           sync_msg=sync_msg)  # Résultat de la dernière synchronisation


@app.route("/users/sync", methods=["POST"])  # Synchronise les comptes Firebase → base locale
@login_required  # Admin requis
def users_sync():  # Importe dans le dashboard les comptes Firebase absents
    if not firebase_auth.is_ready():  # Firebase non configuré
        session["users_sync_msg"] = "Firebase non configuré — synchronisation impossible."
        return redirect(url_for("users"))
    try:
        comptes = firebase_auth.list_users()  # Récupère tous les comptes Firebase
    except Exception as e:  # Erreur d'accès à Firebase
        session["users_sync_msg"] = f"Échec de la synchronisation : {e}"
        return redirect(url_for("users"))
    crees = 0  # Compteur de nouveaux comptes importés
    for c in comptes:  # Parcourt chaque compte Firebase
        if database.import_firebase_user(c["uid"], c["email"], c["display_name"]):  # Insère si absent
            crees += 1  # Incrémente si un compte a été créé
    _audit("Synchronisation Firebase", details=f"{crees} compte(s) importé(s) sur {len(comptes)}")
    session["users_sync_msg"] = (
        f"Synchronisation terminée : {crees} nouveau(x) compte(s) importé(s) "
        f"sur {len(comptes)} dans Firebase."
    )
    return redirect(url_for("users"))


@app.route("/users/<uid>/approve", methods=["POST"])  # Route POST pour approuver un compte
@login_required  # Admin requis
def user_approve(uid):  # Passe le compte au statut « approuvé »
    database.set_user_status(uid, "approved")  # Met à jour le statut en base
    _audit("Utilisateur approuvé", target=uid)  # Journalise l'approbation
    return redirect(url_for("users"))  # Retour à la liste des utilisateurs


@app.route("/users/<uid>/reject", methods=["POST"])  # Route POST pour refuser un compte
@login_required  # Admin requis
def user_reject(uid):  # Passe le compte au statut « refusé »
    database.set_user_status(uid, "rejected")  # Met à jour le statut en base
    _audit("Utilisateur refusé", target=uid)  # Journalise le refus
    return redirect(url_for("users"))  # Retour à la liste des utilisateurs


@app.route("/users/<uid>/block", methods=["POST"])  # Route POST pour bloquer un compte
@login_required  # Admin requis
def user_block(uid):  # Passe le compte au statut « bloqué »
    database.set_user_status(uid, "blocked")  # Met à jour le statut en base
    _audit("Utilisateur bloqué", target=uid)  # Journalise le blocage
    return redirect(url_for("users"))  # Retour à la liste des utilisateurs


@app.route("/users/<uid>")  # Page de détail d'un utilisateur client
@login_required  # Admin requis
def user_detail(uid):  # Affiche le profil et les actions disponibles
    user = database.get_user_by_uid(uid)  # Récupère l'utilisateur par son UID
    if not user:  # Utilisateur introuvable
        return redirect(url_for("users"))  # Redirige vers la liste
    agent_id = database.ensure_agent_for_user(uid, user.get("display_name") or user.get("email"))  # Agent attribué
    agent = database.get_agent(agent_id)  # Fiche de l'agent lié au compte
    if agent:  # Enrichit avec l'état en ligne/hors ligne
        agent = _annotate_online([agent])[0]
    return render_template("user_detail.html", user=user, agent=agent,  # Affiche la fiche + agent attribué
                           ok=False, msg=None, erreur=None)


@app.route("/users/<uid>/edit", methods=["POST"])  # Route POST pour modifier un utilisateur
@login_required  # Admin requis
def user_edit(uid):  # Met à jour le nom affiché du client
    name = (request.form.get("display_name") or "").strip()  # Nouveau nom saisi dans le formulaire
    database.update_user(uid, name)  # Persiste la modification en base
    _audit("Modification utilisateur", target=uid, details=f"nom='{name}'")  # Journalise le changement
    return redirect(url_for("user_detail", uid=uid))  # Retour à la fiche utilisateur


@app.route("/users/<uid>/password", methods=["POST"])  # Route POST pour changer le mot de passe client
@login_required  # Admin requis
def user_password(uid):  # Réinitialise le mot de passe Firebase d'un client
    user = database.get_user_by_uid(uid)  # Récupère le profil utilisateur
    if not user:  # Utilisateur introuvable
        return redirect(url_for("users"))  # Redirige vers la liste
    new_pwd = request.form.get("new_password") or ""  # Nouveau mot de passe saisi par l'admin
    if len(new_pwd) < _MIN_PASSWORD_LEN:  # Longueur minimale requise
        return render_template("user_detail.html", user=user, ok=False, msg=None,
                               erreur=f"Le mot de passe doit faire au moins {_MIN_PASSWORD_LEN} caractères."), 400
    if not firebase_auth.is_ready():  # Firebase non configuré
        return render_template("user_detail.html", user=user, ok=False, msg=None,  # Réaffiche avec erreur
                               erreur="Firebase non configuré : changement impossible."), 503  # Service indisponible
    try:  # Tente la mise à jour côté Firebase Admin SDK
        firebase_auth.update_user_password(uid, new_pwd)  # Change le mot de passe dans Firebase
    except Exception as e:  # Erreur Firebase (compte inexistant, etc.)
        return render_template("user_detail.html", user=user, ok=False, msg=None,  # Réaffiche avec erreur
                               erreur=f"Échec de la mise à jour : {e}"), 500  # Erreur serveur
    notified = False  # Indique si une notification push a été envoyée
    if user.get("fcm_token"):  # Si l'utilisateur a un jeton FCM enregistré
        notified = firebase_auth.send_push(  # Envoie une alerte push de sécurité
            user["fcm_token"], "MoMoGuard — sécurité",  # Destinataire et titre
            "Votre mot de passe a été modifié par l'administrateur. "  # Corps du message
            "Si ce n'est pas vous, contactez le support.",  # Suite du message d'alerte
        )
    msg = ("Mot de passe mis à jour. "  # Message de confirmation pour l'admin
           + ("L'utilisateur a été notifié." if notified  # Précise si push envoyée
              else "(Pas de notification : aucun jeton FCM enregistré pour ce compte.)"))  # Sinon absence de FCM
    _audit("Changement mot de passe utilisateur", target=uid,  # Journalise l'opération
           details=("notifié" if notified else "non notifié"))  # Précise si notification envoyée
    return render_template("user_detail.html", user=database.get_user_by_uid(uid),  # Recharge la fiche à jour
                           ok=True, msg=msg, erreur=None)  # Affiche le succès


# --- Paramètres (seuils de score) ------------------------------------------

@app.route("/settings", methods=["GET", "POST"])  # Page de configuration des seuils de risque
@login_required  # Admin requis
def settings_page():  # Affiche ou enregistre les seuils moyen/élevé
    if request.method == "POST":  # Soumission du formulaire de paramètres
        try:  # Tente de convertir les valeurs en entiers
            moyen = int(request.form.get("seuil_moyen", 25))  # Seuil « moyen » (défaut 25)
            eleve = int(request.form.get("seuil_eleve", 55))  # Seuil « élevé » (défaut 55)
        except ValueError:  # Valeurs non numériques
            m, e = database.get_thresholds()  # Recharge les seuils actuels
            return render_template("settings.html", moyen=m, eleve=e,  # Réaffiche avec erreur
                                   erreur="Valeurs invalides.", ok=False), 400  # Bad request
        if not (0 <= moyen < eleve <= 100):  # Contrainte : 0 ≤ moyen < élevé ≤ 100
            m, e = database.get_thresholds()  # Recharge les seuils actuels
            return render_template("settings.html", moyen=m, eleve=e,  # Réaffiche avec erreur
                                   erreur="Il faut 0 ≤ moyen < élevé ≤ 100.", ok=False), 400  # Bad request
        database.set_thresholds(moyen, eleve)  # Persiste les nouveaux seuils
        _audit("Modification des seuils", details=f"{moyen}/{eleve}")  # Journalise le changement
        return render_template("settings.html", moyen=moyen, eleve=eleve, erreur=None, ok=True)  # Succès
    m, e = database.get_thresholds()  # GET : charge les seuils actuels
    return render_template("settings.html", moyen=m, eleve=e, erreur=None, ok=False)  # Affiche le formulaire


# --- Consentement ----------------------------------------------------------

SCOPES = [  # Périmètres de collecte proposés au formulaire de consentement
    ("clipboard", "Presse-papier (numéros, liens copiés)"),  # Surveillance du presse-papier
    ("link", "Liens reçus ou ouverts"),  # Surveillance des liens
    ("sms", "Messages SMS (Android)"),  # Lecture des SMS sur Android
    ("file", "Fichiers téléchargés"),  # Analyse des fichiers téléchargés
    ("ussd", "Codes USSD composés"),  # Détection des codes USSD
]


@app.route("/consent", methods=["GET", "POST"])  # Formulaire public de consentement éthique
@limiter.limit("20 per minute", methods=["POST"])
def consent():  # Affiche ou enregistre un consentement de participant
    if request.method == "POST":  # Soumission du formulaire
        participant = (request.form.get("participant") or "").strip()  # Nom du participant
        role = (request.form.get("role") or "").strip()  # Rôle (chercheur, sujet, etc.)
        device = (request.form.get("device") or "").strip()  # Appareil utilisé
        scope = request.form.getlist("scope")  # Périmètres cochés (liste)
        comprend = request.form.get("comprend")  # Case « j'ai compris » cochée
        if not participant or not comprend or not scope:  # Champs obligatoires manquants
            return render_template(  # Réaffiche avec message d'erreur
                "consent.html", scopes=SCOPES,  # Template avec la liste des périmètres
                erreur="Renseigne ton nom, coche au moins un périmètre et confirme avoir compris.",  # Message
            ), 400  # Bad request
        database.insert_consent(participant, role, device, scope)  # Enregistre le consentement en base
        return redirect(url_for("consents"))  # Redirige vers la liste (admin)
    return render_template("consent.html", scopes=SCOPES, erreur=None)  # GET : affiche le formulaire vide


@app.route("/consents")  # Page admin listant les consentements enregistrés
@login_required  # Admin requis
def consents():  # Affiche tous les consentements
    return render_template("consents.html", consents=database.get_consents())  # Template avec la liste


@app.route("/consent/<int:cid>/revoke", methods=["POST"])  # Route POST pour révoquer un consentement
@login_required  # Admin requis
def consent_revoke(cid):  # Marque un consentement comme révoqué
    database.revoke_consent(cid)  # Met à jour le statut en base
    _audit("Consentement révoqué", target=str(cid))  # Journalise la révocation
    return redirect(url_for("consents"))  # Retour à la liste des consentements


@app.route("/audit")  # Page du journal d'audit administrateur
@login_required  # Admin requis
def audit():  # Affiche l'historique des actions admin
    return render_template("audit.html", entries=database.get_audit())  # Template avec les entrées


@socketio.on("connect")  # Événement SocketIO : connexion d'un client dashboard
def on_connect():  # Callback à la connexion WebSocket
    if not session.get("admin"):  # OWASP A01 : accès réservé aux admins connectés
        return False
    print("[+] Dashboard connecté (admin authentifié)")


def _lan_ips():
    """Retourne les adresses IPv4 locales (LAN) utilisables par un téléphone."""
    import socket  # Résolution des adresses réseau de la machine
    ips = set()  # Ensemble d'adresses uniques
    try:  # Méthode fiable : ouvre une socket UDP vers l'extérieur pour lire l'IP LAN
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Aucune donnée réellement envoyée
        s.connect(("8.8.8.8", 80))  # Détermine l'interface de sortie
        ips.add(s.getsockname()[0])  # IP locale de cette interface
        s.close()
    except OSError:
        pass  # Pas de réseau : on ignore
    try:  # Complément : toutes les IPv4 associées au nom d'hôte
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])  # Ajoute chaque adresse trouvée
    except OSError:
        pass  # Résolution impossible : on ignore
    return sorted(ip for ip in ips if not ip.startswith("127."))  # Exclut la boucle locale


def main():  # Point d'entrée du serveur MoMoGuard
    """Initialise la base, l'admin et démarre le serveur."""
    database.init_db()  # Crée les tables SQLite si nécessaire
    ensure_default_admin()  # Crée l'admin par défaut au premier lancement
    _maybe_reset_admin_2fa()  # Secours optionnel si la 2FA bloque après un redeploy
    print(f"[Horloge] UTC serveur : {datetime.now(timezone.utc).isoformat()} "
          "(doit coller à l'heure de ton téléphone ±1 min)")
    if firebase_auth.init_firebase():  # Tente d'initialiser Firebase Admin SDK
        print("[Firebase] authentification client activée")  # Firebase opérationnel
    else:  # Clé de service absente ou invalide
        print("[Firebase] clé absente — authentification client désactivée")  # Mode dégradé
        print("[Firebase] fournis FIREBASE_CREDENTIALS_BASE64 (Dokploy) "
              "ou serviceAccountKey.json (local)")
    if threat_intel.is_ready():
        print("[ThreatIntel] Google Safe Browsing activé")
    else:
        print("[ThreatIntel] SAFEBROWSING_API_KEY absente — réputation URL désactivée")
    # En développement, on écoute sur toutes les interfaces (0.0.0.0) pour que
    # l'app mobile sur le même Wi-Fi puisse joindre le serveur. En production,
    # on garde 127.0.0.1 par défaut (à placer derrière un reverse-proxy).
    _defaut_host = "127.0.0.1" if _PRODUCTION else "0.0.0.0"
    host = os.environ.get("MOMOGUARD_HOST", _defaut_host)
    port = int(os.environ.get("MOMOGUARD_PORT", "5000"))
    debug = os.environ.get("MOMOGUARD_DEBUG", "0") == "1"
    if _PRODUCTION and debug:
        print("[!] MOMOGUARD_DEBUG=1 ignoré en production.")
        debug = False
    print("=" * 60)
    print(" MoMoGuard - serveur central")
    print(f" Env       : {'production' if _PRODUCTION else 'development'}")
    print(f" Database  : {database.DATABASE_URL.split('://', 1)[0]}  ({database._DATA_DIR})")
    print(f" Firebase  : {'ON' if firebase_auth.is_ready() else 'OFF'}")
    print(f" SafeBrows : {'ON' if threat_intel.is_ready() else 'OFF'}")
    print(f" Dashboard : http://127.0.0.1:{port}  (connexion requise)")
    print(f" Health    : http://127.0.0.1:{port}/health")
    if host == "0.0.0.0":  # Serveur accessible depuis le réseau local
        lan = _lan_ips()  # Détecte les adresses LAN de ce PC
        if lan:
            print(" Accès mobile (app Android) — mets une de ces URL dans l'app :")
            for ip in lan:  # Affiche chaque adresse joignable par le téléphone
                print(f"   http://{ip}:{port}")
            print(" (le téléphone doit être sur le MÊME Wi-Fi ; autorise le port "
                  f"{port} dans le pare-feu Windows)")
        else:
            print(" [!] Aucune IP LAN détectée — vérifie ta connexion Wi-Fi.")
    else:  # Liaison restreinte : le mobile ne pourra pas joindre le serveur
        print(f" [!] host={host} : l'app mobile ne pourra pas se connecter "
              "(utilise MOMOGUARD_HOST=0.0.0.0).")
    print(f" API       : POST http://{host}:{port}/report")
    if _HTTPS:
        print(" HTTPS     : SESSION_COOKIE_SECURE + ProxyFix activés")
    print("=" * 60)
    # Derrière Dokploy/Traefik : un seul process Python est acceptable.
    # Sans allow_unsafe_werkzeug=True, SocketIO refuse de démarrer en production
    # → conteneur mort → 502 Bad Gateway.
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":  # Exécution directe du module (python -m server.app)
    main()  # Démarre le serveur
