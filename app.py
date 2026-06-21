"""Serveur central MoMoGuard : Flask + Flask-SocketIO + SQLite.

Ajouts de cette version :
  - compte administrateur (connexion, déconnexion, changement de mot de passe) ;
  - gestion des agents (enregistrer, bloquer/débloquer, retirer) ;
  - les rapports d'un agent bloqué sont refusés, et un agent enregistré avec
    un jeton doit le fournir.
"""

import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, session, flash)
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash

import database
import scoring
import firebase_auth

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "momoguard"


def ensure_default_admin():
    """Crée un administrateur par défaut au premier démarrage."""
    if database.count_admins() == 0:
        database.create_admin(
            DEFAULT_ADMIN_USER, generate_password_hash(DEFAULT_ADMIN_PASS)
        )
        print(f"[!] Admin par défaut créé : {DEFAULT_ADMIN_USER} / {DEFAULT_ADMIN_PASS}")
        print("[!] Change ce mot de passe depuis la page « Compte ».")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# --- Authentification ------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        admin = database.get_admin(username)
        if admin and check_password_hash(admin["password_hash"], password):
            session["admin"] = username
            return redirect(url_for("dashboard"))
        return render_template("login.html", erreur="Identifiants incorrects."), 401
    return render_template("login.html", erreur=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    username = session["admin"]
    if request.method == "POST":
        actuel = request.form.get("actuel") or ""
        nouveau = request.form.get("nouveau") or ""
        admin = database.get_admin(username)
        if not check_password_hash(admin["password_hash"], actuel):
            return render_template("account.html", username=username,
                                   erreur="Mot de passe actuel incorrect.", ok=False)
        if len(nouveau) < 6:
            return render_template("account.html", username=username,
                                   erreur="Le nouveau mot de passe doit faire au moins 6 caractères.", ok=False)
        database.update_admin_password(username, generate_password_hash(nouveau))
        return render_template("account.html", username=username, erreur=None, ok=True)
    return render_template("account.html", username=username, erreur=None, ok=False)


# --- Dashboard -------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    admin = database.get_admin(session["admin"])
    mdp_par_defaut = check_password_hash(admin["password_hash"], DEFAULT_ADMIN_PASS)
    return render_template("dashboard.html", mdp_par_defaut=mdp_par_defaut)


@app.route("/api/reports")
@login_required
def api_reports():
    return jsonify({
        "reports": database.get_recent(limit=100),
        "stats": database.get_stats(),
    })


# --- Réception des rapports (agents) ---------------------------------------

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON manquant ou invalide"}), 400

    agent_id = data.get("agent_id", "inconnu")
    platform = data.get("platform", "inconnu")
    event_type = data.get("event_type", "message")
    content = data.get("content", "")
    metadata = data.get("metadata", {})
    token = data.get("token")
    uid = data.get("uid")

    if not content:
        return jsonify({"error": "Le champ 'content' est requis"}), 400

    # Contrôle d'adhésion : si l'agent est rattaché à un compte client,
    # ce compte doit avoir été approuvé par l'admin.
    user = database.get_user_by_uid(uid) if uid else None
    if user and user["status"] != "approved":
        libelle = {
            "pending": "Compte en attente d'approbation",
            "rejected": "Compte refusé",
            "blocked": "Compte bloqué",
        }.get(user["status"], "Compte non approuvé")
        return jsonify({"error": libelle}), 403

    # Contrôle d'accès de l'agent
    agent = database.get_agent(agent_id)
    if agent:
        if agent["status"] == "blocked":
            return jsonify({"error": "Agent bloqué"}), 403
        if agent["token"] and token != agent["token"]:
            return jsonify({"error": "Jeton d'agent invalide"}), 401
        database.touch_agent(agent_id)
    else:
        # Agent inconnu : on l'enregistre automatiquement pour qu'il soit gérable
        database.register_agent(agent_id, "(auto)", platform, None)
        database.touch_agent(agent_id)

    score, level, reasons = scoring.score_event(
        event_type, content, metadata, database.get_thresholds()
    )
    saved = database.insert_report(
        agent_id, platform, event_type, content, metadata, score, level, reasons,
        uid=uid,
    )
    socketio.emit("new_report", saved)

    # Notification push de danger au client concerné (alerte de niveau élevé).
    if level == "eleve" and user and user.get("fcm_token"):
        firebase_auth.send_push(
            user["fcm_token"],
            "MoMoGuard — danger détecté",
            "Un message à haut risque a été repéré sur ton appareil. Vérifie tes alertes.",
        )

    return jsonify({
        "ok": True, "id": saved["id"], "score": score,
        "level": level, "reasons": reasons,
    }), 201


# --- Gestion des agents ----------------------------------------------------

def _annotate_online(agents, window_seconds=120):
    """Marque chaque agent en ligne s'il a été vu dans la fenêtre donnée."""
    now = datetime.now(timezone.utc)
    for a in agents:
        online = False
        if a.get("last_seen"):
            try:
                seen = datetime.fromisoformat(a["last_seen"])
                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=timezone.utc)
                online = (now - seen).total_seconds() <= window_seconds
            except Exception:
                online = False
        a["online"] = online
    return agents


@app.route("/agents", methods=["GET", "POST"])
@login_required
def agents():
    if request.method == "POST":
        agent_id = (request.form.get("agent_id") or "").strip()
        label = (request.form.get("label") or "").strip()
        platform = (request.form.get("platform") or "").strip()
        if not agent_id:
            return render_template("agents.html",
                                   agents=_annotate_online(database.get_agents()),
                                   erreur="L'identifiant de l'agent est requis."), 400
        token = secrets.token_hex(8)
        database.register_agent(agent_id, label or "(sans nom)", platform or "inconnu", token)
        return redirect(url_for("agents"))
    return render_template("agents.html",
                           agents=_annotate_online(database.get_agents()), erreur=None)


@app.route("/agents/<agent_id>/block", methods=["POST"])
@login_required
def agent_block(agent_id):
    database.set_agent_status(agent_id, "blocked")
    return redirect(url_for("agents"))


@app.route("/agents/<agent_id>/unblock", methods=["POST"])
@login_required
def agent_unblock(agent_id):
    database.set_agent_status(agent_id, "active")
    return redirect(url_for("agents"))


@app.route("/agents/<agent_id>/remove", methods=["POST"])
@login_required
def agent_remove(agent_id):
    database.delete_agent(agent_id)
    return redirect(url_for("agents"))


# --- Authentification client (Firebase) ------------------------------------

@app.route("/api/auth/firebase", methods=["POST"])
def auth_firebase():
    """L'app envoie son ID token Firebase. On le vérifie, puis on crée/relie
    l'utilisateur dans MySQL (statut 'pending' tant que l'admin n'a pas approuvé)."""
    if not firebase_auth.is_ready():
        return jsonify({"error": "Firebase non configuré sur le serveur"}), 503

    data = request.get_json(silent=True) or {}
    id_token = data.get("id_token")
    if not id_token:
        return jsonify({"error": "id_token manquant"}), 400

    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception:
        return jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401

    uid = decoded.get("uid")
    email = decoded.get("email", "")
    name = decoded.get("name", "")
    # IP du client (gère le cas d'un proxy via X-Forwarded-For)
    ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
          or request.remote_addr)
    user = database.upsert_user(uid, email, name, ip=ip)

    return jsonify({
        "ok": True,
        "uid": user["uid"],
        "email": user["email"],
        "status": user["status"],
    })


@app.route("/api/my-reports", methods=["POST"])
def my_reports():
    """L'app envoie son ID token ; on renvoie les alertes de CE client."""
    if not firebase_auth.is_ready():
        return jsonify({"error": "Firebase non configuré sur le serveur"}), 503
    data = request.get_json(silent=True) or {}
    id_token = data.get("id_token")
    if not id_token:
        return jsonify({"error": "id_token manquant"}), 400
    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception:
        return jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401

    uid = decoded.get("uid")
    user = database.get_user_by_uid(uid)
    reports = database.get_reports_for_user(uid, limit=100)
    counts = {"total": len(reports), "faible": 0, "moyen": 0, "eleve": 0}
    for r in reports:
        counts[r["level"]] = counts.get(r["level"], 0) + 1
    return jsonify({
        "status": user["status"] if user else "unknown",
        "stats": counts,
        "reports": reports,
    })


@app.route("/api/fcm-token", methods=["POST"])
def fcm_token():
    """L'app enregistre (ou met à jour) son jeton FCM pour recevoir les push."""
    if not firebase_auth.is_ready():
        return jsonify({"error": "Firebase non configuré sur le serveur"}), 503
    data = request.get_json(silent=True) or {}
    id_token = data.get("id_token")
    fcm = data.get("fcm_token")
    if not id_token or not fcm:
        return jsonify({"error": "id_token et fcm_token requis"}), 400
    try:
        decoded = firebase_auth.verify_id_token(id_token)
    except Exception:
        return jsonify({"error": "Jeton Firebase invalide ou expiré"}), 401
    database.set_user_fcm_token(decoded.get("uid"), fcm)
    return jsonify({"ok": True})


# --- Gestion des utilisateurs clients --------------------------------------

@app.route("/users")
@login_required
def users():
    return render_template("users.html", users=database.get_users())


@app.route("/users/<uid>/approve", methods=["POST"])
@login_required
def user_approve(uid):
    database.set_user_status(uid, "approved")
    return redirect(url_for("users"))


@app.route("/users/<uid>/reject", methods=["POST"])
@login_required
def user_reject(uid):
    database.set_user_status(uid, "rejected")
    return redirect(url_for("users"))


@app.route("/users/<uid>/block", methods=["POST"])
@login_required
def user_block(uid):
    database.set_user_status(uid, "blocked")
    return redirect(url_for("users"))


@app.route("/users/<uid>")
@login_required
def user_detail(uid):
    user = database.get_user_by_uid(uid)
    if not user:
        return redirect(url_for("users"))
    return render_template("user_detail.html", user=user, ok=False, msg=None, erreur=None)


@app.route("/users/<uid>/edit", methods=["POST"])
@login_required
def user_edit(uid):
    name = (request.form.get("display_name") or "").strip()
    database.update_user(uid, name)
    return redirect(url_for("user_detail", uid=uid))


@app.route("/users/<uid>/password", methods=["POST"])
@login_required
def user_password(uid):
    user = database.get_user_by_uid(uid)
    if not user:
        return redirect(url_for("users"))
    new_pwd = request.form.get("new_password") or ""
    if len(new_pwd) < 6:
        return render_template("user_detail.html", user=user, ok=False, msg=None,
                               erreur="Le mot de passe doit faire au moins 6 caractères."), 400
    if not firebase_auth.is_ready():
        return render_template("user_detail.html", user=user, ok=False, msg=None,
                               erreur="Firebase non configuré : changement impossible."), 503
    try:
        firebase_auth.update_user_password(uid, new_pwd)
    except Exception as e:
        return render_template("user_detail.html", user=user, ok=False, msg=None,
                               erreur=f"Échec de la mise à jour : {e}"), 500
    notified = False
    if user.get("fcm_token"):
        notified = firebase_auth.send_push(
            user["fcm_token"], "MoMoGuard — sécurité",
            "Votre mot de passe a été modifié par l'administrateur. "
            "Si ce n'est pas vous, contactez le support.",
        )
    msg = ("Mot de passe mis à jour. "
           + ("L'utilisateur a été notifié." if notified
              else "(Pas de notification : aucun jeton FCM enregistré pour ce compte.)"))
    return render_template("user_detail.html", user=database.get_user_by_uid(uid),
                           ok=True, msg=msg, erreur=None)


# --- Paramètres (seuils de score) ------------------------------------------

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    if request.method == "POST":
        try:
            moyen = int(request.form.get("seuil_moyen", 25))
            eleve = int(request.form.get("seuil_eleve", 55))
        except ValueError:
            m, e = database.get_thresholds()
            return render_template("settings.html", moyen=m, eleve=e,
                                   erreur="Valeurs invalides.", ok=False), 400
        if not (0 <= moyen < eleve <= 100):
            m, e = database.get_thresholds()
            return render_template("settings.html", moyen=m, eleve=e,
                                   erreur="Il faut 0 ≤ moyen < élevé ≤ 100.", ok=False), 400
        database.set_thresholds(moyen, eleve)
        return render_template("settings.html", moyen=moyen, eleve=eleve, erreur=None, ok=True)
    m, e = database.get_thresholds()
    return render_template("settings.html", moyen=m, eleve=e, erreur=None, ok=False)


# --- Consentement ----------------------------------------------------------

SCOPES = [
    ("clipboard", "Presse-papier (numéros, liens copiés)"),
    ("link", "Liens reçus ou ouverts"),
    ("sms", "Messages SMS (Android)"),
    ("notification", "Notifications d'apps (WhatsApp, Telegram, etc.)"),
    ("file", "Fichiers téléchargés"),
    ("ussd", "Codes USSD composés"),
]


@app.route("/consent", methods=["GET", "POST"])
def consent():
    if request.method == "POST":
        participant = (request.form.get("participant") or "").strip()
        role = (request.form.get("role") or "").strip()
        device = (request.form.get("device") or "").strip()
        scope = request.form.getlist("scope")
        comprend = request.form.get("comprend")
        if not participant or not comprend or not scope:
            return render_template(
                "consent.html", scopes=SCOPES,
                erreur="Renseigne ton nom, coche au moins un périmètre et confirme avoir compris.",
            ), 400
        database.insert_consent(participant, role, device, scope)
        return redirect(url_for("consents"))
    return render_template("consent.html", scopes=SCOPES, erreur=None)


@app.route("/consents")
@login_required
def consents():
    return render_template("consents.html", consents=database.get_consents())


@app.route("/consent/<int:cid>/revoke", methods=["POST"])
@login_required
def consent_revoke(cid):
    database.revoke_consent(cid)
    return redirect(url_for("consents"))


@socketio.on("connect")
def on_connect():
    print("[+] Un dashboard s'est connecté")


if __name__ == "__main__":
    database.init_db()
    ensure_default_admin()
    if firebase_auth.init_firebase():
        print("[Firebase] authentification client activée")
    else:
        print("[Firebase] clé absente — authentification client désactivée")
    print("=" * 60)
    print(" MoMoGuard - serveur central")
    print(" Dashboard : http://127.0.0.1:5000  (connexion requise)")
    print(" API       : POST http://127.0.0.1:5000/report")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True,
                 allow_unsafe_werkzeug=True)
