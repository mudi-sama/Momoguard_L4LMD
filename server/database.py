"""Couche base de données MoMoGuard — via SQLAlchemy.

Avantage : on bascule entre SQLite et MySQL (WAMP) en changeant UNE ligne,
la variable DATABASE_URL ci-dessous. Le reste du code ne change pas.

  - SQLite (par défaut, aucune installation) :
        sqlite:///momoguard.db
  - MySQL via WAMP (décommente et adapte) :
        mysql+pymysql://root:@127.0.0.1:3306/momoguard
    (sous WAMP, l'utilisateur est « root » et le mot de passe est vide par défaut)
"""

import os  # Accès aux variables d'environnement et aux chemins du système de fichiers
import json  # Sérialisation/désérialisation JSON pour les champs structurés en base
from datetime import datetime, timezone, timedelta  # Horodatage UTC ISO + durée de verrouillage

from sqlalchemy import (create_engine, MetaData, Table, Column, Integer,  # Moteur SQL, schéma et types entiers
                        String, Text, select, insert as sa_insert,  # Chaînes, texte long et requêtes SELECT/INSERT
                        update as sa_update, delete as sa_delete, func,  # Requêtes UPDATE/DELETE et fonctions SQL (COUNT, etc.)
                        inspect, text)  # Introspection du schéma et exécution de SQL brut

# === Choix de la base de données ===========================================
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Répertoire racine du projet (parent de server/)
# Répertoire des données persistantes. En local : racine du projet. En production
# (Docker/Dokploy) : définir MOMOGUARD_DATA_DIR=/app/data et monter un volume
# sur ce dossier pour conserver la base SQLite entre deux déploiements.
_DATA_DIR = os.environ.get("MOMOGUARD_DATA_DIR", _ROOT)  # Dossier où stocker momoguard.db
os.makedirs(_DATA_DIR, exist_ok=True)  # Crée le dossier de données s'il n'existe pas encore
_DEFAULT_DB = "sqlite:///" + os.path.join(_DATA_DIR, "momoguard.db").replace("\\", "/")  # URL SQLite par défaut
DATABASE_URL = os.environ.get("MOMOGUARD_DB", _DEFAULT_DB)  # URL effective : variable d'env ou valeur par défaut SQLite
# Exemple WAMP / MySQL :
# DATABASE_URL = "mysql+pymysql://root:@127.0.0.1:3306/momoguard"
# ===========================================================================

md = MetaData()  # Conteneur SQLAlchemy regroupant toutes les définitions de tables

reports = Table(  # Table des rapports d'événements remontés par les agents
    "reports", md,  # Nom SQL de la table et métadonnées associées
    Column("id", Integer, primary_key=True, autoincrement=True),  # Identifiant unique auto-incrémenté
    Column("agent_id", String(255), nullable=False),  # Identifiant de l'agent émetteur du rapport
    Column("platform", String(64), nullable=False),  # Plateforme source (ex. android, windows)
    Column("event_type", String(32), nullable=False),  # Type d'événement détecté (SMS, appel, etc.)
    Column("content", Text, nullable=False),  # Contenu brut de l'événement signalé
    Column("metadata", Text, nullable=False, default="{}"),  # Métadonnées JSON sérialisées en chaîne
    Column("score", Integer, nullable=False, default=0),  # Score de risque calculé par le moteur de scoring
    Column("level", String(16), nullable=False, default="faible"),  # Niveau d'alerte (faible, moyen, eleve)
    Column("reasons", Text, nullable=False, default="[]"),  # Liste JSON des raisons du score
    Column("created_at", String(40), nullable=False),  # Date/heure de création au format ISO UTC
    Column("uid", String(191)),  # UID Firebase de l'utilisateur concerné (optionnel)
)

consents = Table(  # Table des consentements RGPD des participants à la démo
    "consents", md,  # Nom SQL et métadonnées
    Column("id", Integer, primary_key=True, autoincrement=True),  # Clé primaire auto-incrémentée
    Column("participant", String(255), nullable=False),  # Nom ou identifiant du participant
    Column("role", String(64)),  # Rôle du participant (observateur, victime simulée, etc.)
    Column("device", String(255)),  # Appareil utilisé lors du consentement
    Column("scope", Text, nullable=False, default="[]"),  # Périmètre consenti, stocké en JSON
    Column("agreed_at", String(40), nullable=False),  # Horodatage de l'accord
    Column("revoked_at", String(40)),  # Horodatage de révocation (NULL si actif)
)

admins = Table(  # Table des comptes administrateurs du tableau de bord
    "admins", md,  # Nom SQL et métadonnées
    Column("id", Integer, primary_key=True, autoincrement=True),  # Identifiant interne unique
    Column("username", String(191), nullable=False, unique=True),  # Nom de connexion unique
    Column("password_hash", String(255), nullable=False),  # Mot de passe haché (jamais en clair)
    Column("created_at", String(40), nullable=False),  # Date de création du compte admin
    Column("totp_secret", String(64)),  # Secret TOTP pour l'authentification à deux facteurs
    Column("failed_attempts", Integer, nullable=False, default=0),  # Compteur d'échecs de connexion consécutifs
    Column("locked_until", String(40)),  # Verrouillage temporaire du compte jusqu'à cette date ISO (NULL si libre)
)

agents = Table(  # Table des agents MoMoGuard enregistrés sur le serveur
    "agents", md,  # Nom SQL et métadonnées
    Column("id", Integer, primary_key=True, autoincrement=True),  # Clé primaire interne
    Column("agent_id", String(191), nullable=False, unique=True),  # Identifiant public unique de l'agent
    Column("label", String(255)),  # Libellé descriptif affiché dans l'interface
    Column("platform", String(64)),  # Plateforme de l'agent (android, windows, etc.)
    Column("status", String(16), nullable=False, default="active"),  # État : active, suspended, etc.
    Column("token", String(64)),  # Jeton d'authentification API de l'agent
    Column("created_at", String(40), nullable=False),  # Date d'enregistrement de l'agent
    Column("last_seen", String(40)),  # Dernière activité connue de l'agent
)

users = Table(  # Table des utilisateurs clients authentifiés via Firebase
    "users", md,  # Nom SQL et métadonnées
    Column("id", Integer, primary_key=True, autoincrement=True),  # Identifiant interne
    Column("uid", String(191), nullable=False, unique=True),  # UID Firebase unique
    Column("email", String(255)),  # Adresse e-mail du compte
    Column("display_name", String(255)),  # Nom affiché dans l'application
    Column("status", String(16), nullable=False, default="pending"),  # Statut d'approbation (pending, approved, blocked)
    Column("fcm_token", String(255)),  # Jeton Firebase Cloud Messaging pour les notifications push
    Column("ip", String(64)),  # Dernière adresse IP connue de l'utilisateur
    Column("created_at", String(40), nullable=False),  # Date de première inscription
    Column("approved_at", String(40)),  # Date d'approbation par un administrateur
    Column("last_seen", String(40)),  # Dernière connexion ou activité
)

settings = Table(  # Table clé/valeur pour les paramètres globaux de l'application
    "settings", md,  # Nom SQL et métadonnées
    Column("skey", String(64), primary_key=True),  # Nom du paramètre (clé primaire)
    Column("svalue", String(255)),  # Valeur du paramètre sous forme de chaîne
)

audit_log = Table(  # Journal d'audit pour la traçabilité et la non-répudiation
    "audit_log", md,  # Nom SQL et métadonnées
    Column("id", Integer, primary_key=True, autoincrement=True),  # Identifiant séquentiel de l'entrée
    Column("created_at", String(40), nullable=False),  # Horodatage de l'action auditée
    Column("actor", String(191)),  # Acteur ayant effectué l'action (admin, système, etc.)
    Column("action", String(120), nullable=False),  # Type d'action (login, approve_user, etc.)
    Column("target", String(255)),  # Cible de l'action (uid, agent_id, etc.)
    Column("details", Text),  # Détails complémentaires libres
)


def _make_engine(url):
    """Permet de construire un moteur SQLAlchemy adapté à l'URL de connexion."""
    kwargs = {"pool_pre_ping": True}  # Vérifie la connexion avant chaque emprunt du pool
    if url.startswith("sqlite"):  # Cas particulier SQLite (fichier local, mono-thread par défaut)
        # nécessaire car le serveur tourne en multi-thread
        kwargs["connect_args"] = {"check_same_thread": False}  # Autorise l'accès SQLite depuis plusieurs threads Flask
    return create_engine(url, **kwargs)  # Instancie et retourne le moteur SQLAlchemy


engine = _make_engine(DATABASE_URL)  # Moteur global utilisé par toutes les fonctions de ce module


def set_database_url(url):
    """Permet de changer de base à chaud (utilisé surtout pour les tests)."""
    global engine, DATABASE_URL  # Réassigne les variables module-level partagées
    DATABASE_URL = url  # Met à jour l'URL mémorisée
    engine = _make_engine(url)  # Recrée le moteur pointant vers la nouvelle base


def init_db():
    """Crée les tables manquantes et applique les migrations douces de colonnes."""
    md.create_all(engine)  # Crée toutes les tables définies dans md si elles n'existent pas
    _ensure_column("reports", "uid", "VARCHAR(191)")  # Migration : colonne uid sur reports
    _ensure_column("admins", "totp_secret", "VARCHAR(64)")  # Migration : colonne 2FA sur admins
    _ensure_column("admins", "failed_attempts", "INTEGER DEFAULT 0")  # Migration : compteur d'échecs de connexion
    _ensure_column("admins", "locked_until", "VARCHAR(40)")  # Migration : date de fin de verrouillage du compte
    _ensure_column("users", "ip", "VARCHAR(64)")  # Migration : colonne IP sur users
    _ensure_column("users", "approved_at", "VARCHAR(40)")  # Migration : date d'approbation sur users


def _ensure_column(table_name, column, coltype):
    """Ajoute une colonne manquante sur une table existante (migration douce)."""
    try:
        existing = [c["name"] for c in inspect(engine).get_columns(table_name)]  # Liste des colonnes actuelles
    except Exception:
        return  # Abandon silencieux si la table n'existe pas encore ou erreur d'introspection
    if column not in existing:  # La colonne cible est absente du schéma
        with engine.begin() as conn:  # Transaction automatique (commit ou rollback)
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column} {coltype}"))  # Ajoute la colonne via SQL brut


def _now():
    """Retourne l'horodatage UTC courant au format ISO 8601."""
    return datetime.now(timezone.utc).isoformat()  # Ex. 2026-06-27T12:00:00+00:00


# --- Rapports --------------------------------------------------------------

def insert_report(agent_id, platform, event_type, content, metadata,
                  score, level, reasons, uid=None):
    """Insère un rapport d'événement et retourne le dictionnaire créé."""
    created_at = _now()  # Horodatage de l'insertion
    with engine.begin() as conn:  # Ouvre une transaction d'écriture
        result = conn.execute(sa_insert(reports).values(  # Exécute l'INSERT et capture le résultat
            agent_id=agent_id, platform=platform, event_type=event_type,  # Identité agent, plateforme et type
            content=content, metadata=json.dumps(metadata, ensure_ascii=False),  # Contenu et métadonnées sérialisées
            score=score, level=level,  # Score numérique et niveau textuel
            reasons=json.dumps(reasons, ensure_ascii=False),  # Raisons sérialisées en JSON
            created_at=created_at, uid=uid,  # Horodatage et lien utilisateur optionnel
        ))
        report_id = result.inserted_primary_key[0]  # Récupère l'id auto-généré par la base
    return {  # Retourne le rapport sous forme de dict Python (types natifs, pas JSON string)
        "id": report_id, "agent_id": agent_id, "platform": platform,  # Identifiants et plateforme
        "event_type": event_type, "content": content, "metadata": metadata,  # Type, contenu et métadonnées
        "score": score, "level": level, "reasons": reasons,  # Scoring et explications
        "conseil": _conseil(reasons),  # Conseil de prévention (aligné sur _report_to_dict)
        "categorie": _categorie(reasons),  # Type d'arnaque pour le graphique temps réel
        "created_at": created_at, "uid": uid,  # Horodatage et uid
    }


CONSEILS = [  # Liste de tuples (mots-clés, message) pour les conseils de prévention anti-arnaque
    (("PUK", "SIM"),  # Déclencheurs liés au code PUK ou au remplacement de SIM
     "Un opérateur ne vous demandera jamais votre code PUK ni de remplacer votre SIM par SMS."),  # Conseil associé
    (("code", "mot de passe", "OTP"),  # Mots-clés : codes secrets et OTP
     "Ne communiquez jamais votre code de confirmation ni votre mot de passe, même à une personne se présentant comme un agent."),  # Conseil
    (("agent",),  # Mot-clé unique : usurpation d'agent
     "Un vrai agent ne vous demande jamais d'effectuer une opération à distance avec un code."),  # Conseil
    (("URL", "lien", "domaine", "raccourci", "malveillante", "phishing"),  # Mots-clés liés au phishing par lien
     "Ne cliquez pas sur les liens reçus par SMS : ouvrez vous-même l'application officielle."),  # Conseil
    (("gain", "loterie", "cadeau"),  # Arnaques à la loterie ou au faux gain
     "Une promesse de gain qui réclame des frais à l'avance est une arnaque."),  # Conseil
    (("multiplier",),  # Schéma « envoyez X, recevez Y »
     "Aucun service ne multiplie votre argent : « envoyez X, recevez Y » est une arnaque."),  # Conseil
    (("erreur", "rembours"),  # Faux virement ou remboursement par erreur
     "En cas d'« envoi par erreur », ne renvoyez rien et contactez votre opérateur."),  # Conseil
    (("frais", "déblocage", "debloquer"),  # Frais de déblocage de compte
     "Aucun déblocage de compte ne se paie par transfert Mobile Money."),  # Conseil
]


def _conseil(reasons):
    """Renvoie un conseil de prévention adapté aux raisons de l'alerte."""
    texte = " ".join(reasons).lower()  # Concatène les raisons en une seule chaîne minuscule pour la recherche
    for cles, conseil in CONSEILS:  # Parcourt chaque règle mot-clés → message
        if any(c.lower() in texte for c in cles):  # Si au moins un mot-clé apparaît dans les raisons
            return conseil  # Retourne le premier conseil correspondant
    return ""  # Aucune règle ne correspond : pas de conseil


# Taxonomie des arnaques : (libellé, mots-clés cherchés dans les raisons).
# L'ordre définit la priorité : la première catégorie qui correspond gagne.
# Les plus spécifiques (SIM swap, faux agent…) passent avant le phishing générique.
CATEGORIES = [
    ("SIM swap (PUK)", ("sim swap", "code puk")),  # Remplacement de SIM / code PUK
    ("Vol de code / OTP", ("partage d'un code",)),  # Demande de communiquer un code secret
    ("Faux agent", ("agent opérateur",)),  # Usurpation d'un agent Mobile Money
    ("Arnaque au remboursement", ("remboursez-moi", "envoi par erreur",  # Faux virement « par erreur »
                                   "arnaque au remboursement")),
    ("Multiplication d'argent", ("multiplier l'argent",)),  # « Envoyez X, recevez Y »
    ("Frais fictifs", ("frais pour débloquer", "arnaque aux frais")),  # Frais de déblocage imaginaires
    ("Loterie / faux gain", ("appât au gain", "loterie")),  # Tombola, cadeau, gain piégé
    ("Code USSD suspect", ("code ussd",)),  # Séquence *…# potentiellement dictée
    ("Fichier malveillant", ("fichier exécutable",)),  # Pièce jointe .exe/.apk, etc.
    ("Usurpation d'expéditeur", ("numéro personnel",)),  # Opérateur imité depuis un mobile perso
    ("Presse-papier à risque", ("copié",)),  # Numéro de bénéficiaire copié/substitué
    ("Phishing (lien piégé)", ("adresse ip brute", "lien raccourci",  # Liens et domaines trompeurs
                               "extension de domaine", "domaine imitant",
                               "connexion non sécurisée", "combiné à un lien",
                               "url signalée", "malveillante")),
    ("Ingénierie sociale", ("vocabulaire d'arnaque",)),  # Lexique d'arnaque sans autre signal fort
]


def _categorie(reasons):
    """Déduit le type d'arnaque à partir des raisons ; None si rien de suspect."""
    texte = " ".join(reasons).lower()  # Fusionne les raisons en une chaîne minuscule
    if not texte or "aucun signal" in texte:  # Aucune règle déclenchée → pas une arnaque
        return None
    for label, cles in CATEGORIES:  # Parcourt la taxonomie par ordre de priorité
        if any(c in texte for c in cles):  # Première catégorie dont un mot-clé apparaît
            return label  # Renvoie son libellé
    return "Autre signal suspect"  # Signaux présents mais hors taxonomie explicite


def _report_to_dict(r):
    """Convertit une ligne SQLAlchemy (mapping) en dictionnaire rapport enrichi."""
    reasons = json.loads(r["reasons"])  # Désérialise la liste JSON des raisons
    return {  # Construit le dict exposé à l'API et aux templates
        "id": r["id"], "agent_id": r["agent_id"], "platform": r["platform"],  # Identifiants de base
        "event_type": r["event_type"], "content": r["content"],  # Type et contenu de l'événement
        "metadata": json.loads(r["metadata"]), "score": r["score"],  # Métadonnées dict et score
        "level": r["level"], "reasons": reasons,  # Niveau et raisons en listes Python
        "conseil": _conseil(reasons),  # Conseil de prévention calculé à partir des raisons
        "categorie": _categorie(reasons),  # Type d'arnaque déduit des raisons (None si RAS)
        "created_at": r["created_at"],  # Horodatage brut
        "uid": r["uid"] if "uid" in r else None,  # UID utilisateur si la colonne existe dans la ligne
    }


def get_recent(limit=100):
    """Retourne les rapports les plus récents, limités par défaut à 100."""
    with engine.connect() as conn:  # Connexion en lecture seule (pas de transaction d'écriture)
        rows = conn.execute(  # Exécute la requête SELECT
            select(reports).order_by(reports.c.id.desc()).limit(limit)  # Tri décroissant par id, avec limite
        ).mappings().all()  # Récupère toutes les lignes sous forme de mappings nommés
    return [_report_to_dict(r) for r in rows]  # Transforme chaque ligne en dict enrichi


def get_reports_for_user(uid, limit=100):
    """Retourne les rapports associés à un UID Firebase donné."""
    with engine.connect() as conn:  # Connexion lecture
        rows = conn.execute(  # SELECT filtré par utilisateur
            select(reports).where(reports.c.uid == uid)  # Filtre sur l'UID Firebase
            .order_by(reports.c.id.desc()).limit(limit)  # Plus récents en premier, avec limite
        ).mappings().all()  # Liste de mappings
    return [_report_to_dict(r) for r in rows]  # Conversion en dicts


def get_stats():
    """Agrège le nombre de rapports par niveau de risque."""
    with engine.connect() as conn:  # Connexion lecture
        rows = conn.execute(  # GROUP BY level avec COUNT
            select(reports.c.level, func.count().label("n")).group_by(reports.c.level)  # Compte par niveau
        ).all()  # Liste de tuples (level, n)
    stats = {"total": 0, "faible": 0, "moyen": 0, "eleve": 0}  # Structure de sortie avec compteurs initialisés
    for level, n in rows:  # Parcourt chaque groupe retourné par SQL
        stats[level] = n  # Enregistre le décompte pour ce niveau
        stats["total"] += n  # Incrémente le total global
    return stats  # Retourne les statistiques agrégées


def get_category_stats():
    """Compte les alertes moyennes/élevées par type d'arnaque (pour le graphique)."""
    with engine.connect() as conn:  # Connexion lecture seule
        rows = conn.execute(  # Récupère raisons + niveau de chaque rapport
            select(reports.c.reasons, reports.c.level)
        ).mappings().all()  # Liste de mappings {reasons, level}
    counts = {}  # Dictionnaire libellé de catégorie → nombre d'alertes
    for r in rows:  # Parcourt chaque rapport
        if r["level"] == "faible":  # On ne compte que les vraies menaces (moyen/élevé)
            continue  # Ignore les événements faibles (RAS)
        cat = _categorie(json.loads(r["reasons"]))  # Déduit la catégorie depuis les raisons
        if not cat:  # Aucune catégorie (rien de suspect)
            continue  # Passe au rapport suivant
        counts[cat] = counts.get(cat, 0) + 1  # Incrémente le compteur de cette catégorie
    return counts  # Renvoie la répartition par type d'arnaque


# --- Consentements ---------------------------------------------------------

def insert_consent(participant, role, device, scope):
    """Enregistre un nouveau consentement participant et retourne l'enregistrement créé."""
    agreed_at = _now()  # Horodatage de l'accord
    with engine.begin() as conn:  # Transaction d'insertion
        result = conn.execute(sa_insert(consents).values(  # INSERT dans consents
            participant=participant, role=role, device=device,  # Identité du participant
            scope=json.dumps(scope, ensure_ascii=False), agreed_at=agreed_at,  # Périmètre JSON et date
        ))
        cid = result.inserted_primary_key[0]  # Id du consentement créé
    return {  # Dict retourné à l'appelant
        "id": cid, "participant": participant, "role": role, "device": device,  # Champs identitaires
        "scope": scope, "agreed_at": agreed_at, "revoked_at": None,  # Périmètre, date d'accord, pas encore révoqué
    }


def get_consents():
    """Liste tous les consentements, du plus récent au plus ancien."""
    with engine.connect() as conn:  # Connexion lecture
        rows = conn.execute(  # SELECT ordonné
            select(consents).order_by(consents.c.id.desc())  # Tri par id décroissant
        ).mappings().all()  # Toutes les lignes
    return [{  # List comprehension construisant les dicts
        "id": r["id"], "participant": r["participant"], "role": r["role"],  # Identité
        "device": r["device"], "scope": json.loads(r["scope"]),  # Appareil et périmètre désérialisé
        "agreed_at": r["agreed_at"], "revoked_at": r["revoked_at"],  # Dates accord et révocation
    } for r in rows]


def revoke_consent(consent_id):
    """Marque un consentement actif comme révoqué à l'instant présent."""
    with engine.begin() as conn:  # Transaction d'écriture
        conn.execute(  # UPDATE conditionnel
            sa_update(consents)  # Table cible
            .where(consents.c.id == consent_id, consents.c.revoked_at.is_(None))  # Seulement si non déjà révoqué
            .values(revoked_at=_now())  # Pose la date de révocation
        )


# --- Administrateurs -------------------------------------------------------

def count_admins():
    """Compte le nombre total de comptes administrateurs."""
    with engine.connect() as conn:  # Connexion lecture
        return conn.execute(select(func.count()).select_from(admins)).scalar()  # COUNT(*) sur admins, valeur scalaire


def create_admin(username, password_hash):
    """Crée un nouveau compte administrateur avec mot de passe déjà haché."""
    with engine.begin() as conn:  # Transaction d'insertion
        conn.execute(sa_insert(admins).values(  # INSERT admin
            username=username, password_hash=password_hash, created_at=_now(),  # Identifiants et horodatage
        ))


def get_admin(username):
    """Récupère un administrateur par son nom d'utilisateur, ou None."""
    with engine.connect() as conn:  # Connexion lecture
        row = conn.execute(  # SELECT unique
            select(admins).where(admins.c.username == username)  # Filtre par username
        ).mappings().first()  # Première ligne ou None
    return dict(row) if row else None  # Dict Python ou absence


def update_admin_password(username, password_hash):
    """Met à jour le hash du mot de passe d'un administrateur existant."""
    with engine.begin() as conn:  # Transaction
        conn.execute(  # UPDATE
            sa_update(admins).where(admins.c.username == username)  # Cible l'admin par username
            .values(password_hash=password_hash)  # Nouveau hash
        )


def set_admin_totp(username, secret):
    """Active (secret) ou désactive (None) la 2FA pour un administrateur."""
    with engine.begin() as conn:  # Transaction
        conn.execute(  # UPDATE du secret TOTP
            sa_update(admins).where(admins.c.username == username)  # Admin ciblé
            .values(totp_secret=secret)  # Secret ou None pour désactiver
        )


def admin_lock_remaining(username):
    """Renvoie le nombre de secondes de verrouillage restantes pour un compte (0 si libre)."""
    admin = get_admin(username)  # Récupère la fiche admin
    if not admin or not admin.get("locked_until"):  # Compte inconnu ou non verrouillé
        return 0  # Aucun verrouillage actif
    try:
        until = datetime.fromisoformat(admin["locked_until"])  # Parse la date de fin de verrouillage
    except (TypeError, ValueError):  # Valeur corrompue ou absente
        return 0  # On considère le compte libre
    if until.tzinfo is None:  # Date stockée sans fuseau horaire
        until = until.replace(tzinfo=timezone.utc)  # Normalise en UTC pour la comparaison
    remaining = (until - datetime.now(timezone.utc)).total_seconds()  # Temps restant en secondes
    return int(remaining) if remaining > 0 else 0  # Secondes restantes, jamais négatif


def record_failed_login(username, max_failures=4, lockout_minutes=15):
    """Comptabilise un échec de connexion pour un compte ; le verrouille au seuil atteint.

    Le compteur est porté par le compte lui-même : le verrouillage est donc
    indépendant de l'adresse IP source. Retourne (nb_echecs, date_verrou ou None).
    """
    admin = get_admin(username)  # Fiche du compte visé
    if not admin:  # Compte inconnu : rien à comptabiliser (pas de fuite d'information)
        return 0, None
    attempts = (admin.get("failed_attempts") or 0) + 1  # Incrémente le compteur d'échecs consécutifs
    vals = {"failed_attempts": attempts}  # Valeurs à écrire en base
    locked_until = None  # Par défaut, pas de verrouillage déclenché
    if attempts >= max_failures:  # Seuil atteint : on verrouille le compte
        locked_until = (datetime.now(timezone.utc)  # Date de fin de verrouillage
                        + timedelta(minutes=lockout_minutes)).isoformat()
        vals["locked_until"] = locked_until  # Pose le verrou
        vals["failed_attempts"] = 0  # Réinitialise le compteur (le verrou prend le relais)
    with engine.begin() as conn:  # Transaction d'écriture
        conn.execute(sa_update(admins).where(admins.c.username == username).values(**vals))  # Applique la mise à jour
    return attempts, locked_until  # Nombre d'échecs et éventuelle date de verrou


def reset_failed_login(username):
    """Réinitialise le compteur d'échecs et lève tout verrouillage (connexion réussie)."""
    with engine.begin() as conn:  # Transaction
        conn.execute(  # Remet le compteur à zéro et efface le verrou
            sa_update(admins).where(admins.c.username == username)
            .values(failed_attempts=0, locked_until=None)
        )


# --- Agents ----------------------------------------------------------------

def _agent_to_dict(r):
    """Convertit une ligne agents en dictionnaire Python."""
    return {  # Mapping colonne → clé dict
        "id": r["id"], "agent_id": r["agent_id"], "label": r["label"],  # Identifiants et libellé
        "platform": r["platform"], "status": r["status"], "token": r["token"],  # Plateforme, statut, jeton
        "created_at": r["created_at"], "last_seen": r["last_seen"],  # Dates création et dernière activité
    }


def register_agent(agent_id, label, platform, token=None):
    """Enregistre un agent, ou réémet son jeton s'il existe déjà.

    Un ré-enregistrement depuis le dashboard régénère le jeton : le jeton
    affiché correspond ainsi toujours à celui stocké en base (évite les 401)."""
    existing = get_agent(agent_id)  # Vérifie si l'agent est déjà connu
    if existing is None:  # Première inscription
        with engine.begin() as conn:  # Transaction
            conn.execute(sa_insert(agents).values(  # INSERT nouvel agent
                agent_id=agent_id, label=label, platform=platform,  # Identité
                status="active", token=token, created_at=_now(),  # Actif par défaut, jeton optionnel, date
            ))
    else:  # Agent déjà présent : on met à jour le libellé/plateforme et le jeton fourni
        valeurs = {"label": label, "platform": platform}  # Champs d'identité rafraîchis
        if token is not None:  # Réémission d'un nouveau jeton fonctionnel
            valeurs["token"] = token  # Le jeton stocké correspondra à celui affiché
        with engine.begin() as conn:  # Transaction
            conn.execute(  # UPDATE de la fiche existante
                sa_update(agents).where(agents.c.agent_id == agent_id).values(**valeurs)
            )
    return get_agent(agent_id)  # Retourne la fiche à jour (existante ou nouvellement créée)


def get_agent(agent_id):
    """Retourne la fiche d'un agent par son agent_id public, ou None."""
    with engine.connect() as conn:  # Connexion lecture
        row = conn.execute(  # SELECT
            select(agents).where(agents.c.agent_id == agent_id)  # Filtre par agent_id
        ).mappings().first()  # Une ligne max
    return _agent_to_dict(row) if row else None  # Dict ou None


def get_agents():
    """Liste tous les agents enregistrés, du plus récent au plus ancien."""
    with engine.connect() as conn:  # Connexion lecture
        rows = conn.execute(  # SELECT ordonné
            select(agents).order_by(agents.c.id.desc())  # Tri décroissant
        ).mappings().all()  # Toutes les lignes
    return [_agent_to_dict(r) for r in rows]  # Liste de dicts


def set_agent_status(agent_id, status):
    """Modifie le statut d'un agent (active, suspended, etc.)."""
    with engine.begin() as conn:  # Transaction
        conn.execute(  # UPDATE statut
            sa_update(agents).where(agents.c.agent_id == agent_id).values(status=status)  # Cible et nouvelle valeur
        )


def delete_agent(agent_id):
    """Supprime définitivement un agent de la base."""
    with engine.begin() as conn:  # Transaction
        conn.execute(sa_delete(agents).where(agents.c.agent_id == agent_id))  # DELETE par agent_id


def touch_agent(agent_id):
    """Met à jour last_seen à maintenant pour signaler une activité récente."""
    with engine.begin() as conn:  # Transaction
        conn.execute(  # UPDATE last_seen
            sa_update(agents).where(agents.c.agent_id == agent_id).values(last_seen=_now())  # Horodatage courant
        )


# --- Utilisateurs clients (authentifiés via Firebase) ----------------------

def _user_to_dict(r):
    """Convertit une ligne users en dictionnaire Python."""
    return {  # Mapping des colonnes utilisateur
        "id": r["id"], "uid": r["uid"], "email": r["email"],  # Identifiants Firebase et e-mail
        "display_name": r["display_name"], "status": r["status"],  # Nom affiché et statut d'approbation
        "fcm_token": r["fcm_token"], "created_at": r["created_at"],  # Push token et date création
        "last_seen": r["last_seen"],  # Dernière activité
        "ip": r["ip"] if "ip" in r else None,  # IP si colonne présente (compatibilité anciennes bases)
        "approved_at": r["approved_at"] if "approved_at" in r else None,  # Date approbation si disponible
    }


def upsert_user(uid, email, display_name, ip=None):
    """Crée l'utilisateur s'il n'existe pas (statut 'pending'), sinon le met à jour."""
    existing = get_user_by_uid(uid)  # Recherche par UID Firebase
    now = _now()  # Horodatage unique pour created_at / last_seen
    with engine.begin() as conn:  # Transaction
        if existing is None:  # Nouvel utilisateur
            conn.execute(sa_insert(users).values(  # INSERT
                uid=uid, email=email, display_name=display_name,  # Identité
                status="pending", ip=ip, created_at=now, last_seen=now,  # En attente d'approbation admin
            ))
        else:  # Utilisateur déjà connu : mise à jour
            vals = {"email": email, "display_name": display_name, "last_seen": now}  # Champs à rafraîchir
            if ip:  # IP fournie cette fois
                vals["ip"] = ip  # Met à jour l'adresse IP
            conn.execute(sa_update(users).where(users.c.uid == uid).values(**vals))  # UPDATE par uid
    ensure_agent_for_user(uid, display_name or email)  # Attribue (ou confirme) l'agent lié au compte
    return get_user_by_uid(uid)  # Retourne la fiche à jour


def import_firebase_user(uid, email, display_name):
    """Insère un compte Firebase dans la base locale s'il est absent.

    Utilisé par la synchronisation Firebase → dashboard. N'écrase jamais un
    compte existant (préserve son statut d'approbation). Retourne True si un
    nouveau compte a été créé, False s'il existait déjà."""
    if get_user_by_uid(uid) is not None:  # Compte déjà présent : on ne touche à rien
        ensure_agent_for_user(uid, display_name or email)  # Garantit tout de même l'agent attribué
        return False
    with engine.begin() as conn:  # Transaction
        conn.execute(sa_insert(users).values(  # INSERT du compte importé
            uid=uid, email=email, display_name=display_name,  # Identité Firebase
            status="pending", created_at=_now(),  # En attente d'approbation admin
        ))
    ensure_agent_for_user(uid, display_name or email)  # Crée l'agent attribué à ce compte
    return True  # Nouveau compte créé


def ensure_agent_for_user(uid, label=None):
    """Garantit qu'un agent est attribué à ce compte utilisateur (Android).

    L'agent porte l'identifiant `android-<uid>` (le même que celui utilisé pour
    les rapports Android). Créé s'il n'existe pas encore. Retourne l'agent_id."""
    agent_id = f"android-{uid}"  # Identifiant d'agent dérivé de l'UID (relation 1:1 compte↔agent)
    if get_agent(agent_id) is None:  # Aucun agent attribué pour l'instant
        libelle = (label or agent_id)  # Libellé lisible (nom/email si dispo)
        register_agent(agent_id, f"{libelle} (Android)", "android", token=None)  # Sans jeton : auth par compte Firebase
    return agent_id  # Identifiant de l'agent attribué


def update_user(uid, display_name):
    """Met à jour uniquement le nom affiché d'un utilisateur."""
    with engine.begin() as conn:  # Transaction
        conn.execute(sa_update(users).where(users.c.uid == uid)  # Cible l'utilisateur
                     .values(display_name=display_name))  # Nouveau display_name


def get_user_by_uid(uid):
    """Retourne un utilisateur par son UID Firebase, ou None."""
    with engine.connect() as conn:  # Connexion lecture
        row = conn.execute(  # SELECT
            select(users).where(users.c.uid == uid)  # Filtre uid
        ).mappings().first()  # Première ligne
    return _user_to_dict(row) if row else None  # Dict ou None


def get_users():
    """Liste tous les utilisateurs, du plus récent au plus ancien."""
    with engine.connect() as conn:  # Connexion lecture
        rows = conn.execute(select(users).order_by(users.c.id.desc())).mappings().all()  # SELECT trié
    return [_user_to_dict(r) for r in rows]  # Liste de dicts


def set_user_status(uid, status):
    """Change le statut d'un utilisateur ; pose approved_at si status == 'approved'."""
    vals = {"status": status}  # Dictionnaire de valeurs à écrire
    if status == "approved":  # Passage en approuvé
        vals["approved_at"] = _now()  # Enregistre la date d'approbation
    with engine.begin() as conn:  # Transaction
        conn.execute(sa_update(users).where(users.c.uid == uid).values(**vals))  # UPDATE


def set_user_fcm_token(uid, token):
    """Enregistre ou remplace le jeton FCM pour les notifications push."""
    with engine.begin() as conn:  # Transaction
        conn.execute(sa_update(users).where(users.c.uid == uid).values(fcm_token=token))  # UPDATE fcm_token


# --- Paramètres (clé/valeur) -----------------------------------------------

def get_setting(key, default=None):
    """Lit une valeur de paramètre par clé, ou default si absente."""
    with engine.connect() as conn:  # Connexion lecture
        row = conn.execute(  # SELECT de la valeur uniquement
            select(settings.c.svalue).where(settings.c.skey == key)  # Filtre par clé
        ).first()  # Une ligne ou None
    return row[0] if row else default  # Valeur trouvée ou défaut


def set_setting(key, value):
    """Crée ou met à jour un paramètre clé/valeur (valeur convertie en chaîne)."""
    with engine.begin() as conn:  # Transaction
        existing = conn.execute(  # Vérifie si la clé existe déjà
            select(settings.c.skey).where(settings.c.skey == key)  # SELECT clé
        ).first()  # Première ligne ou None
        if existing:  # Mise à jour
            conn.execute(sa_update(settings).where(settings.c.skey == key)  # UPDATE
                         .values(svalue=str(value)))  # Nouvelle valeur stringifiée
        else:  # Insertion
            conn.execute(sa_insert(settings).values(skey=key, svalue=str(value)))  # INSERT nouvelle paire


def get_thresholds():
    """Renvoie (seuil_moyen, seuil_eleve), avec valeurs par défaut (25, 55)."""
    try:
        moyen = int(get_setting("seuil_moyen", 25))  # Seuil niveau moyen depuis settings ou 25
        eleve = int(get_setting("seuil_eleve", 55))  # Seuil niveau élevé depuis settings ou 55
    except (TypeError, ValueError):  # Valeur non entière ou corrompue en base
        moyen, eleve = 25, 55  # Repli sur les défauts hardcodés
    return moyen, eleve  # Tuple des deux seuils


def set_thresholds(moyen, eleve):
    """Persiste les seuils de scoring moyen et élevé dans settings."""
    set_setting("seuil_moyen", moyen)  # Écrit le seuil moyen
    set_setting("seuil_eleve", eleve)  # Écrit le seuil élevé


# --- Journal d'audit (non-répudiation) -------------------------------------

def add_audit(actor, action, target=None, details=None):
    """Ajoute une entrée au journal d'audit."""
    with engine.begin() as conn:  # Transaction
        conn.execute(sa_insert(audit_log).values(  # INSERT audit
            created_at=_now(), actor=actor or "?", action=action,  # Horodatage, acteur (?? si absent), action
            target=target, details=details,  # Cible et détails optionnels
        ))


def get_audit(limit=200):
    """Retourne les entrées d'audit les plus récentes."""
    with engine.connect() as conn:  # Connexion lecture
        rows = conn.execute(  # SELECT audit
            select(audit_log).order_by(audit_log.c.id.desc()).limit(limit)  # Plus récentes en premier
        ).mappings().all()  # Toutes les lignes limitées
    return [dict(r) for r in rows]  # Liste de dicts bruts (sans transformation métier)
