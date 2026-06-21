"""Couche base de données MoMoGuard — via SQLAlchemy.

Avantage : on bascule entre SQLite et MySQL (WAMP) en changeant UNE ligne,
la variable DATABASE_URL ci-dessous. Le reste du code ne change pas.

  - SQLite (par défaut, aucune installation) :
        sqlite:///momoguard.db
  - MySQL via WAMP (décommente et adapte) :
        mysql+pymysql://root:@127.0.0.1:3306/momoguard
    (sous WAMP, l'utilisateur est « root » et le mot de passe est vide par défaut)
"""

import os
import json
from datetime import datetime, timezone

from sqlalchemy import (create_engine, MetaData, Table, Column, Integer,
                        String, Text, select, insert as sa_insert,
                        update as sa_update, delete as sa_delete, func,
                        inspect, text)

# === Choix de la base de données ===========================================
DATABASE_URL = os.environ.get("MOMOGUARD_DB", "sqlite:///momoguard.db")
# Exemple WAMP / MySQL :
# DATABASE_URL = "mysql+pymysql://root:@127.0.0.1:3306/momoguard"
# ===========================================================================

md = MetaData()

reports = Table(
    "reports", md,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("agent_id", String(255), nullable=False),
    Column("platform", String(64), nullable=False),
    Column("event_type", String(32), nullable=False),
    Column("content", Text, nullable=False),
    Column("metadata", Text, nullable=False, default="{}"),
    Column("score", Integer, nullable=False, default=0),
    Column("level", String(16), nullable=False, default="faible"),
    Column("reasons", Text, nullable=False, default="[]"),
    Column("created_at", String(40), nullable=False),
    Column("uid", String(191)),
)

consents = Table(
    "consents", md,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("participant", String(255), nullable=False),
    Column("role", String(64)),
    Column("device", String(255)),
    Column("scope", Text, nullable=False, default="[]"),
    Column("agreed_at", String(40), nullable=False),
    Column("revoked_at", String(40)),
)

admins = Table(
    "admins", md,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(191), nullable=False, unique=True),
    Column("password_hash", String(255), nullable=False),
    Column("created_at", String(40), nullable=False),
)

agents = Table(
    "agents", md,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("agent_id", String(191), nullable=False, unique=True),
    Column("label", String(255)),
    Column("platform", String(64)),
    Column("status", String(16), nullable=False, default="active"),
    Column("token", String(64)),
    Column("created_at", String(40), nullable=False),
    Column("last_seen", String(40)),
)

users = Table(
    "users", md,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("uid", String(191), nullable=False, unique=True),
    Column("email", String(255)),
    Column("display_name", String(255)),
    Column("status", String(16), nullable=False, default="pending"),
    Column("fcm_token", String(255)),
    Column("ip", String(64)),
    Column("created_at", String(40), nullable=False),
    Column("approved_at", String(40)),
    Column("last_seen", String(40)),
)

settings = Table(
    "settings", md,
    Column("skey", String(64), primary_key=True),
    Column("svalue", String(255)),
)


def _make_engine(url):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        # nécessaire car le serveur tourne en multi-thread
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


engine = _make_engine(DATABASE_URL)


def set_database_url(url):
    """Permet de changer de base à chaud (utilisé surtout pour les tests)."""
    global engine, DATABASE_URL
    DATABASE_URL = url
    engine = _make_engine(url)


def init_db():
    md.create_all(engine)
    _ensure_column("reports", "uid", "VARCHAR(191)")
    _ensure_column("users", "ip", "VARCHAR(64)")
    _ensure_column("users", "approved_at", "VARCHAR(40)")


def _ensure_column(table_name, column, coltype):
    """Ajoute une colonne manquante sur une table existante (migration douce)."""
    try:
        existing = [c["name"] for c in inspect(engine).get_columns(table_name)]
    except Exception:
        return
    if column not in existing:
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column} {coltype}"))


def _now():
    return datetime.now(timezone.utc).isoformat()


# --- Rapports --------------------------------------------------------------

def insert_report(agent_id, platform, event_type, content, metadata,
                  score, level, reasons, uid=None):
    created_at = _now()
    with engine.begin() as conn:
        result = conn.execute(sa_insert(reports).values(
            agent_id=agent_id, platform=platform, event_type=event_type,
            content=content, metadata=json.dumps(metadata, ensure_ascii=False),
            score=score, level=level,
            reasons=json.dumps(reasons, ensure_ascii=False),
            created_at=created_at, uid=uid,
        ))
        report_id = result.inserted_primary_key[0]
    return {
        "id": report_id, "agent_id": agent_id, "platform": platform,
        "event_type": event_type, "content": content, "metadata": metadata,
        "score": score, "level": level, "reasons": reasons,
        "created_at": created_at, "uid": uid,
    }


def _report_to_dict(r):
    return {
        "id": r["id"], "agent_id": r["agent_id"], "platform": r["platform"],
        "event_type": r["event_type"], "content": r["content"],
        "metadata": json.loads(r["metadata"]), "score": r["score"],
        "level": r["level"], "reasons": json.loads(r["reasons"]),
        "created_at": r["created_at"],
        "uid": r["uid"] if "uid" in r else None,
    }


def get_recent(limit=100):
    with engine.connect() as conn:
        rows = conn.execute(
            select(reports).order_by(reports.c.id.desc()).limit(limit)
        ).mappings().all()
    return [_report_to_dict(r) for r in rows]


def get_reports_for_user(uid, limit=100):
    with engine.connect() as conn:
        rows = conn.execute(
            select(reports).where(reports.c.uid == uid)
            .order_by(reports.c.id.desc()).limit(limit)
        ).mappings().all()
    return [_report_to_dict(r) for r in rows]


def get_stats():
    with engine.connect() as conn:
        rows = conn.execute(
            select(reports.c.level, func.count().label("n")).group_by(reports.c.level)
        ).all()
    stats = {"total": 0, "faible": 0, "moyen": 0, "eleve": 0}
    for level, n in rows:
        stats[level] = n
        stats["total"] += n
    return stats


# --- Consentements ---------------------------------------------------------

def insert_consent(participant, role, device, scope):
    agreed_at = _now()
    with engine.begin() as conn:
        result = conn.execute(sa_insert(consents).values(
            participant=participant, role=role, device=device,
            scope=json.dumps(scope, ensure_ascii=False), agreed_at=agreed_at,
        ))
        cid = result.inserted_primary_key[0]
    return {
        "id": cid, "participant": participant, "role": role, "device": device,
        "scope": scope, "agreed_at": agreed_at, "revoked_at": None,
    }


def get_consents():
    with engine.connect() as conn:
        rows = conn.execute(
            select(consents).order_by(consents.c.id.desc())
        ).mappings().all()
    return [{
        "id": r["id"], "participant": r["participant"], "role": r["role"],
        "device": r["device"], "scope": json.loads(r["scope"]),
        "agreed_at": r["agreed_at"], "revoked_at": r["revoked_at"],
    } for r in rows]


def revoke_consent(consent_id):
    with engine.begin() as conn:
        conn.execute(
            sa_update(consents)
            .where(consents.c.id == consent_id, consents.c.revoked_at.is_(None))
            .values(revoked_at=_now())
        )


# --- Administrateurs -------------------------------------------------------

def count_admins():
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(admins)).scalar()


def create_admin(username, password_hash):
    with engine.begin() as conn:
        conn.execute(sa_insert(admins).values(
            username=username, password_hash=password_hash, created_at=_now(),
        ))


def get_admin(username):
    with engine.connect() as conn:
        row = conn.execute(
            select(admins).where(admins.c.username == username)
        ).mappings().first()
    return dict(row) if row else None


def update_admin_password(username, password_hash):
    with engine.begin() as conn:
        conn.execute(
            sa_update(admins).where(admins.c.username == username)
            .values(password_hash=password_hash)
        )


# --- Agents ----------------------------------------------------------------

def _agent_to_dict(r):
    return {
        "id": r["id"], "agent_id": r["agent_id"], "label": r["label"],
        "platform": r["platform"], "status": r["status"], "token": r["token"],
        "created_at": r["created_at"], "last_seen": r["last_seen"],
    }


def register_agent(agent_id, label, platform, token=None):
    existing = get_agent(agent_id)
    if existing is None:
        with engine.begin() as conn:
            conn.execute(sa_insert(agents).values(
                agent_id=agent_id, label=label, platform=platform,
                status="active", token=token, created_at=_now(),
            ))
    return get_agent(agent_id)


def get_agent(agent_id):
    with engine.connect() as conn:
        row = conn.execute(
            select(agents).where(agents.c.agent_id == agent_id)
        ).mappings().first()
    return _agent_to_dict(row) if row else None


def get_agents():
    with engine.connect() as conn:
        rows = conn.execute(
            select(agents).order_by(agents.c.id.desc())
        ).mappings().all()
    return [_agent_to_dict(r) for r in rows]


def set_agent_status(agent_id, status):
    with engine.begin() as conn:
        conn.execute(
            sa_update(agents).where(agents.c.agent_id == agent_id).values(status=status)
        )


def delete_agent(agent_id):
    with engine.begin() as conn:
        conn.execute(sa_delete(agents).where(agents.c.agent_id == agent_id))


def touch_agent(agent_id):
    with engine.begin() as conn:
        conn.execute(
            sa_update(agents).where(agents.c.agent_id == agent_id).values(last_seen=_now())
        )


# --- Utilisateurs clients (authentifiés via Firebase) ----------------------

def _user_to_dict(r):
    return {
        "id": r["id"], "uid": r["uid"], "email": r["email"],
        "display_name": r["display_name"], "status": r["status"],
        "fcm_token": r["fcm_token"], "created_at": r["created_at"],
        "last_seen": r["last_seen"],
        "ip": r["ip"] if "ip" in r else None,
        "approved_at": r["approved_at"] if "approved_at" in r else None,
    }


def upsert_user(uid, email, display_name, ip=None):
    """Crée l'utilisateur s'il n'existe pas (statut 'pending'), sinon le met à jour."""
    existing = get_user_by_uid(uid)
    now = _now()
    with engine.begin() as conn:
        if existing is None:
            conn.execute(sa_insert(users).values(
                uid=uid, email=email, display_name=display_name,
                status="pending", ip=ip, created_at=now, last_seen=now,
            ))
        else:
            vals = {"email": email, "display_name": display_name, "last_seen": now}
            if ip:
                vals["ip"] = ip
            conn.execute(sa_update(users).where(users.c.uid == uid).values(**vals))
    return get_user_by_uid(uid)


def update_user(uid, display_name):
    with engine.begin() as conn:
        conn.execute(sa_update(users).where(users.c.uid == uid)
                     .values(display_name=display_name))


def get_user_by_uid(uid):
    with engine.connect() as conn:
        row = conn.execute(
            select(users).where(users.c.uid == uid)
        ).mappings().first()
    return _user_to_dict(row) if row else None


def get_users():
    with engine.connect() as conn:
        rows = conn.execute(select(users).order_by(users.c.id.desc())).mappings().all()
    return [_user_to_dict(r) for r in rows]


def set_user_status(uid, status):
    vals = {"status": status}
    if status == "approved":
        vals["approved_at"] = _now()
    with engine.begin() as conn:
        conn.execute(sa_update(users).where(users.c.uid == uid).values(**vals))


def set_user_fcm_token(uid, token):
    with engine.begin() as conn:
        conn.execute(sa_update(users).where(users.c.uid == uid).values(fcm_token=token))


# --- Paramètres (clé/valeur) -----------------------------------------------

def get_setting(key, default=None):
    with engine.connect() as conn:
        row = conn.execute(
            select(settings.c.svalue).where(settings.c.skey == key)
        ).first()
    return row[0] if row else default


def set_setting(key, value):
    with engine.begin() as conn:
        existing = conn.execute(
            select(settings.c.skey).where(settings.c.skey == key)
        ).first()
        if existing:
            conn.execute(sa_update(settings).where(settings.c.skey == key)
                         .values(svalue=str(value)))
        else:
            conn.execute(sa_insert(settings).values(skey=key, svalue=str(value)))


def get_thresholds():
    """Renvoie (seuil_moyen, seuil_eleve), avec valeurs par défaut (25, 55)."""
    try:
        moyen = int(get_setting("seuil_moyen", 25))
        eleve = int(get_setting("seuil_eleve", 55))
    except (TypeError, ValueError):
        moyen, eleve = 25, 55
    return moyen, eleve


def set_thresholds(moyen, eleve):
    set_setting("seuil_moyen", moyen)
    set_setting("seuil_eleve", eleve)
