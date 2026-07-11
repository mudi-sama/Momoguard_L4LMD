import os
import sys
import tempfile
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mg():
    """Fournit une instance MoMoGuard isolée sur une base SQLite temporaire."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    url = "sqlite:///" + path
    os.environ["MOMOGUARD_DB"] = url
    os.environ.setdefault("MOMOGUARD_SECRET", "test-secret-key-pytest-only-32chars!!")

    from server import database, scoring, firebase_auth, threat_intel
    from server import app as appmod

    database.set_database_url(url)
    database.init_db()
    appmod.ensure_default_admin()

    # En test : on désactive CSRF et la limitation de débit (pratique standard)
    appmod.app.config["WTF_CSRF_ENABLED"] = False
    appmod.app.config["RATELIMIT_ENABLED"] = False
    appmod.limiter.enabled = False

    # On sauvegarde l'état des modules externes pour le restaurer après le test
    saved = (firebase_auth._initialized, firebase_auth.verify_id_token,
             firebase_auth.send_push, firebase_auth.update_user_password,
             threat_intel.is_ready, threat_intel.check_urls)

    ns = types.SimpleNamespace(
        client=appmod.app.test_client(),
        app=appmod, db=database, scoring=scoring, fb=firebase_auth,
        ti=threat_intel, url=url,
    )
    yield ns

    (firebase_auth._initialized, firebase_auth.verify_id_token,
     firebase_auth.send_push, firebase_auth.update_user_password,
     threat_intel.is_ready, threat_intel.check_urls) = saved
    try:
        os.remove(path)
    except OSError:
        pass


@pytest.fixture
def agent(mg):
    """Agent enregistré avec jeton pour les tests /report."""
    token = "test-agent-token-secret"
    mg.db.register_agent("a", "android-test", "android", token)
    mg.db.register_agent("w", "windows-test", "windows", token)
    return {"token": token}


def _mock_firebase(mg, uid="u1"):
    mg.fb._initialized = True
    mg.fb.verify_id_token = lambda t: {"uid": uid, "email": f"{uid}@test.cd", "name": "U"}


def _post_report(mg, agent, **fields):
    payload = {
        "agent_id": "a",
        "platform": "android",
        "content": "http://x.tk",
        "token": agent["token"],
        **fields,
    }
    if payload.get("platform") == "android":
        uid = payload.get("uid", "u1")
        _mock_firebase(mg, uid)
        payload["id_token"] = "fake-token"
    return mg.client.post("/report", json=payload)


@pytest.fixture
def admin(mg):
    """Client déjà authentifié en tant qu'administrateur."""
    mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    return mg
