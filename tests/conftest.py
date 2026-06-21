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

    import database
    import scoring
    import firebase_auth
    import app as appmod

    database.set_database_url(url)
    database.init_db()
    appmod.ensure_default_admin()

    # On sauvegarde l'état de firebase_auth pour le restaurer après le test
    saved = (firebase_auth._initialized, firebase_auth.verify_id_token,
             firebase_auth.send_push, firebase_auth.update_user_password)

    ns = types.SimpleNamespace(
        client=appmod.app.test_client(),
        app=appmod, db=database, scoring=scoring, fb=firebase_auth, url=url,
    )
    yield ns

    (firebase_auth._initialized, firebase_auth.verify_id_token,
     firebase_auth.send_push, firebase_auth.update_user_password) = saved
    try:
        os.remove(path)
    except OSError:
        pass


@pytest.fixture
def admin(mg):
    """Client déjà authentifié en tant qu'administrateur."""
    mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    return mg
