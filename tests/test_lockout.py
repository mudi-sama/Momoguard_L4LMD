"""Tests du verrouillage temporaire du compte admin après échecs répétés."""

import pyotp


def _echec(mg):
    return mg.client.post("/login", data={"username": "admin", "password": "faux"})


def test_verrouillage_apres_4_echecs(mg):
    # Les 3 premiers échecs renvoient 401 (identifiants incorrects).
    for _ in range(3):
        assert _echec(mg).status_code == 401
    # Le 4e échec déclenche le verrouillage (429).
    assert _echec(mg).status_code == 429
    admin = mg.db.get_admin("admin")
    assert admin["locked_until"] is not None


def test_bon_mdp_refuse_pendant_verrou(mg):
    for _ in range(4):
        _echec(mg)
    # Même avec le bon mot de passe, l'accès est refusé tant que le verrou dure.
    r = mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    assert r.status_code == 429
    assert mg.client.get("/").status_code in (302, 303)  # toujours pas connecté


def test_verrou_trace_dans_audit(mg):
    for _ in range(4):
        _echec(mg)
    actions = [(e["action"] or "").lower() for e in mg.db.get_audit()]
    assert any("verrouill" in a for a in actions)


def test_succes_reinitialise_le_compteur(mg):
    for _ in range(3):
        _echec(mg)
    r = mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    assert r.status_code in (302, 303)  # connexion réussie
    admin = mg.db.get_admin("admin")
    assert (admin["failed_attempts"] or 0) == 0
    assert admin["locked_until"] is None


def test_utilisateur_inconnu_pas_de_verrou(mg):
    # Un compte inexistant ne doit jamais être verrouillé (pas de fuite d'info).
    for _ in range(6):
        r = mg.client.post("/login", data={"username": "ghost", "password": "x"})
    assert r.status_code == 401


def test_echecs_2fa_verrouillent_le_compte(mg):
    secret = pyotp.random_base32()
    mg.db.set_admin_totp("admin", secret)
    mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    # 4 codes 2FA erronés -> verrouillage.
    r = None
    for _ in range(4):
        r = mg.client.post("/login/2fa", data={"code": "000000"})
    assert r.status_code == 429
    assert mg.db.get_admin("admin")["locked_until"] is not None


def test_helpers_db_verrou(mg):
    attempts, locked_until = mg.db.record_failed_login("admin", max_failures=1, lockout_minutes=15)
    assert attempts == 1 and locked_until is not None
    assert mg.db.admin_lock_remaining("admin") > 0
    mg.db.reset_failed_login("admin")
    assert mg.db.admin_lock_remaining("admin") == 0
