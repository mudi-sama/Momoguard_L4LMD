"""Tests de l'authentification à deux facteurs (TOTP)."""
import pyotp


def test_activation_2fa(admin):
    r = admin.client.get("/account/2fa/setup")
    assert r.status_code == 200
    with admin.client.session_transaction() as s:
        secret = s["twofa_tmp"]
    admin.client.post("/account/2fa/enable", data={"code": pyotp.TOTP(secret).now()})
    assert admin.db.get_admin("admin")["totp_secret"] == secret


def test_connexion_exige_2fa(mg):
    secret = pyotp.random_base32()
    mg.db.set_admin_totp("admin", secret)
    # Bon mot de passe : on est redirigé vers l'étape 2FA, pas encore connecté
    r = mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    assert r.status_code in (302, 303)
    assert mg.client.get("/").status_code in (302, 303)  # accès refusé
    # Code valide -> accès accordé
    mg.client.post("/login/2fa", data={"code": pyotp.TOTP(secret).now()})
    assert mg.client.get("/").status_code == 200


def test_code_2fa_invalide_refuse(mg):
    mg.db.set_admin_totp("admin", pyotp.random_base32())
    mg.client.post("/login", data={"username": "admin", "password": "momoguard"})
    r = mg.client.post("/login/2fa", data={"code": "000000"})
    assert r.status_code == 401


def test_desactivation_2fa(admin):
    secret = pyotp.random_base32()
    admin.db.set_admin_totp("admin", secret)
    admin.client.post("/account/2fa/disable", data={
        "password": "momoguard",
        "code": pyotp.TOTP(secret).now(),
    })
    assert admin.db.get_admin("admin")["totp_secret"] is None


def test_desactivation_2fa_sans_mdp_refuse(admin):
    secret = pyotp.random_base32()
    admin.db.set_admin_totp("admin", secret)
    r = admin.client.post("/account/2fa/disable", data={
        "password": "wrong",
        "code": pyotp.TOTP(secret).now(),
    })
    assert r.status_code == 401
    assert admin.db.get_admin("admin")["totp_secret"] == secret
