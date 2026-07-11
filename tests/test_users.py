"""Tests de la gestion des utilisateurs (IP, fiche, mot de passe)."""


def test_capture_ip_a_l_enregistrement(mg):
    mg.fb._initialized = True
    mg.fb.verify_id_token = lambda t: {"uid": "u1", "email": "c@test.cd", "name": "C"}
    mg.client.post("/api/auth/firebase", json={"id_token": "x"},
                   headers={"X-Forwarded-For": "41.1.2.3"})
    assert mg.db.get_user_by_uid("u1")["ip"] == "41.1.2.3"


def test_fiche_et_edition(admin):
    admin.db.upsert_user("u1", "c@test.cd", "Ancien", ip="1.2.3.4")
    r = admin.client.get("/users/u1")
    assert b"1.2.3.4" in r.data
    admin.client.post("/users/u1/edit", data={"display_name": "Nouveau"})
    assert admin.db.get_user_by_uid("u1")["display_name"] == "Nouveau"


def test_changement_mot_de_passe_notifie(admin):
    admin.db.upsert_user("u1", "c@test.cd", "C")
    admin.db.set_user_status("u1", "approved")
    admin.db.set_user_fcm_token("u1", "TOK")
    admin.fb._initialized = True
    admin.fb.update_user_password = lambda uid, pwd: True
    envoyes = []
    admin.fb.send_push = lambda tok, t, b: envoyes.append(tok) or True
    r = admin.client.post("/users/u1/password", data={"new_password": "secret12345"})
    assert r.status_code == 200 and envoyes == ["TOK"]


def test_mot_de_passe_trop_court(admin):
    admin.db.upsert_user("u1", "c@test.cd", "C")
    r = admin.client.post("/users/u1/password", data={"new_password": "abc"})
    assert r.status_code == 400
