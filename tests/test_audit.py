"""Tests du journal d'audit (non-répudiation)."""


def test_connexion_journalisee(admin):
    assert any(e["action"] == "Connexion réussie" for e in admin.db.get_audit())


def test_action_utilisateur_journalisee(admin):
    admin.db.upsert_user("u1", "c@test.cd", "C")
    admin.client.post("/users/u1/approve")
    entries = admin.db.get_audit()
    assert any(e["action"] == "Utilisateur approuvé" and e["target"] == "u1" for e in entries)


def test_page_journal_affiche(admin):
    admin.db.upsert_user("u1", "c@test.cd", "C")
    admin.client.post("/users/u1/block")
    r = admin.client.get("/audit")
    assert r.status_code == 200 and "Utilisateur bloqué".encode() in r.data
