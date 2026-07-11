"""Tests du bouton de démonstration et des conseils de prévention."""


def test_demo_genere_alerte(admin):
    r = admin.client.post("/demo")
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and j["level"] in ("moyen", "eleve")
    assert any(rep["agent_id"] == "demo-jury" for rep in admin.db.get_recent())


def test_conseil_dans_alerte(admin):
    from conftest import _mock_firebase
    token = "demo-token"
    admin.db.register_agent("a", "test", "android", token)
    admin.db.upsert_user("u1", "u1@test.cd", "U")
    admin.db.set_user_status("u1", "approved")
    _mock_firebase(admin, "u1")
    admin.client.post("/report", json={
        "agent_id": "a", "platform": "android",
        "content": "Votre carte SIM va etre remplacee, code PUK requis",
        "token": token, "id_token": "fake", "uid": "u1",
    })
    recents = admin.db.get_recent()
    assert recents and recents[0]["conseil"]


def test_conseil_mapping(mg):
    assert "PUK" in mg.db._conseil(["Indice de SIM swap (PUK/remplacement)"])
    assert mg.db._conseil([]) == ""
