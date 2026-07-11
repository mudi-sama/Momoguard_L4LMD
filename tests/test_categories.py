"""Tests de la taxonomie des arnaques (catégorisation + graphique)."""


def test_categorie_mapping(mg):
    # SIM swap prioritaire sur le reste
    assert mg.db._categorie(["Référence à un remplacement de SIM / code PUK (possible SIM swap)"]) == "SIM swap (PUK)"
    # Faux agent
    assert mg.db._categorie(["Message se présentant comme un agent opérateur avec une consigne d'action"]) == "Faux agent"
    # Phishing par lien
    assert mg.db._categorie(["Domaine imitant un opérateur sans être officiel (0range-money.tk)"]) == "Phishing (lien piégé)"
    # Aucun signal suspect -> pas de catégorie
    assert mg.db._categorie(["Aucun signal suspect détecté"]) is None
    assert mg.db._categorie([]) is None


def test_categorie_dans_report_dict(admin):
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
    assert recents and recents[0]["categorie"] == "SIM swap (PUK)"


def test_get_category_stats_ignore_faible(admin):
    # Le bouton démo génère une arnaque (moyen/élevé) : elle doit apparaître.
    admin.client.post("/demo")
    stats = admin.db.get_category_stats()
    assert sum(stats.values()) >= 1
    # Aucune clé ne doit correspondre à un événement faible/RAS.
    assert None not in stats


def test_api_reports_expose_categories(admin):
    admin.client.post("/demo")
    data = admin.client.get("/api/reports").get_json()
    assert "categories" in data
    assert isinstance(data["categories"], dict)
