"""Tests des nouvelles pages : Analyseur, Statistiques, Menaces, Guide."""


def test_pages_exigent_login(mg):
    for path in ("/analyzer", "/stats", "/threats", "/guide", "/api/reports.csv"):
        r = mg.client.get(path)
        assert r.status_code in (302, 303, 401), path


def test_pages_admin_ok(admin):
    for path in ("/analyzer", "/stats", "/threats", "/guide"):
        r = admin.client.get(path)
        assert r.status_code == 200, path


def test_api_analyze_detecte_fraude(admin):
    r = admin.client.post("/api/analyze", json={
        "event_type": "sms",
        "content": "URGENT votre compte Orange Money sera suspendu, reactivez sur http://0range-money.tk",
    })
    assert r.status_code == 200
    d = r.get_json()
    assert d["level"] in ("moyen", "eleve")
    assert d["score"] > 0
    assert d["categorie"]  # une catégorie a été déduite
    assert isinstance(d["reasons"], list) and d["reasons"]


def test_api_analyze_message_legitime(admin):
    r = admin.client.post("/api/analyze", json={
        "event_type": "sms",
        "content": "Rendez-vous demain a 14h a l'agence pour votre dossier. Merci.",
    })
    assert r.status_code == 200
    assert r.get_json()["level"] == "faible"


def test_api_analyze_vide_refuse(admin):
    r = admin.client.post("/api/analyze", json={"content": "   "})
    assert r.status_code == 400


def test_export_csv(admin):
    admin.client.post("/demo")  # génère au moins une alerte
    r = admin.client.get("/api/reports.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("Content-Type", "")
    assert "attachment" in r.headers.get("Content-Disposition", "")
    body = r.get_data(as_text=True)
    assert "niveau" in body and "categorie" in body


def test_stats_affiche_metriques(admin):
    r = admin.client.get("/stats")
    body = r.get_data(as_text=True)
    assert "96.2" in body  # taux de détection du benchmark
