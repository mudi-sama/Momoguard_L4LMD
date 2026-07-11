"""Tests de durcissement OWASP : en-têtes, accès, API client."""


def test_entetes_securite_presents(mg):
    r = mg.client.get("/login")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_routes_admin_sans_session_refusees(mg):
    for path in ("/", "/users", "/api/reports", "/agents", "/audit"):
        r = mg.client.get(path)
        assert r.status_code in (302, 303, 401)


def test_my_reports_compte_pending_refuse(mg):
    mg.fb._initialized = True
    mg.fb.verify_id_token = lambda t: {"uid": "p", "email": "p@test.cd"}
    mg.db.upsert_user("p", "p@test.cd", "P")
    r = mg.client.post("/api/my-reports", json={"id_token": "x"})
    assert r.status_code == 403


def test_my_reports_compte_approuve_ok(mg):
    mg.fb._initialized = True
    mg.fb.verify_id_token = lambda t: {"uid": "u1", "email": "u1@test.cd"}
    mg.db.upsert_user("u1", "u1@test.cd", "U")
    mg.db.set_user_status("u1", "approved")
    r = mg.client.post("/api/my-reports", json={"id_token": "x"})
    assert r.status_code == 200
    assert r.get_json()["status"] == "approved"
