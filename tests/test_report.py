"""Tests de l'endpoint /report : adhésion, blocage, notification."""


def _approve(mg, uid="u1"):
    mg.db.upsert_user(uid, uid + "@test.cd", "U")
    mg.db.set_user_status(uid, "approved")


def test_compte_en_attente_refuse(mg):
    mg.db.upsert_user("p", "p@test.cd", "P")
    r = mg.client.post("/report", json={
        "agent_id": "a", "platform": "android", "content": "http://x.tk", "uid": "p"})
    assert r.status_code == 403


def test_compte_approuve_accepte(mg):
    _approve(mg)
    r = mg.client.post("/report", json={
        "agent_id": "a", "platform": "android", "content": "http://x.tk", "uid": "u1"})
    assert r.status_code == 201


def test_agent_windows_sans_uid(mg):
    r = mg.client.post("/report", json={
        "agent_id": "w", "platform": "windows", "content": "http://x.tk"})
    assert r.status_code == 201


def test_push_sur_alerte_elevee(mg):
    _approve(mg)
    mg.db.set_user_fcm_token("u1", "TOK")
    mg.fb._initialized = True
    envoyes = []
    mg.fb.send_push = lambda tok, t, b: envoyes.append(tok) or True
    mg.client.post("/report", json={
        "agent_id": "a", "platform": "android",
        "content": "URGENT reactiver votre compte http://0range-money.xyz", "uid": "u1"})
    assert envoyes == ["TOK"]
