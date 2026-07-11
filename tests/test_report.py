"""Tests de l'endpoint /report : adhésion, blocage, notification."""

from conftest import _post_report


def _approve(mg, uid="u1"):
    mg.db.upsert_user(uid, uid + "@test.cd", "U")
    mg.db.set_user_status(uid, "approved")


def test_compte_en_attente_refuse(mg, agent):
    mg.db.upsert_user("p", "p@test.cd", "P")
    r = _post_report(mg, agent, uid="p")
    assert r.status_code == 403


def test_compte_approuve_accepte(mg, agent):
    _approve(mg)
    r = _post_report(mg, agent)
    assert r.status_code == 201


def test_agent_windows_sans_uid(mg, agent):
    r = mg.client.post("/report", json={
        "agent_id": "w", "platform": "windows",
        "content": "http://x.tk", "token": agent["token"],
    })
    assert r.status_code == 201


def test_agent_inconnu_refuse(mg):
    r = mg.client.post("/report", json={
        "agent_id": "inconnu", "platform": "windows",
        "content": "http://x.tk", "token": "x",
    })
    assert r.status_code == 403


def test_jeton_invalide_refuse(mg, agent):
    r = mg.client.post("/report", json={
        "agent_id": "w", "platform": "windows",
        "content": "http://x.tk", "token": "mauvais-jeton",
    })
    assert r.status_code == 401


def test_push_sur_alerte_elevee(mg, agent):
    _approve(mg)
    mg.db.set_user_fcm_token("u1", "TOK")
    mg.fb._initialized = True
    envoyes = []
    mg.fb.send_push = lambda tok, t, b: envoyes.append(tok) or True
    _post_report(mg, agent, content="URGENT reactiver votre compte http://0range-money.xyz")
    assert envoyes == ["TOK"]
