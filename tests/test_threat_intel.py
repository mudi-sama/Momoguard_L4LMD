"""Tests de l'enrichissement par API externe de réputation d'URL."""

from conftest import _post_report


def _approve(mg, uid="u1"):
    mg.db.upsert_user(uid, uid + "@test.cd", "U")
    mg.db.set_user_status(uid, "approved")


def test_url_malveillante_force_eleve(mg, agent):
    _approve(mg)
    mg.ti.is_ready = lambda: True
    mg.ti.check_urls = lambda urls: "malicious"
    r = _post_report(mg, agent, content="Regarde ce lien http://exemple-banal.com")
    j = r.get_json()
    assert r.status_code == 201 and j["level"] == "eleve"
    assert any("malveillante" in x for x in j["reasons"])


def test_url_saine_pas_d_escalade(mg, agent):
    _approve(mg)
    mg.ti.is_ready = lambda: True
    mg.ti.check_urls = lambda urls: "clean"
    r = _post_report(mg, agent, content="Bonjour, on se voit demain")
    assert r.get_json()["level"] == "faible"


def test_sans_cle_aucun_effet(mg, agent):
    _approve(mg)
    mg.ti.is_ready = lambda: False
    r = _post_report(mg, agent, content="Bonjour, on se voit demain")
    assert r.get_json()["level"] == "faible"


def test_extraction_urls(mg):
    urls = mg.ti.extract_urls("voir http://a.com et www.b.cd, fin.")
    assert "http://a.com" in urls and "http://www.b.cd" in urls
