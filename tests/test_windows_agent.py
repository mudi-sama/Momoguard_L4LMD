"""Tests unitaires de l'agent Windows (filtres et helpers)."""

from agents.windows_agent import url_a_analyser


def test_url_http_acceptee():
    assert url_a_analyser("https://orange-money.phishing.tk/login")


def test_url_interne_ignoree():
    assert not url_a_analyser("chrome://newtab/")
    assert not url_a_analyser("about:blank")
    assert not url_a_analyser("edge://settings/")


def test_url_vide_ignoree():
    assert not url_a_analyser("")
    assert not url_a_analyser("   ")
