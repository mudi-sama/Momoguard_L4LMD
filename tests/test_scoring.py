"""Tests du moteur de scoring (règles et seuils)."""


def test_phishing_homoglyphe(mg):
    score, level, reasons = mg.scoring.score_event(
        "sms", "Compte bloque, reactivez sur http://0range-money.tk")
    assert score > 0 and level in ("moyen", "eleve")


def test_sim_swap_detecte(mg):
    _, _, reasons = mg.scoring.score_event(
        "sms", "Votre carte SIM va etre remplacee, code PUK requis")
    assert any("SIM" in r for r in reasons)


def test_partage_otp_detecte(mg):
    score, _, _ = mg.scoring.score_event(
        "sms", "envoie-moi le code de confirmation recu par SMS")
    assert score >= 30


def test_otp_protecteur_non_signale(mg):
    _, level, _ = mg.scoring.score_event(
        "sms", "Votre code est 1234. Ne le partagez jamais avec personne.")
    assert level == "faible"


def test_message_benin(mg):
    _, level, _ = mg.scoring.score_event("sms", "Salut, on se voit demain a 14h")
    assert level == "faible"


def test_seuils_configurables(mg):
    _, niveau_defaut, _ = mg.scoring.score_event("sms", "envoie le code", thresholds=(25, 55))
    _, niveau_bas, _ = mg.scoring.score_event("sms", "envoie le code", thresholds=(5, 10))
    assert niveau_defaut == "moyen" and niveau_bas == "eleve"
