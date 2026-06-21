"""Tests de la page des paramètres (seuils de score)."""


def test_enregistrer_seuils(admin):
    r = admin.client.post("/settings", data={"seuil_moyen": "20", "seuil_eleve": "50"})
    assert r.status_code == 200 and admin.db.get_thresholds() == (20, 50)


def test_seuils_invalides_refuses(admin):
    r = admin.client.post("/settings", data={"seuil_moyen": "60", "seuil_eleve": "50"})
    assert r.status_code == 400
