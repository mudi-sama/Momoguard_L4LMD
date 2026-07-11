"""Insère un jeu de données de démonstration (utilisateurs, agents, alertes).

Usage : python scripts/seed_demo.py
"""
import os, sys  # os : chemins ; sys : manipulation du PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # Ajoute la racine du projet au chemin d'import
from server import database, scoring  # Modules serveur : persistance et calcul de score

SAMPLES = [  # Messages SMS fictifs pour alimenter la démo
    ("sms", "URGENT votre compte Orange Money est bloque, reactivez sur http://0range-money.tk", "Orange"),  # Arnaque phishing Mobile Money
    ("sms", "Felicitations ! Vous avez gagne 5000$, envoyez vos frais pour recevoir", "Promo"),  # Arnaque loterie / avance de frais
    ("sms", "Votre carte SIM va etre remplacee, communiquez votre code PUK", "Operateur"),  # Tentative d'obtention du code PUK
    ("sms", "Bonjour, on se voit demain a 15h", "Maman"),  # Message légitime (contrôle faux positif)
]

def main():
    database.init_db()  # Crée les tables si elles n'existent pas encore
    database.upsert_user("demo_pending", "client.attente@demo.cd", "Client En Attente")  # Utilisateur en attente d'approbation
    database.upsert_user("demo_ok", "client.ok@demo.cd", "Client Approuve", ip="41.243.10.7")  # Utilisateur approuvé avec IP
    database.set_user_status("demo_ok", "approved")  # Passe le statut du client démo à « approuvé »

    database.register_agent("android-demo", "Telephone de demo", "android", "demo-token")  # Agent Android fictif
    database.register_agent("windows-demo", "PC de demo", "windows", "demo-token2")  # Agent Windows fictif
    database.touch_agent("android-demo")  # Met à jour la date de dernière activité de l'agent Android

    thr = database.get_thresholds()  # Récupère les seuils de scoring configurés en base
    for etype, content, sender in SAMPLES:  # Parcourt chaque message d'exemple
        score, level, reasons = scoring.score_event(etype, content, {"sender": sender}, thr)  # Calcule score, niveau et raisons
        database.insert_report("android-demo", "android", etype, content,  # Insère le rapport en base
                               {"sender": sender}, score, level, reasons, uid="demo_ok")  # Associé à l'utilisateur demo_ok
    print(f"Données de démonstration insérées ({len(SAMPLES)} alertes).")  # Confirmation en console

if __name__ == "__main__":  # Exécution directe du script
    main()  # Lance le peuplement de la base démo
