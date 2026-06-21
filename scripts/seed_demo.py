"""Insère un jeu de données de démonstration (utilisateurs, agents, alertes).

Usage : python scripts/seed_demo.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database, scoring

SAMPLES = [
    ("sms", "URGENT votre compte Orange Money est bloque, reactivez sur http://0range-money.tk", "Orange"),
    ("sms", "Felicitations ! Vous avez gagne 5000$, envoyez vos frais pour recevoir", "Promo"),
    ("sms", "Votre carte SIM va etre remplacee, communiquez votre code PUK", "Operateur"),
    ("sms", "Bonjour, on se voit demain a 15h", "Maman"),
]

def main():
    database.init_db()
    database.upsert_user("demo_pending", "client.attente@demo.cd", "Client En Attente")
    database.upsert_user("demo_ok", "client.ok@demo.cd", "Client Approuve", ip="41.243.10.7")
    database.set_user_status("demo_ok", "approved")

    database.register_agent("android-demo", "Telephone de demo", "android", "demo-token")
    database.register_agent("windows-demo", "PC de demo", "windows", "demo-token2")
    database.touch_agent("android-demo")

    thr = database.get_thresholds()
    for etype, content, sender in SAMPLES:
        score, level, reasons = scoring.score_event(etype, content, {"sender": sender}, thr)
        database.insert_report("android-demo", "android", etype, content,
                               {"sender": sender}, score, level, reasons, uid="demo_ok")
    print(f"Données de démonstration insérées ({len(SAMPLES)} alertes).")

if __name__ == "__main__":
    main()
