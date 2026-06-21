"""Agent Windows MoMoGuard — transparent et consenti.

Cet agent surveille TON propre environnement et envoie un rapport au serveur
quand il repère quelque chose qui mérite vérification :

  - le presse-papier (liens, codes USSD, numéros de compte copiés) ;
  - le dossier Téléchargements (nouveaux fichiers exécutables).

Il N'EST PAS furtif : il affiche dans la console tout ce qu'il fait, et tu
peux l'arrêter à tout moment avec Ctrl+C.

Dépendances :  pip install requests pyperclip watchdog
"""

import os
import time
import requests
import pyperclip
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---------------------------------------------------------
SERVER_URL = "http://127.0.0.1:5000/report"
AGENT_ID = "windows-pc-01"
# Si tu as déclaré cet agent dans le dashboard, colle son jeton ici.
# Laisse vide ("") si l'agent n'est pas déclaré (il sera ajouté automatiquement).
AGENT_TOKEN = ""
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")
POLL_SECONDS = 1.5

EXT_DANGEREUSES = (".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".apk", ".jar")
MOTS_CLES = ["code", "urgent", "gagné", "félicitations", "cliquez", "bloqué",
             "promotion", "tombola", "confirmez"]


def envoyer(event_type, content, metadata=None):
    """Envoie un rapport au serveur et affiche le verdict reçu."""
    payload = {
        "agent_id": AGENT_ID,
        "platform": "windows",
        "event_type": event_type,
        "content": content,
        "metadata": metadata or {},
        "token": AGENT_TOKEN,
    }
    try:
        r = requests.post(SERVER_URL, json=payload, timeout=5)
        if r.status_code == 403:
            print("  !! cet agent est BLOQUÉ par l'administrateur")
            return
        if r.status_code == 401:
            print("  !! jeton d'agent invalide (vérifie AGENT_TOKEN)")
            return
        data = r.json()
        print(f"  -> envoyé [{event_type}] niveau={data.get('level')} "
              f"score={data.get('score')}")
    except Exception as e:
        print(f"  !! échec d'envoi : {e}")


def merite_analyse(texte):
    """Pré-filtre simple pour éviter d'envoyer chaque copier-coller anodin."""
    t = texte.lower()
    if "http://" in t or "https://" in t or "www." in t:
        return "link"
    if "*" in texte and "#" in texte:
        return "ussd"
    if any(c.isdigit() for c in texte) and sum(c.isdigit() for c in texte) >= 8:
        return "clipboard"
    if any(k in t for k in MOTS_CLES):
        return "message"
    return None


class DownloadsHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        nom = os.path.basename(event.src_path)
        if nom.lower().endswith(EXT_DANGEREUSES):
            print(f"[fichier] nouveau fichier exécutable : {nom}")
            envoyer("file", nom, {"path": event.src_path})


def surveiller_presse_papier():
    print(f"[presse-papier] surveillance active (toutes les {POLL_SECONDS}s)")
    dernier = ""
    while True:
        try:
            actuel = pyperclip.paste()
        except Exception:
            actuel = ""
        if actuel and actuel != dernier:
            dernier = actuel
            type_event = merite_analyse(actuel)
            if type_event:
                apercu = actuel[:80].replace("\n", " ")
                print(f"[presse-papier] détecté ({type_event}) : {apercu}")
                envoyer(type_event, actuel)
        time.sleep(POLL_SECONDS)


def main():
    print("=" * 60)
    print(" Agent Windows MoMoGuard (transparent)")
    print(f" Serveur : {SERVER_URL}")
    print(f" Dossier surveillé : {DOWNLOADS_DIR}")
    print(" Arrêt : Ctrl+C")
    print("=" * 60)

    observer = None
    if os.path.isdir(DOWNLOADS_DIR):
        observer = Observer()
        observer.schedule(DownloadsHandler(), DOWNLOADS_DIR, recursive=False)
        observer.start()
        print(f"[fichier] surveillance de {DOWNLOADS_DIR}")
    else:
        print("[fichier] dossier Téléchargements introuvable — surveillance fichiers désactivée")

    try:
        surveiller_presse_papier()
    except KeyboardInterrupt:
        print("\n[arrêt] agent stoppé par l'utilisateur")
    finally:
        if observer:
            observer.stop()
            observer.join()


if __name__ == "__main__":
    main()
