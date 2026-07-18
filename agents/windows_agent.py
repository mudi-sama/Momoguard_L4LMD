"""Agent Windows MoMoGuard — transparent et consenti.

Cet agent surveille TON propre environnement et envoie un rapport au serveur
quand il repère quelque chose qui mérite vérification :

  - le presse-papier (liens, codes USSD, numéros de compte copiés) ;
  - les liens ouverts dans le navigateur (Chrome, Edge, Firefox, Brave) ;
  - le dossier Téléchargements (nouveaux fichiers exécutables).

Il N'EST PAS furtif : il affiche dans la console tout ce qu'il fait, et tu
peux l'arrêter à tout moment avec Ctrl+C.

Dépendances :  pip install requests pyperclip watchdog
"""

import os  # Accès aux chemins, variables d'environnement et opérations fichiers
import shutil  # Copie de fichiers (bases d'historique navigateur verrouillées)
import sqlite3  # Lecture des bases SQLite d'historique des navigateurs
import tempfile  # Création de copies temporaires des bases avant lecture
import threading  # Exécution parallèle de la surveillance navigateur
import time  # Pauses entre sondes et horodatages
import requests  # Envoi HTTP des rapports au serveur MoMoGuard
import pyperclip  # Lecture du contenu actuel du presse-papier Windows
from collections import deque  # File des URLs récentes pour éviter les doublons
from watchdog.observers import Observer  # Observateur du système de fichiers
from watchdog.events import FileSystemEventHandler  # Classe de base pour les événements fichiers

# --- Configuration ---------------------------------------------------------
# Serveur en ligne (Dokploy) par défaut. Pour le local : mets
# http://127.0.0.1:5000 dans agents/server_url.txt ou MOMOGUARD_SERVER_URL.
_DEFAULT_SERVER = "https://momoguardserv.com"
_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_ID = os.environ.get("MOMOGUARD_AGENT_ID", "windows-pc-01")


def _lire_fichier(chemin):
    """Lit un fichier texte local (jeton, URL…) ; chaîne vide si absent."""
    try:
        with open(chemin, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _normaliser_url_serveur(url):
    """Accepte une base (https://host) ou l'endpoint /report complet."""
    u = (url or "").strip().rstrip("/")
    if not u:
        return _DEFAULT_SERVER.rstrip("/") + "/report"
    if u.endswith("/report"):
        return u
    return u + "/report"


def _lire_url_serveur():
    """URL du serveur : env, puis agents/server_url.txt, puis production."""
    env = os.environ.get("MOMOGUARD_SERVER_URL", "").strip()
    if env:
        return _normaliser_url_serveur(env)
    fichier = _lire_fichier(os.path.join(_AGENT_DIR, "server_url.txt"))
    if fichier:
        return _normaliser_url_serveur(fichier)
    return _normaliser_url_serveur(_DEFAULT_SERVER)


def _lire_jeton():
    """Récupère le jeton d'agent : variable d'environnement, sinon fichier local.

    Ordre de priorité :
      1. MOMOGUARD_AGENT_TOKEN (variable d'environnement) ;
      2. fichier pointé par MOMOGUARD_AGENT_TOKEN_FILE ;
      3. fichier agent_token.txt placé à côté de ce script (persistant).
    Cela évite d'avoir à reconfigurer le jeton à chaque lancement du terminal."""
    jeton = os.environ.get("MOMOGUARD_AGENT_TOKEN", "").strip()  # 1) variable d'environnement
    if jeton:
        return jeton
    chemin = os.environ.get(  # 2) chemin de fichier explicite, sinon 3) fichier par défaut
        "MOMOGUARD_AGENT_TOKEN_FILE",
        os.path.join(_AGENT_DIR, "agent_token.txt"),
    )
    return _lire_fichier(chemin)


# Jeton obligatoire : déclarez l'agent dans le dashboard EN LIGNE et collez le
# jeton dans agents/agent_token.txt (ou MOMOGUARD_AGENT_TOKEN).
SERVER_URL = _lire_url_serveur()
AGENT_TOKEN = _lire_jeton()
DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")  # Dossier Téléchargements de l'utilisateur
POLL_SECONDS = 1.5  # Intervalle entre deux lectures du presse-papier
BROWSER_POLL_SECONDS = 3.0  # Intervalle entre deux lectures de l'historique navigateur

EXT_DANGEREUSES = (".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".apk", ".jar")  # Extensions considérées comme risquées
MOTS_CLES = ["code", "urgent", "gagné", "félicitations", "cliquez", "bloqué",  # Mots typiques des arnaques SMS/phishing
             "promotion", "tombola", "confirmez"]

_PREFIXES_IGNORES = (  # Schémas d'URL internes au navigateur, à ne pas analyser
    "chrome://", "chrome-extension://", "edge://", "about:",
    "devtools://", "javascript:", "data:", "blob:", "file://",
    "ms-browser-extension://", "brave://",
)

# Décalage entre l'époque Unix et l'époque WebKit (Chrome/Edge) en secondes
_EPOQUE_WEBKIT = 11644473600  # Constante de conversion pour les horodatages Chromium


def url_a_analyser(url):
    """Retourne True si l'URL ouverte dans le navigateur mérite une analyse."""
    u = (url or "").strip()  # Normalise l'URL en supprimant les espaces
    if not u:  # URL vide : rien à analyser
        return False
    lu = u.lower()  # Version minuscule pour comparaisons insensibles à la casse
    if any(lu.startswith(p) for p in _PREFIXES_IGNORES):  # Ignore les URLs internes du navigateur
        return False
    return lu.startswith("http://") or lu.startswith("https://")  # Seuls les liens web publics sont retenus


def _timestamp_chrome_us():
    """Horodatage courant au format Chrome/Edge (microsecondes depuis 1601)."""
    return int((time.time() + _EPOQUE_WEBKIT) * 1_000_000)  # Convertit l'heure Unix en microsecondes WebKit


def _timestamp_firefox_us():
    """Horodatage courant au format Firefox (microsecondes depuis 1970)."""
    return int(time.time() * 1_000_000)  # Horodatage Firefox en microsecondes depuis l'époque Unix


def _chemins_navigateurs():
    """Chemins des bases d'historique des navigateurs installés."""
    local = os.environ.get("LOCALAPPDATA", "")  # Dossier AppData local (Chrome, Edge, Brave)
    appdata = os.environ.get("APPDATA", "")  # Dossier AppData roaming (profils Firefox)
    chemins = []  # Liste des navigateurs détectés avec leur type et chemin

    for nom, rel in (  # Parcourt les navigateurs basés sur Chromium
        ("chrome", os.path.join("Google", "Chrome", "User Data", "Default", "History")),
        ("edge", os.path.join("Microsoft", "Edge", "User Data", "Default", "History")),
        ("brave", os.path.join("BraveSoftware", "Brave-Browser", "User Data", "Default", "History")),
    ):
        chemin = os.path.join(local, rel)  # Chemin absolu vers le fichier History
        if os.path.isfile(chemin):  # Vérifie que la base d'historique existe
            chemins.append(("chromium", nom, chemin))  # Enregistre le profil Chromium trouvé

    profils = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")  # Racine des profils Firefox
    if os.path.isdir(profils):  # Firefox installé avec au moins un profil
        for profil in os.listdir(profils):  # Chaque sous-dossier est un profil Firefox
            places = os.path.join(profils, profil, "places.sqlite")  # Base d'historique Firefox
            if os.path.isfile(places):  # Profil valide avec historique
                chemins.append(("firefox", profil, places))  # Enregistre le profil Firefox trouvé

    return chemins  # Retourne tous les navigateurs exploitables


def _lire_visites_chromium(chemin_history, depuis_us):
    """Lit les visites récentes depuis History (Chrome, Edge, Brave)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)  # Fichier temporaire pour copier la base
    tmp.close()  # Ferme le descripteur pour permettre la copie sous Windows
    try:
        shutil.copy2(chemin_history, tmp.name)  # Copie la base verrouillée par le navigateur
        with sqlite3.connect(tmp.name) as conn:  # Ouvre la copie en lecture seule
            return conn.execute(  # Exécute la requête des visites récentes
                """
                SELECT u.url, COALESCE(u.title, ''), v.visit_time
                FROM visits v
                JOIN urls u ON u.id = v.url
                WHERE v.visit_time > ?
                ORDER BY v.visit_time ASC
                """,
                (depuis_us,),  # Paramètre : horodatage minimal des visites à récupérer
            ).fetchall()  # Retourne toutes les lignes (url, titre, horodatage)
    except (sqlite3.Error, OSError):  # Base corrompue, verrouillée ou copie impossible
        return []  # Échec silencieux : aucune visite à traiter
    finally:
        try:
            os.unlink(tmp.name)  # Supprime le fichier temporaire
        except OSError:
            pass  # Ignore si la suppression échoue


def _lire_visites_firefox(chemin_places, depuis_us):
    """Lit les visites récentes depuis places.sqlite (Firefox)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)  # Fichier temporaire pour la copie
    tmp.close()  # Libère le descripteur avant copie
    try:
        shutil.copy2(chemin_places, tmp.name)  # Copie places.sqlite hors du verrou Firefox
        with sqlite3.connect(tmp.name) as conn:  # Connexion SQLite sur la copie
            return conn.execute(  # Requête des visites Firefox postérieures au curseur
                """
                SELECT h.url, COALESCE(h.title, ''), v.visit_date
                FROM moz_historyvisits v
                JOIN moz_places h ON h.id = v.place_id
                WHERE v.visit_date > ?
                ORDER BY v.visit_date ASC
                """,
                (depuis_us,),  # Seuil temporel en microsecondes Firefox
            ).fetchall()  # Liste des tuples (url, titre, horodatage)
    except (sqlite3.Error, OSError):  # Erreur d'accès ou de lecture SQLite
        return []  # Aucune visite disponible
    finally:
        try:
            os.unlink(tmp.name)  # Nettoie le fichier temporaire
        except OSError:
            pass  # Suppression optionnelle en cas d'échec


def envoyer(event_type, content, metadata=None):
    """Envoie un rapport au serveur et affiche le verdict reçu."""
    if not AGENT_TOKEN:
        print("  !! AGENT_TOKEN manquant — collez le jeton dans agents/agent_token.txt "
              "ou dans la variable MOMOGUARD_AGENT_TOKEN")
        return
    payload = {  # Corps JSON de la requête POST
        "agent_id": AGENT_ID,  # Identifiant de l'agent émetteur
        "platform": "windows",  # Plateforme signalée au serveur
        "event_type": event_type,  # Type d'événement (link, file, ussd, etc.)
        "content": content,  # Contenu brut détecté (URL, texte, nom de fichier)
        "metadata": metadata or {},  # Informations complémentaires (navigateur, chemin, etc.)
        "token": AGENT_TOKEN,  # Jeton d'authentification de l'agent
    }
    try:
        r = requests.post(SERVER_URL, json=payload, timeout=15)  # Timeout plus long (serveur distant)
        if r.status_code == 403:  # Bloqué ou non enregistré sur ce serveur
            detail = ""
            try:
                detail = (r.json() or {}).get("error", "")
            except Exception:
                pass
            print(f"  !! refusé (403) : {detail or 'agent bloqué ou non déclaré sur le serveur'}")
            print("  !! crée/active l'agent sur https://momoguardserv.com → Agents")
            return
        if r.status_code == 401:  # Jeton invalide ou absent
            print("  !! jeton d'agent invalide — déclare l'agent sur "
                  "https://momoguardserv.com (Agents) et mets à jour agent_token.txt")
            return
        data = r.json()  # Parse la réponse JSON du serveur (score, niveau)
        print(f"  -> envoyé [{event_type}] niveau={data.get('level')} "  # Affiche le verdict reçu
              f"score={data.get('score')}")
    except Exception as e:  # Erreur réseau, timeout ou JSON invalide
        print(f"  !! échec d'envoi vers {SERVER_URL} : {e}")  # Informe l'utilisateur de l'échec


def merite_analyse(texte):
    """Pré-filtre simple pour éviter d'envoyer chaque copier-coller anodin."""
    t = texte.lower()  # Texte en minuscules pour la détection de motifs
    if "http://" in t or "https://" in t or "www." in t:  # Lien web copié
        return "link"  # Catégorie lien
    if "*" in texte and "#" in texte:  # Syntaxe typique d'un code USSD
        return "ussd"  # Catégorie code USSD
    if any(c.isdigit() for c in texte) and sum(c.isdigit() for c in texte) >= 8:  # Numéro ou compte long
        return "clipboard"  # Catégorie contenu numérique sensible
    if any(k in t for k in MOTS_CLES):  # Mot-clé d'arnaque détecté
        return "message"  # Catégorie message suspect
    return None  # Contenu anodin : pas d'envoi au serveur


class DownloadsHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:  # Ignore la création de dossiers
            return
        nom = os.path.basename(event.src_path)  # Nom du fichier créé
        if nom.lower().endswith(EXT_DANGEREUSES):  # Extension potentiellement dangereuse
            print(f"[fichier] nouveau fichier exécutable : {nom}")  # Log console transparent
            envoyer("file", nom, {"path": event.src_path})  # Rapport au serveur avec chemin complet


def surveiller_presse_papier():
    print(f"[presse-papier] surveillance active (toutes les {POLL_SECONDS}s)")  # Annonce du démarrage
    dernier = ""  # Dernier contenu déjà traité (évite les répétitions)
    while True:  # Boucle infinie jusqu'à Ctrl+C
        try:
            actuel = pyperclip.paste()  # Lit le presse-papier Windows
        except Exception:
            actuel = ""  # Presse-papier inaccessible : valeur vide
        if actuel and actuel != dernier:  # Nouveau contenu différent du précédent
            dernier = actuel  # Mémorise pour ne pas retraiter
            type_event = merite_analyse(actuel)  # Détermine si le contenu mérite analyse
            if type_event:  # Contenu suspect détecté
                apercu = actuel[:80].replace("\n", " ")  # Aperçu tronqué pour la console
                print(f"[presse-papier] détecté ({type_event}) : {apercu}")  # Log transparent
                envoyer(type_event, actuel)  # Envoi au serveur MoMoGuard
        time.sleep(POLL_SECONDS)  # Pause avant la prochaine lecture


def surveiller_navigateur():
    """Surveille les clics sur des liens via l'historique des navigateurs."""
    print(f"[navigateur] surveillance des liens ouverts (toutes les {BROWSER_POLL_SECONDS}s)")  # Annonce
    chemins = _chemins_navigateurs()  # Détecte les navigateurs installés
    if not chemins:  # Aucun navigateur compatible trouvé
        print("[navigateur] aucun navigateur compatible détecté (Chrome, Edge, Firefox, Brave)")
        return  # Arrête ce fil de surveillance

    for moteur, nom, _ in chemins:  # Affiche chaque profil détecté
        print(f"[navigateur] profil actif : {nom} ({moteur})")

    # Ne remonter que les visites après le démarrage de l'agent
    curseurs = {}  # Horodatage minimal par profil (évite le rejeu de l'historique)
    for moteur, nom, _ in chemins:  # Initialise un curseur par navigateur
        cle = f"{moteur}:{nom}"  # Clé unique profil
        curseurs[cle] = (_timestamp_chrome_us() if moteur == "chromium"  # Format horaire selon moteur
                         else _timestamp_firefox_us())

    urls_recentes = deque(maxlen=200)  # Cache des 200 dernières URLs déjà envoyées

    while True:  # Boucle de polling de l'historique
        for moteur, nom, chemin in chemins:  # Parcourt chaque profil navigateur
            cle = f"{moteur}:{nom}"  # Identifiant du profil courant
            depuis = curseurs[cle]  # Seuil temporel pour ce profil
            if moteur == "chromium":  # Chrome, Edge ou Brave
                visites = _lire_visites_chromium(chemin, depuis)  # Lit les nouvelles visites Chromium
            else:
                visites = _lire_visites_firefox(chemin, depuis)  # Lit les nouvelles visites Firefox

            for url, titre, horodatage in visites:  # Traite chaque visite récente
                curseurs[cle] = max(curseurs[cle], horodatage)  # Avance le curseur temporel
                if not url_a_analyser(url) or url in urls_recentes:  # URL ignorée ou déjà traitée
                    continue  # Passe à la visite suivante
                urls_recentes.append(url)  # Marque l'URL comme déjà envoyée
                apercu = url[:80]  # Aperçu tronqué pour la console
                print(f"[navigateur] lien ouvert ({nom}) : {apercu}")  # Log transparent
                envoyer("link", url, {  # Rapport lien avec métadonnées navigateur
                    "source": "browser_click",  # Origine : clic dans le navigateur
                    "browser": nom,  # Nom du navigateur (chrome, edge, etc.)
                    "title": titre[:200] if titre else "",  # Titre de la page (tronqué)
                })

        time.sleep(BROWSER_POLL_SECONDS)  # Pause avant le prochain cycle de lecture


def main():
    print("=" * 60)  # Séparateur visuel de démarrage
    print(" Agent Windows MoMoGuard (transparent)")  # Titre de l'agent
    print(f" Serveur : {SERVER_URL}")  # URL du serveur cible
    print(f" Agent   : {AGENT_ID}")
    print(f" Jeton   : {'OK' if AGENT_TOKEN else 'MANQUANT (agents/agent_token.txt)'}")
    print(f" Dossier surveillé : {DOWNLOADS_DIR}")  # Dossier Téléchargements
    print(" Config  : agents/server_url.txt (optionnel) | agents/agent_token.txt")
    print(" Arrêt : Ctrl+C")  # Instruction d'arrêt manuel
    print("=" * 60)  # Fin du bandeau d'accueil

    observer = None  # Observateur watchdog, initialisé si Téléchargements existe
    if os.path.isdir(DOWNLOADS_DIR):  # Le dossier Téléchargements est accessible
        observer = Observer()  # Crée l'observateur de fichiers
        observer.schedule(DownloadsHandler(), DOWNLOADS_DIR, recursive=False)  # Surveille sans sous-dossiers
        observer.start()  # Démarre le thread de surveillance fichiers
        print(f"[fichier] surveillance de {DOWNLOADS_DIR}")  # Confirmation console
    else:
        print("[fichier] dossier Téléchargements introuvable — surveillance fichiers désactivée")

    threading.Thread(target=surveiller_navigateur, daemon=True).start()  # Lance la surveillance navigateur en arrière-plan

    try:
        surveiller_presse_papier()  # Boucle principale : presse-papier (bloquant)
    except KeyboardInterrupt:  # Arrêt demandé par Ctrl+C
        print("\n[arrêt] agent stoppé par l'utilisateur")  # Message de fin propre
    finally:
        if observer:  # Arrêt propre de l'observateur fichiers si actif
            observer.stop()  # Signale l'arrêt au thread watchdog
            observer.join()  # Attend la fin du thread


if __name__ == "__main__":  # Point d'entrée si exécution directe du script
    main()  # Lance l'agent Windows
