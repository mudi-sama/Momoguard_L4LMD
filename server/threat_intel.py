"""Consommation d'une API externe de réputation d'URL (threat intelligence).

Interroge Google Safe Browsing (v4) pour savoir si une URL est connue comme
malveillante (phishing, malware, logiciel indésirable). La clé API se configure
via la variable d'environnement SAFEBROWSING_API_KEY.

Dégradation gracieuse : sans clé ou en cas d'erreur réseau, le module renvoie
« unknown » et n'affecte pas le scoring — la plateforme continue de fonctionner
hors ligne.
"""
import os  # Lecture de la variable d'environnement SAFEBROWSING_API_KEY
import re  # Extraction des URLs dans un texte

import requests  # Appels HTTP vers l'API Google Safe Browsing

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"  # Endpoint officiel v4
URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)  # Motif http(s) ou www.
TIMEOUT = 4  # Délai max (secondes) pour ne pas bloquer le scoring


def is_ready():
    """Vrai si une clé API est configurée."""
    return bool(os.environ.get("SAFEBROWSING_API_KEY"))  # Sans clé → module inactif


def extract_urls(text):
    """Extrait les URLs d'un texte (préfixe http:// pour les www.)."""
    urls = []  # Liste des URLs trouvées
    for match in URL_REGEX.findall(text or ""):  # Parcourt chaque correspondance regex
        url = match[0] if isinstance(match, tuple) else match  # Normalise le format de capture
        if url.lower().startswith("www."):  # www. seul n'est pas une URL valide pour l'API
            url = "http://" + url  # Ajoute le schéma manquant
        urls.append(url.rstrip(".,;)"))  # Retire la ponctuation collée en fin de phrase
    return urls


def check_urls(urls):
    """Renvoie 'malicious' si au moins une URL est signalée, 'clean' si toutes
    sont saines, 'unknown' sans clé ou en cas d'erreur."""
    key = os.environ.get("SAFEBROWSING_API_KEY")  # Clé API Google Cloud
    if not key or not urls:  # Rien à vérifier ou pas de clé
        return "unknown"
    body = {  # Corps JSON attendu par l'API Safe Browsing v4
        "client": {"clientId": "momoguard", "clientVersion": "1.0"},  # Identifiant client
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],  # Types recherchés
            "platformTypes": ["ANY_PLATFORM"],  # Toutes plateformes
            "threatEntryTypes": ["URL"],  # On envoie des URLs
            "threatEntries": [{"url": u} for u in urls],  # Liste des URLs à analyser
        },
    }
    try:
        r = requests.post(API_URL, params={"key": key}, json=body, timeout=TIMEOUT)  # Requête POST
        if r.status_code != 200:  # Erreur HTTP (quota, clé invalide…)
            return "unknown"
        return "malicious" if (r.json() or {}).get("matches") else "clean"  # matches = URL dangereuse
    except Exception:  # Timeout, pas de réseau, JSON invalide
        return "unknown"  # Ne bloque jamais le traitement principal
