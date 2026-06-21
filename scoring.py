"""Moteur de scoring basé sur des règles (explicable) — version affinée.

Principe : chaque signal suspect ajoute des points. La somme donne un score
(0-100) et un niveau (faible / moyen / eleve). Chaque règle déclenchée est
enregistrée dans `reasons` pour pouvoir EXPLIQUER la décision devant le jury.

Améliorations de cette version :
  - détection des domaines sosies écrits en homoglyphes (0range, airte1, v0dacom) ;
  - correspondance des mots-clés insensible aux accents (gagne = gagné) ;
  - bonus quand urgence et lien apparaissent ensemble (schéma d'arnaque classique).
"""

import re
import unicodedata

# --- Listes de référence (contexte Mobile Money RDC) -----------------------

OPERATEURS = ["orange", "airtel", "vodacom", "mpesa", "africell", "illico"]

# Domaines officiels (approximatifs, à compléter selon tes sources réelles)
DOMAINES_OFFICIELS = ["orange.cd", "airtel.cd", "vodacom.cd", "africell.cd"]

TLD_SUSPECTS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".link"]

RACCOURCISSEURS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"]

# Mots-clés écrits SANS accent : la comparaison se fait sur du texte normalisé.
MOTS_CLES_FRAUDE = [
    "code pin", "code secret", "code de confirmation", "urgent", "gagne",
    "gagnant", "felicitations", "cliquez", "bloque", "reactiver", "confirmez",
    "verifiez", "promotion", "tombola", "loterie", "recompense", "suspendu",
    "votre compte sera", "activer maintenant", "lien ci-dessous",
]

MOTS_URGENCE = ["urgent", "immediatement", "maintenant", "suspendu", "bloque", "expire"]

# Nouveaux types d'attaque (Phase 5)
MOTS_SIM_SWAP = [
    "carte sim", "nouvelle sim", "nouvelle carte sim", "remplacer la sim",
    "remplacement de sim", "remplacement sim", "code puk", "puk",
    "changer de sim", "swap sim", "sim bloquee", "reinitialiser la sim",
]
VERBES_PARTAGE = [
    "partage", "partagez", "envoie", "envoyez", "donne", "donnez",
    "communique", "communiquez", "transfere", "transferez", "dicte", "dictez",
]
MOTS_CODE = ["code", "otp", "code de confirmation", "code de verification", "code secret"]
MOTS_ACTION_AGENT = ["composez", "envoyez", "confirmez", "validez", "donnez", "code", "transferez"]
MOTS_ERREUR = ["par erreur", "envoye par erreur", "erreur de transfert", "transfert par erreur"]
MOTS_REMBOURSEMENT = ["rembours", "renvoyez", "renvoie", "retournez", "retourner l'argent", "renvoyer l'argent"]

PACKAGES_MESSAGERIE = {
    "com.whatsapp": "WhatsApp",
    "org.telegram.messenger": "Telegram",
    "com.facebook.orca": "Messenger",
    "com.viber.voip": "Viber",
    "org.thoughtcrime.securesms": "Signal",
}

EXTENSIONS_DANGEREUSES = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".apk", ".jar"]

# Substitutions d'homoglyphes les plus courantes
HOMOGLYPHES = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "$": "s", "@": "a",
})

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
IP_HOST_REGEX = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}", re.IGNORECASE)
USSD_REGEX = re.compile(r"\*\d{2,4}(\*[\d#]+)*#")
NUMERO_REGEX = re.compile(r"(\+?243|0)\d{8,9}")


def _sans_accents(texte):
    """Minuscule + suppression des accents (gagné -> gagne)."""
    t = unicodedata.normalize("NFD", texte.lower())
    return "".join(c for c in t if unicodedata.category(c) != "Mn")


def _extract_domain(url):
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)
    return url.split("/")[0].lower()


def _domaine_nettoye(domain):
    """Ramène un domaine à sa forme « lisible » pour détecter les sosies."""
    deleet = domain.translate(HOMOGLYPHES)
    return re.sub(r"[^a-z]", "", deleet)


def score_event(event_type, content, metadata=None, thresholds=(25, 55)):
    """Analyse un évènement et renvoie (score, niveau, raisons).

    thresholds = (seuil_moyen, seuil_eleve) : bornes configurables des niveaux.
    """
    metadata = metadata or {}
    content = content or ""
    norm = _sans_accents(content)
    score = 0
    reasons = []

    # 1) Analyse des liens / URLs ------------------------------------------
    urls = URL_REGEX.findall(content)
    urls = [u[0] if isinstance(u, tuple) else u for u in urls]
    a_un_lien = bool(urls)
    for url in urls:
        domain = _extract_domain(url)
        clean = _domaine_nettoye(domain)

        if IP_HOST_REGEX.search(url):
            score += 30
            reasons.append("Lien pointant vers une adresse IP brute (très suspect)")

        if any(domain == d or domain.endswith("." + d) for d in RACCOURCISSEURS):
            score += 20
            reasons.append(f"Lien raccourci masquant la vraie destination ({domain})")

        if any(domain.endswith(tld) for tld in TLD_SUSPECTS):
            score += 15
            reasons.append(f"Extension de domaine peu fiable ({domain})")

        # Domaine sosie : imite un opérateur (même via homoglyphes) sans être officiel
        if any(op in clean for op in OPERATEURS) and not any(
            domain == d or domain.endswith("." + d) for d in DOMAINES_OFFICIELS
        ):
            score += 35
            note = f"Domaine imitant un opérateur sans être officiel ({domain}"
            if clean != re.sub(r"[^a-z]", "", domain):
                note += f" → lu « {clean} »"
            reasons.append(note + ")")

        if url.lower().startswith("http://"):
            score += 5
            reasons.append("Connexion non sécurisée (http au lieu de https)")

    # 2) Mots-clés d'ingénierie sociale (insensible aux accents) -----------
    cles_trouvees = [k for k in MOTS_CLES_FRAUDE if k in norm]
    if cles_trouvees:
        gain = min(len(cles_trouvees) * 8, 32)
        score += gain
        reasons.append("Vocabulaire d'arnaque détecté : " + ", ".join(cles_trouvees[:4]))

    # 3) Combo urgence + lien (schéma classique de phishing) ---------------
    if a_un_lien and any(u in norm for u in MOTS_URGENCE):
        score += 12
        reasons.append("Sentiment d'urgence combiné à un lien (pression typique d'arnaque)")

    # 4) Expéditeur usurpé --------------------------------------------------
    sender = str(metadata.get("sender", "")).strip()
    if sender and NUMERO_REGEX.fullmatch(sender) and any(op in norm for op in OPERATEURS):
        score += 15
        reasons.append(f"Message au nom d'un opérateur envoyé depuis un numéro personnel ({sender})")

    # 4b) Notification d'app tierce usurpant un opérateur ------------------
    if event_type == "notification":
        package = str(metadata.get("package", "")).strip().lower()
        app_name = str(metadata.get("app_name", "")).strip()
        if package:
            nom_app = PACKAGES_MESSAGERIE.get(package, app_name or package)
            ops = [op for op in OPERATEURS if op in norm]
            if ops and package in PACKAGES_MESSAGERIE:
                score += 12
                reasons.append(
                    f"Alerte opérateur ({ops[0]}) via {nom_app} — "
                    "les opérateurs n'envoient pas les codes OTP par messagerie"
                )

    # 5) Code USSD à risque -------------------------------------------------
    if USSD_REGEX.search(content):
        score += 25
        reasons.append("Présence d'un code USSD (possible transfert ou renvoi dicté)")

    # 6) Fichier dangereux --------------------------------------------------
    if event_type == "file" and any(norm.endswith(ext) for ext in EXTENSIONS_DANGEREUSES):
        score += 30
        reasons.append("Fichier exécutable potentiellement malveillant")

    # 7) Presse-papier contenant un numéro de paiement ----------------------
    if event_type == "clipboard" and NUMERO_REGEX.search(content):
        score += 10
        reasons.append("Numéro de compte/téléphone copié — vérifier qu'il n'a pas été modifié")

    # 8) SIM swap (remplacement de SIM / PUK) -------------------------------
    if any(k in norm for k in MOTS_SIM_SWAP):
        score += 25
        reasons.append("Référence à un remplacement de SIM / code PUK (possible SIM swap)")

    # 9) Partage ou demande de code OTP -------------------------------------
    if (any(k in norm for k in MOTS_CODE) and any(v in norm for v in VERBES_PARTAGE)
            and "jamais" not in norm):
        score += 30
        reasons.append("Demande de partage d'un code/OTP (un code ne se partage jamais)")

    # 10) Faux agent Mobile Money -------------------------------------------
    if ("agent" in norm and any(op in norm for op in OPERATEURS)
            and any(a in norm for a in MOTS_ACTION_AGENT)):
        score += 25
        reasons.append("Message se présentant comme un agent opérateur avec une consigne d'action")

    # 11) Arnaque « envoi par erreur / remboursement » ----------------------
    if any(e in norm for e in MOTS_ERREUR) and any(r in norm for r in MOTS_REMBOURSEMENT):
        score += 25
        reasons.append("Schéma « envoi par erreur, remboursez-moi » (arnaque au remboursement)")

    # --- Bornage et niveau -------------------------------------------------
    seuil_moyen, seuil_eleve = thresholds
    score = max(0, min(score, 100))
    if score >= seuil_eleve:
        level = "eleve"
    elif score >= seuil_moyen:
        level = "moyen"
    else:
        level = "faible"

    if not reasons:
        reasons.append("Aucun signal suspect détecté")

    return score, level, reasons
