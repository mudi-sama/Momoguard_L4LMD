"""Moteur de scoring basé sur des règles (explicable) — version affinée.

Principe : chaque signal suspect ajoute des points. La somme donne un score
(0-100) et un niveau (faible / moyen / eleve). Chaque règle déclenchée est
enregistrée dans `reasons` pour pouvoir EXPLIQUER la décision devant le jury.

Améliorations de cette version :
  - détection des domaines sosies écrits en homoglyphes (0range, airte1, v0dacom) ;
  - correspondance des mots-clés insensible aux accents (gagne = gagné) ;
  - bonus quand urgence et lien apparaissent ensemble (schéma d'arnaque classique) ;
  - niveau « faible » réservé aux canaux officiels des opérateurs (sender ID / app).
"""

import re  # Expressions régulières pour extraire URLs, montants, USSD, numéros
import unicodedata  # Normalisation Unicode pour ignorer les accents à la comparaison

# --- Listes de référence (contexte Mobile Money RDC) -----------------------

OPERATEURS = ["orange", "airtel", "vodacom", "mpesa", "africell", "illico"]  # Noms d'opérateurs locaux

# Domaines officiels
DOMAINES_OFFICIELS = ["orange.cd", "airtel.cd", "vodacom.cd", "africell.cd"]

TLD_SUSPECTS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".link"]  # Extensions souvent abusées

RACCOURCISSEURS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"]  # Services qui masquent l'URL réelle

# Sender ID officiels (normalisés), short codes et apps Android — RDC / calibration.
SENDERS_OFFICIELS = {
    "orange", "orangemoney", "orangemoneyrdc", "omoney", "orangerdc",
    "airtel", "airtelmoney", "airtelmoneydrc", "airtelrdc",
    "vodacom", "vodacomrdc", "mpesa", "mpesardc", "vodacommpesa",
    "africell", "afrimoney", "africellmoney", "africellrdc",
}
SHORT_CODES_OFFICIELS = {
    "100", "111", "123", "124", "130", "144", "145", "149", "400", "425",
}
# MSISDN de confiance : messages classés « faible » (ex. téléphone de démo / contact sûr).
NUMEROS_DE_CONFIANCE = {
    "243854348028",
}
PACKAGES_OFFICIELS_PREFIXES = (
    "com.orange.", "com.airtel.", "com.vodacom.", "com.vodafone.",
    "com.africell.", "cd.orange.", "cd.airtel.", "cd.vodacom.",
)
MOTS_MOBILE_MONEY = [
    "orange money", "airtel money", "m-pesa", "mpesa", "africell", "afrimoney",
    "mobile money", "solde", "transfert", "transaction", "retrait", "depot",
    "porte-monnaie", "vous avez recu", "vous avez envoye", "code pin",
    "code secret", "otp", "ussd",
]

# Mots-clés écrits SANS accent : la comparaison se fait sur du texte normalisé.
MOTS_CLES_FRAUDE = [  # Lexique typique des arnaques par SMS/message
    "code pin", "code secret", "code de confirmation", "urgent", "gagne",
    "gagnant", "felicitations", "cliquez", "bloque", "reactiver", "confirmez",
    "verifiez", "promotion", "tombola", "loterie", "recompense", "suspendu",
    "votre compte sera", "activer maintenant", "lien ci-dessous", "deblocage",
]

MOTS_URGENCE = ["urgent", "immediatement", "maintenant", "suspendu", "bloque", "expire"]  # Termes de pression temporelle

# Nouveaux types d'attaque (Phase 5)
MOTS_SIM_SWAP = [  # Indicateurs de fraude par remplacement de carte SIM
    "carte sim", "nouvelle sim", "nouvelle carte sim", "remplacer la sim",
    "remplacement de sim", "remplacement sim", "code puk", "puk",
    "changer de sim", "swap sim", "sim bloquee", "reinitialiser la sim",
]
VERBES_PARTAGE = [  # Verbes invitant à transmettre une information sensible
    "partage", "partagez", "envoie", "envoyez", "donne", "donnez",
    "communique", "communiquez", "transfere", "transferez", "dicte", "dictez",
]
MOTS_CODE = ["code", "otp", "code de confirmation", "code de verification", "code secret"]  # Références à des codes à usage unique
MOTS_ACTION_AGENT = ["composez", "envoyez", "confirmez", "validez", "donnez", "code", "transferez"]  # Verbes d'instruction d'un faux agent
MOTS_ERREUR = ["par erreur", "envoye par erreur", "erreur de transfert", "transfert par erreur"]  # Prétexte « transfert accidentel »
MOTS_REMBOURSEMENT = ["rembours", "renvoyez", "renvoie", "retournez", "retourner l'argent", "renvoyer l'argent"]  # Demande de renvoi d'argent

# Identifiants sensibles (un code OU un mot de passe ne se partagent jamais)
MOTS_IDENTIFIANT = MOTS_CODE + ["mot de passe", "code pin", "identifiants", "mdp"]  # Union codes + secrets d'authentification
# Formulations PROTECTRICES (le message met en garde, il ne demande pas de partager)
MOTS_PROTECTEUR = ["jamais", "a personne", "ne communiquez", "ne le communiquez",  # Formulations légitimes de mise en garde
                   "ne partagez", "ne le partagez", "ne donnez", "ne le donnez", "ne divulguez"]
# Appât au gain (loterie / cadeau) et amorces de sollicitation
MOTS_GAIN = ["gagne", "gagnant", "gagner", "tombola", "loterie", "felicitations",  # Promesses de gain ou récompense
             "selectionne", "tirage", "recompense", "cadeau"]
MOTS_APPAT = ["frais", "payer", "envoyez", "envoie", "recevez", "reclamez", "cliquez", "bonus"]  # Actions demandées après l'appât

EXTENSIONS_DANGEREUSES = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".apk", ".jar"]  # Suffixes de fichiers exécutables

# Substitutions d'homoglyphes les plus courantes
HOMOGLYPHES = str.maketrans({  # Table de traduction caractère → lettre pour détecter les sosies visuelles
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "$": "s", "@": "a",
})

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)  # Capture http(s)://… ou www.… jusqu'à l'espace
MONTANT_REGEX = re.compile(r"\d[\d.\s]*\s*(\$|fc|usd|cdf)", re.IGNORECASE)  # Montant suivi d'une devise ($, FC, USD, CDF)
IP_HOST_REGEX = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}", re.IGNORECASE)  # URL dont l'hôte est une adresse IPv4
USSD_REGEX = re.compile(r"\*\d{2,4}(\*[\d#]+)*#")  # Séquence USSD type *123*456#
NUMERO_REGEX = re.compile(r"(\+?243|0)\d{8,9}")  # Numéro congolais (+243 ou 0 suivi de 8-9 chiffres)


def _sans_accents(texte):
    """Minuscule + suppression des accents (gagné -> gagne)."""
    t = unicodedata.normalize("NFD", texte.lower())  # Décompose les caractères accentués en base + marque diacritique
    return "".join(c for c in t if unicodedata.category(c) != "Mn")  # Retire les marques combinantes (accents)


def _extract_domain(url):
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)  # Supprime le schéma http ou https en tête
    url = re.sub(r"^www\.", "", url, flags=re.IGNORECASE)  # Supprime le préfixe www. éventuel
    return url.split("/")[0].lower()  # Prend l'hôte avant le premier /, en minuscules


def _domaine_nettoye(domain):
    """Ramène un domaine à sa forme « lisible » pour détecter les sosies."""
    deleet = domain.translate(HOMOGLYPHES)  # Remplace chiffres/symboles par leurs équivalents lettres
    return re.sub(r"[^a-z]", "", deleet)  # Ne conserve que les lettres minuscules a-z


def _normaliser_sender(valeur):
    """Normalise un expéditeur / package pour comparaison."""
    brut = _sans_accents(str(valeur or "").strip())
    return re.sub(r"[\s\-_.]+", "", brut)


def _normaliser_msisdn(valeur):
    """Normalise un numéro (+243… / 0…) en chiffres internationaux sans +."""
    digits = re.sub(r"\D", "", str(valeur or ""))
    if digits.startswith("00"):
        digits = digits[2:]
    if len(digits) == 10 and digits.startswith("0"):
        digits = "243" + digits[1:]
    return digits


def _sources_expediteur(metadata):
    """Collecte les champs d'expéditeur / app utiles pour le scoring."""
    metadata = metadata or {}
    sources = [
        str(metadata.get("sender", "") or "").strip(),
        str(metadata.get("package", "") or "").strip(),
    ]
    for cle in ("from", "address", "app_name"):
        val = metadata.get(cle)
        if val:
            sources.append(str(val).strip())
    return sources


def est_numero_de_confiance(metadata=None):
    """True si l'expéditeur est un MSISDN explicitement de confiance."""
    for src in _sources_expediteur(metadata):
        if not src:
            continue
        if _normaliser_msisdn(src) in NUMEROS_DE_CONFIANCE:
            return True
    return False


def est_canal_officiel(metadata=None):
    """True si l'évènement vient d'un canal opérateur officiel (SMS ou app).

    Un MSISDN personnel (+243…) n'est jamais considéré comme canal officiel,
    sauf s'il figure dans NUMEROS_DE_CONFIANCE.
    """
    metadata = metadata or {}
    if est_numero_de_confiance(metadata):
        return True
    if str(metadata.get("filter_categorie", "")).upper() == "CONFIRMATION_OPERATEUR":
        return True

    for src in _sources_expediteur(metadata):
        if not src:
            continue
        digits = re.sub(r"[\s\-]", "", src)
        if NUMERO_REGEX.fullmatch(digits):
            continue
        norm = _normaliser_sender(src)
        if not norm:
            continue
        if norm in SENDERS_OFFICIELS or norm in SHORT_CODES_OFFICIELS:
            return True
        pkg = src.lower().strip()
        if any(pkg.startswith(p) for p in PACKAGES_OFFICIELS_PREFIXES):
            return True
        if any(norm.startswith(s) and len(norm) <= len(s) + 6 for s in SENDERS_OFFICIELS):
            return True
    return False


def _concerne_mobile_money(norm):
    """True si le texte évoque le Mobile Money / un opérateur."""
    if any(m in norm for m in MOTS_MOBILE_MONEY):
        return True
    if any(op in norm for op in OPERATEURS):
        return True
    if MONTANT_REGEX.search(norm) or USSD_REGEX.search(norm):
        return True
    return False


def score_event(event_type, content, metadata=None, thresholds=(25, 55)):
    """Analyse un évènement et renvoie (score, niveau, raisons).

    thresholds = (seuil_moyen, seuil_eleve) : bornes configurables des niveaux.

    Politique « faible » : pour le Mobile Money, le niveau faible n'est accordé
    que si le message est émis depuis un canal officiel (sender ID / app).
    """
    metadata = metadata or {}  # Métadonnées optionnelles (expéditeur, etc.) ; dict vide par défaut
    content = content or ""  # Contenu textuel ; chaîne vide si absent
    # Numéro de confiance : toujours niveau faible (téléphone de démo / contact sûr).
    if est_numero_de_confiance(metadata):
        return 0, "faible", [
            "Expéditeur de confiance (+243854348028) — niveau faible"
        ]
    norm = _sans_accents(content)  # Version normalisée pour comparaisons insensibles aux accents
    score = 0  # Compteur cumulatif de points de risque
    reasons = []  # Liste des explications associées aux règles déclenchées
    officiel = est_canal_officiel(metadata)

    # 1) Analyse des liens / URLs ------------------------------------------
    urls = URL_REGEX.findall(content)  # Extrait toutes les URLs présentes dans le message
    urls = [u[0] if isinstance(u, tuple) else u for u in urls]  # Aplatit les tuples éventuels du regex
    a_un_lien = bool(urls)  # Indicateur booléen : au moins une URL trouvée
    for url in urls:  # Évalue chaque lien individuellement
        domain = _extract_domain(url)  # Isole le nom d'hôte brut
        clean = _domaine_nettoye(domain)  # Forme « déguisée » du domaine sans homoglyphes

        if IP_HOST_REGEX.search(url):  # L'URL pointe vers une IP au lieu d'un nom de domaine
            score += 30  # Pénalité forte : comportement atypique des sites légitimes
            reasons.append("Lien pointant vers une adresse IP brute (très suspect)")

        if any(domain == d or domain.endswith("." + d) for d in RACCOURCISSEURS):  # Hôte = raccourcisseur connu
            score += 20  # Pénalité : destination réelle masquée
            reasons.append(f"Lien raccourci masquant la vraie destination ({domain})")

        if any(domain.endswith(tld) for tld in TLD_SUSPECTS):  # Extension de premier niveau peu fiable
            score += 15  # Pénalité modérée pour TLD à réputation douteuse
            reasons.append(f"Extension de domaine peu fiable ({domain})")

        # Domaine sosie : imite un opérateur (même via homoglyphes) sans être officiel
        if any(op in clean for op in OPERATEURS) and not any(  # Nom d'opérateur dans le domaine nettoyé
            domain == d or domain.endswith("." + d) for d in DOMAINES_OFFICIELS  # …mais pas un domaine officiel
        ):
            score += 35  # Pénalité élevée : usurpation probable de marque
            note = f"Domaine imitant un opérateur sans être officiel ({domain}"  # Début du message explicatif
            if clean != re.sub(r"[^a-z]", "", domain):  # Homoglyphes détectés (forme nettoyée différente)
                note += f" → lu « {clean} »"  # Affiche la lecture « corrigée » du domaine
            reasons.append(note + ")")  # Finalise et enregistre la raison

        if url.lower().startswith("http://"):  # Protocole non chiffré
            score += 5  # Pénalité légère : absence de TLS
            reasons.append("Connexion non sécurisée (http au lieu de https)")

    # 2) Mots-clés d'ingénierie sociale (insensible aux accents) -----------
    cles_trouvees = [k for k in MOTS_CLES_FRAUDE if k in norm]  # Sous-ensemble des mots-clés présents
    if cles_trouvees:  # Au moins un mot-clé de fraude repéré
        gain = min(len(cles_trouvees) * 8, 32)  # 8 pts par mot, plafonné à 32
        score += gain  # Ajoute le gain calculé au score total
        reasons.append("Vocabulaire d'arnaque détecté : " + ", ".join(cles_trouvees[:4]))  # Liste les 4 premiers

    # 3) Combo urgence + lien (schéma classique de phishing) ---------------
    if a_un_lien and any(u in norm for u in MOTS_URGENCE):  # Lien ET terme d'urgence dans le même message
        score += 12  # Bonus combo : schéma classique de hameçonnage
        reasons.append("Sentiment d'urgence combiné à un lien (pression typique d'arnaque)")

    # 4) Expéditeur hors canal officiel ------------------------------------
    sender = str(metadata.get("sender", "")).strip()  # Numéro ou identifiant de l'expéditeur, nettoyé
    evoque_operateur = any(op in norm for op in OPERATEURS)
    if not officiel and evoque_operateur:
        if sender and NUMERO_REGEX.fullmatch(re.sub(r"[\s\-]", "", sender)):
            score += 20  # Usurpation depuis un mobile personnel
            reasons.append(
                f"Message au nom d'un opérateur envoyé depuis un numéro personnel ({sender})"
            )
        else:
            score += 15
            reasons.append(
                "Message évoquant un opérateur hors canal officiel "
                "(sender ID / application non reconnus)"
            )

    # 5) Code USSD à risque -------------------------------------------------
    if USSD_REGEX.search(content):  # Présence d'une séquence USSD dans le texte brut
        score += 25  # Pénalité : risque de manipulation de compte via codes dial
        reasons.append("Présence d'un code USSD (possible transfert ou renvoi dicté)")

    # 6) Fichier dangereux --------------------------------------------------
    if event_type == "file" and any(norm.endswith(ext) for ext in EXTENSIONS_DANGEREUSES):  # Événement fichier + extension exécutable
        score += 30  # Pénalité forte : malware potentiel
        reasons.append("Fichier exécutable potentiellement malveillant")

    # 7) Presse-papier contenant un numéro de paiement ----------------------
    if event_type == "clipboard" and NUMERO_REGEX.search(content):  # Copie d'un numéro Mobile Money
        score += 10  # Pénalité modérée : risque de substitution de bénéficiaire
        reasons.append("Numéro de compte/téléphone copié — vérifier qu'il n'a pas été modifié")

    # 8) SIM swap (remplacement de SIM / PUK) -------------------------------
    if any(k in norm for k in MOTS_SIM_SWAP):  # Vocabulaire de remplacement SIM ou PUK
        score += 25  # Pénalité : attaque SIM swap possible
        reasons.append("Référence à un remplacement de SIM / code PUK (possible SIM swap)")

    # 9) Partage ou demande d'un identifiant (code OTP ou mot de passe) -----
    if (any(k in norm for k in MOTS_IDENTIFIANT) and any(v in norm for v in VERBES_PARTAGE)  # Demande de partage d'identifiant
            and not any(p in norm for p in MOTS_PROTECTEUR)):  # …sans formulation protectrice (avertissement légitime)
        score += 30  # Pénalité forte : demande explicite de secret
        reasons.append("Demande de partage d'un code/mot de passe (ne se partagent jamais)")

    # 10) Faux agent Mobile Money -------------------------------------------
    if ("agent" in norm and any(op in norm for op in OPERATEURS)  # Se présente comme agent d'un opérateur
            and any(a in norm for a in MOTS_ACTION_AGENT)):  # …avec une consigne d'action
        score += 25  # Pénalité : usurpation d'agent avec instruction
        reasons.append("Message se présentant comme un agent opérateur avec une consigne d'action")

    # 11) Arnaque « envoi par erreur / remboursement » ----------------------
    if any(e in norm for e in MOTS_ERREUR) and any(r in norm for r in MOTS_REMBOURSEMENT):  # Erreur + demande de remboursement
        score += 25  # Pénalité : arnaque au faux virement accidentel
        reasons.append("Schéma « envoi par erreur, remboursez-moi » (arnaque au remboursement)")

    # 12) Appât au gain (loterie / cadeau) avec sollicitation ---------------
    if any(g in norm for g in MOTS_GAIN) and any(a in norm for a in MOTS_APPAT):  # Gain promis + action demandée
        score += 25  # Pénalité : loterie frauduleuse ou cadeau piégé
        reasons.append("Appât au gain (loterie/cadeau) accompagné d'une sollicitation")

    # 13) Promesse de multiplier l'argent -----------------------------------
    if ("recevez" in norm and ("envoyez" in norm or "envoie" in norm)  # Schéma « envoyez X, recevez Y »
            and MONTANT_REGEX.search(norm)):  # …avec des montants chiffrés
        score += 22  # Pénalité : arnaque pyramidale ou multiplication d'argent
        reasons.append("Promesse de multiplier l'argent (« envoyez X, recevez Y »)")

    # 14) Frais à payer pour débloquer un compte ----------------------------
    if "frais" in norm and ("payer" in norm or "deblocage" in norm):  # Demande de frais pour déblocage
        score += 22  # Pénalité : arnaque aux frais administratifs fictifs
        reasons.append("Demande de frais pour débloquer un compte (arnaque aux frais)")

    # --- Bornage et niveau -------------------------------------------------
    seuil_moyen, seuil_eleve = thresholds  # Dépaquette les deux seuils configurables
    score = max(0, min(score, 100))  # Borne le score entre 0 et 100 inclus

    # Politique : « faible » uniquement depuis un canal opérateur officiel
    # pour tout message lié au Mobile Money / aux opérateurs.
    if score < seuil_moyen:
        if officiel:
            level = "faible"
            if not reasons or reasons == ["Aucun signal suspect détecté"]:
                reasons = ["Aucun signal suspect — canal opérateur officiel"]
            elif "canal opérateur officiel" not in " ".join(reasons).lower():
                reasons.append("Canal opérateur officiel reconnu")
        elif _concerne_mobile_money(norm):
            score = max(score, seuil_moyen)
            level = "moyen"
            reasons.append(
                "Niveau faible refusé : réservé aux SMS/apps officiels des opérateurs"
            )
        else:
            level = "faible"
    elif score >= seuil_eleve:
        level = "eleve"
    else:
        level = "moyen"

    if not reasons:  # Aucune règle n'a produit d'explication
        reasons.append("Aucun signal suspect détecté")  # Message par défaut pour traçabilité

    return score, level, reasons  # Tuple : points, catégorie, liste des justifications
