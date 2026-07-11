"""Vérification des jetons Firebase côté serveur (SDK firebase-admin).

L'app Android authentifie l'utilisateur via Firebase, récupère un « ID token »,
et l'envoie au backend. Ce module vérifie ce jeton et en extrait l'identité.

Le serveur a besoin d'une clé de compte de service Firebase :
  Console Firebase → Paramètres du projet → Comptes de service →
  « Générer une nouvelle clé privée » → place le fichier ici sous le nom
  serviceAccountKey.json (NE PAS le mettre sur GitHub).

Si la clé est absente, l'authentification Firebase est simplement désactivée
et le reste de la plateforme continue de fonctionner normalement.
"""

import os  # Accès au système de fichiers pour localiser la clé Firebase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Racine du projet (dossier momoguard/)
CRED_PATH = os.path.join(ROOT, "serviceAccountKey.json")  # Chemin complet vers la clé de service
_initialized = False  # Indique si le SDK Firebase a déjà été initialisé


def init_firebase(cred_path=CRED_PATH):
    """Initialise le SDK si la clé existe. Renvoie True si prêt."""
    global _initialized  # Permet de modifier la variable module _initialized
    if _initialized:  # Déjà prêt : évite une double initialisation
        return True
    if not os.path.exists(cred_path):  # Pas de clé → Firebase reste désactivé
        return False
    try:
        import firebase_admin  # SDK admin Firebase (import différé pour accélérer le démarrage)
        from firebase_admin import credentials  # Chargement des identifiants de service
        cred = credentials.Certificate(cred_path)  # Lit le fichier JSON de clé privée
        firebase_admin.initialize_app(cred)  # Enregistre l'application Firebase côté serveur
        _initialized = True  # Marque le module comme prêt
        return True
    except Exception as e:  # Clé invalide, fichier corrompu, etc.
        print(f"[Firebase] initialisation impossible : {e}")  # Log d'erreur non bloquant
        return False


def is_ready():
    """Vrai si Firebase a été initialisé avec succès."""
    return _initialized  # Utilisé par les routes API pour renvoyer 503 si absent


def verify_id_token(id_token):
    """Vérifie un ID token Firebase et renvoie le dict décodé (uid, email, name).

    Lève une exception si le jeton est invalide ou expiré.
    """
    from firebase_admin import auth  # Module d'authentification Firebase
    return auth.verify_id_token(id_token)  # Valide la signature et l'expiration du jeton


def send_push(fcm_token, title, body):
    """Envoie une notification push à un appareil via Firebase Cloud Messaging.

    Renvoie True si l'envoi a réussi. Ne lève jamais : en cas d'échec, log + False.
    """
    if not _initialized or not fcm_token:  # Prérequis : Firebase actif + jeton FCM du téléphone
        return False
    try:
        from firebase_admin import messaging  # Module de notifications push
        message = messaging.Message(  # Construit le message à envoyer
            notification=messaging.Notification(title=title, body=body),  # Titre et corps visibles
            token=fcm_token,  # Destinataire : jeton unique de l'appareil
        )
        messaging.send(message)  # Envoi effectif via les serveurs Google
        return True
    except Exception as e:  # Jeton expiré, app désinstallée, réseau, etc.
        print(f"[Firebase] push échoué : {e}")
        return False


def update_user_password(uid, new_password):
    """Met à jour le mot de passe d'un utilisateur Firebase (côté admin).

    Renvoie True si réussi. Lève une exception si Firebase n'est pas prêt ou en
    cas d'erreur (gérée par l'appelant).
    """
    if not _initialized:  # Impossible sans clé de service
        raise RuntimeError("Firebase non configuré")
    from firebase_admin import auth
    auth.update_user(uid, password=new_password)  # Modifie le compte Firebase de l'utilisateur
    return True
