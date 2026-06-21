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

import os

CRED_PATH = "serviceAccountKey.json"
_initialized = False


def init_firebase(cred_path=CRED_PATH):
    """Initialise le SDK si la clé existe. Renvoie True si prêt."""
    global _initialized
    if _initialized:
        return True
    if not os.path.exists(cred_path):
        return False
    try:
        import firebase_admin
        from firebase_admin import credentials
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        _initialized = True
        return True
    except Exception as e:
        print(f"[Firebase] initialisation impossible : {e}")
        return False


def is_ready():
    return _initialized


def verify_id_token(id_token):
    """Vérifie un ID token Firebase et renvoie le dict décodé (uid, email, name).

    Lève une exception si le jeton est invalide ou expiré.
    """
    from firebase_admin import auth
    return auth.verify_id_token(id_token)


def send_push(fcm_token, title, body):
    """Envoie une notification push à un appareil via Firebase Cloud Messaging.

    Renvoie True si l'envoi a réussi. Ne lève jamais : en cas d'échec, log + False.
    """
    if not _initialized or not fcm_token:
        return False
    try:
        from firebase_admin import messaging
        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body),
            token=fcm_token,
        )
        messaging.send(message)
        return True
    except Exception as e:
        print(f"[Firebase] push échoué : {e}")
        return False


def update_user_password(uid, new_password):
    """Met à jour le mot de passe d'un utilisateur Firebase (côté admin).

    Renvoie True si réussi. Lève une exception si Firebase n'est pas prêt ou en
    cas d'erreur (gérée par l'appelant).
    """
    if not _initialized:
        raise RuntimeError("Firebase non configuré")
    from firebase_admin import auth
    auth.update_user(uid, password=new_password)
    return True
