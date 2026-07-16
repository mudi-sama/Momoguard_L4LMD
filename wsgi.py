"""Point d'entrée WSGI / Docker pour MoMoGuard.

Utilisé par gunicorn (routes HTTP) et par le démarrage Docker.
Le dashboard temps réel (SocketIO) fonctionne via le mode threading
déjà configuré dans server.app.
"""
from server.app import app, socketio  # noqa: F401 — exportés pour gunicorn / Docker

# Alias attendu par certains reverse-proxies
application = app
