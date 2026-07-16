# Image de production MoMoGuard (Flask + SocketIO) pour Dokploy / Docker.
FROM python:3.12-slim

WORKDIR /app

# Dépendances système (psycopg2, certificats HTTPS)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# --root-user-action=ignore : normal dans Docker ; évite un faux "error" dans les logs Dokploy
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt

COPY . .

# Le fichier Firebase n'est PAS dans l'image : à monter en volume / secret Dokploy.
# Place serviceAccountKey.json à /app/serviceAccountKey.json au runtime.

ENV MOMOGUARD_ENV=production \
    MOMOGUARD_HOST=0.0.0.0 \
    MOMOGUARD_PORT=5000 \
    MOMOGUARD_HTTPS=1 \
    PYTHONUNBUFFERED=1

EXPOSE 5000

# Démarre via SocketIO (threading) — compatible WebSocket dashboard + API /report.
# MOMOGUARD_HOST=0.0.0.0 est déjà défini ci-dessus.
CMD ["python", "-c", "from server.app import main; main()"]
