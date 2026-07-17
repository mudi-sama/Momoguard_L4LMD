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

# Données persistantes (SQLite) : monter un volume Dokploy sur /app/data
RUN mkdir -p /app/data

# Firebase : fournir FIREBASE_CREDENTIALS_BASE64 dans l'environnement Dokploy
# (ne jamais copier serviceAccountKey.json dans l'image).

ENV MOMOGUARD_ENV=production \
    MOMOGUARD_HOST=0.0.0.0 \
    MOMOGUARD_PORT=5000 \
    MOMOGUARD_HTTPS=1 \
    MOMOGUARD_DATA_DIR=/app/data \
    PYTHONUNBUFFERED=1

EXPOSE 5000
VOLUME ["/app/data"]

# Démarre via SocketIO (threading) — compatible WebSocket dashboard + API /report.
CMD ["python", "-c", "from server.app import main; main()"]
