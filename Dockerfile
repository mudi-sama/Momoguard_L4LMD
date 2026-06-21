# Image du serveur central MoMoGuard
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Démarre le serveur Flask + SocketIO (écoute sur 0.0.0.0:5000)
CMD ["python", "app.py"]
