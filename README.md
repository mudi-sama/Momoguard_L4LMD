# MoMoGuard — plateforme de détection de fraude Mobile Money

MoMoGuard est une plateforme **consentie** de détection de fraude Mobile Money
(Orange Money, Airtel Money, Vodacom M-Pesa, Africell). Des agents installés sur
les **propres appareils** de l'utilisateur (avec son consentement explicite)
analysent les SMS, liens et codes suspects, les notent via un moteur de scoring
**explicable**, et remontent les alertes à un serveur central avec tableau de
bord temps réel.

Projet de fin d'études L4 — axe **sécurité des utilisateurs (humains)** :
phishing, smishing, ingénierie sociale.

## Architecture

```
Agent Windows (Python) ─┐
                        ├─ POST /report ─→ Serveur Flask ─→ Base (PostgreSQL/MySQL/SQLite)
Agent Android (Kotlin) ─┘                      │
   • Firebase Auth                             ├─ WebSocket ─→ Dashboard (navigateur)
   • notifications FCM ←──────────────────────┘
```

## Composants

| Élément              | Rôle                                                       |
|----------------------|------------------------------------------------------------|
| `app.py`             | Serveur Flask + SocketIO (API + dashboard + backoffice)    |
| `database.py`        | Couche données SQLAlchemy (portable, une seule URL)        |
| `scoring.py`         | Moteur de scoring par règles, explicable                   |
| `firebase_auth.py`   | Vérification des jetons Firebase + envoi des push          |
| `templates/`, `static/` | Interface (dashboard, gestion, paramètres)              |
| `agents/`            | Agent Windows (Python)                                      |
| `tests/`             | Suite de tests `pytest`                                     |
| `scripts/`           | Automatisation (seed de démo, sauvegarde)                  |

## Installation (local)

```bash
python -m venv .venv
source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Dashboard : http://127.0.0.1:5000 — compte par défaut `admin` / `momoguard`
(à changer depuis la page **Compte**).

## Base de données (portable)

Le moteur se choisit via la variable d'environnement `MOMOGUARD_DB` :

```bash
# SQLite (défaut, développement)
export MOMOGUARD_DB="sqlite:///momoguard.db"

# PostgreSQL (recommandé en production)
export MOMOGUARD_DB="postgresql+psycopg2://momoguard:momoguard@127.0.0.1:5432/momoguard"

# MySQL / WAMP
export MOMOGUARD_DB="mysql+pymysql://root:@127.0.0.1:3306/momoguard"
```

Les tables sont créées automatiquement au démarrage ; les colonnes ajoutées au
fil des versions sont migrées en douceur, sans perte de données.

## Docker (serveur + PostgreSQL)

```bash
docker compose up --build
```

Démarre PostgreSQL et le serveur MoMoGuard relié à cette base. Dashboard sur
http://127.0.0.1:5000.

## Tests

```bash
pytest -q
```

Couvre le moteur de scoring, le contrôle d'adhésion sur `/report`, la gestion
des utilisateurs (IP, fiche, mot de passe + notification) et les paramètres.

## Scripts d'automatisation

```bash
python scripts/seed_demo.py     # insère un jeu de données de démonstration
python scripts/backup_db.py     # sauvegarde toutes les tables en JSON horodaté
```

Un `Makefile` regroupe les commandes : `make install`, `make run`, `make test`,
`make seed`, `make backup`, `make docker-up`, `make docker-down`.

## Firebase

Placer la clé de service `serviceAccountKey.json` à la racine pour activer
l'authentification client et les notifications push. **Ce fichier ne doit jamais
être committé** (il est exclu via `.gitignore`).
