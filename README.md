# MoMoGuard — plateforme de détection de fraude Mobile Money

MoMoGuard est une plateforme **consentie** de détection de fraude Mobile Money
(Orange Money, Airtel Money, Vodacom M-Pesa, Africell). Des agents installés sur
les **propres appareils** de l'utilisateur (avec son consentement explicite)
analysent les SMS, liens et codes suspects, les notent via un moteur de scoring
**explicable**, et remontent les alertes à un serveur central avec tableau de
bord temps réel.

Projet de fin d'études L4 — axe **sécurité des utilisateurs (humains)** :
phishing, smishing, ingénierie sociale.

## Structure du projet

```
momoguard/
├── run.py                 # Lancer le serveur
├── requirements.txt
├── Makefile
│
├── server/                # Serveur central (Flask + API + dashboard)
│   ├── app.py             # Routes, auth admin, WebSocket
│   ├── database.py        # SQLAlchemy (SQLite / PostgreSQL / MySQL)
│   ├── scoring.py         # Moteur de détection par règles
│   ├── threat_intel.py    # Google Safe Browsing (optionnel)
│   ├── firebase_auth.py   # Auth mobile + notifications push
│   ├── templates/         # Pages HTML (dashboard, utilisateurs…)
│   └── static/            # CSS + JavaScript
│
├── agents/                # Clients installés sur les appareils
│   └── windows_agent.py   # Agent Windows (presse-papier, téléchargements)
│
├── scripts/               # Utilitaires
│   ├── seed_demo.py       # Données de démonstration
│   └── backup_db.py       # Sauvegarde JSON
│
├── tests/                 # Suite pytest
└── evaluation/            # Benchmark du moteur (métriques, dataset)
```

## Architecture

```
Agent Windows (Python) ─┐
                        ├─ POST /report ─→ Serveur Flask ─→ Base (PostgreSQL/MySQL/SQLite)
Agent Android (Kotlin) ─┘                      │
   • Firebase Auth                             ├─ WebSocket ─→ Dashboard (navigateur)
   • notifications FCM ←──────────────────────┘
```

## Installation (local)

```bash
python -m venv .venv
source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Dashboard : http://127.0.0.1:5000 — compte par défaut `admin` / `momoguard`
(à changer depuis la page **Compte**).

## Base de données (portable)

Le moteur se choisit via la variable d'environnement `MOMOGUARD_DB` :

```bash
# SQLite (défaut, développement — fichier momoguard.db à la racine)
export MOMOGUARD_DB="sqlite:///momoguard.db"

# PostgreSQL (recommandé en production)
export MOMOGUARD_DB="postgresql+psycopg2://momoguard:momoguard@127.0.0.1:5432/momoguard"

# MySQL / WAMP
export MOMOGUARD_DB="mysql+pymysql://root:@127.0.0.1:3306/momoguard"
```

Les tables sont créées automatiquement au démarrage ; les colonnes ajoutées au
fil des versions sont migrées en douceur, sans perte de données.

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
`make seed`, `make backup`.

## Firebase

Placer la clé de service `serviceAccountKey.json` à la racine pour activer
l'authentification client et les notifications push. **Ce fichier ne doit jamais
être committé** (il est exclu via `.gitignore`).

## Réputation d'URL (API externe, optionnelle)

Le moteur peut consulter **Google Safe Browsing** pour vérifier les liens des
messages. Active-la en définissant la clé :

```bash
export SAFEBROWSING_API_KEY="ta_cle_api"
```

Quand une URL est confirmée malveillante, l'alerte est automatiquement classée
**élevée**. Sans clé (ou hors ligne), cette vérification est simplement ignorée :
la détection par règles continue de fonctionner normalement.
