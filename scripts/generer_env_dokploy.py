"""Génère le bloc Environment à coller dans Dokploy.

Usage (depuis la racine du projet) :
    python scripts/generer_env_dokploy.py

Lit serviceAccountKey.json local (jamais commité) et produit :
  - .env.dokploy.local  (ignoré par git) avec toutes les variables ;
  - un affichage console pour copier-coller dans Dokploy → Environment.
"""
import base64
import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_PATH = os.path.join(ROOT, "serviceAccountKey.json")
OUT_PATH = os.path.join(ROOT, ".env.dokploy.local")

# Domaine public de production (modifiable via argument)
domaine = sys.argv[1] if len(sys.argv) > 1 else "https://momoguardserv.com"
domaine = domaine.rstrip("/")

if not os.path.isfile(KEY_PATH):
    print(f"[!] Fichier introuvable : {KEY_PATH}")
    print("    Place serviceAccountKey.json à la racine du projet puis relance.")
    sys.exit(1)

with open(KEY_PATH, "rb") as f:
    b64 = base64.b64encode(f.read()).decode("ascii")

secret = secrets.token_hex(32)

lignes = [
    "MOMOGUARD_ENV=production",
    f"MOMOGUARD_SECRET={secret}",
    "MOMOGUARD_HOST=0.0.0.0",
    "MOMOGUARD_PORT=5000",
    "MOMOGUARD_HTTPS=1",
    "MOMOGUARD_DATA_DIR=/app/data",
    f"MOMOGUARD_CORS_ORIGINS={domaine}",
    f"FIREBASE_CREDENTIALS_BASE64={b64}",
    "# Optionnel — décommente si tu as une clé Google Safe Browsing :",
    "# SAFEBROWSING_API_KEY=ta_cle_api",
]

contenu = "\n".join(lignes) + "\n"
with open(OUT_PATH, "w", encoding="utf-8") as f:
    f.write(contenu)

print("=" * 60)
print(" Fichier généré : .env.dokploy.local  (NE PAS committer)")
print("=" * 60)
print()
print("Dans Dokploy > ton app > onglet Environment, COLLE ceci :")
print()
# Affiche sans tronquer la clé (nécessaire pour le copier-coller)
print(contenu)
print("=" * 60)
print("Ensuite :")
print("  1) Advanced > Volumes > ajoute un volume sur /app/data")
print("  2) Domains > port 5000 + HTTPS")
print("  3) Deploy")
print(f"  4) Teste {domaine}/health  (firebase: true)")
print("=" * 60)
