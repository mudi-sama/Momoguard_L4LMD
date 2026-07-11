"""Sauvegarde portable de la base (toutes tables -> JSON horodaté).

Fonctionne quel que soit le moteur (SQLite, MySQL, PostgreSQL).
Usage : python scripts/backup_db.py
"""
import os, sys, json, datetime  # os/sys : chemins ; json : sérialisation ; datetime : horodatage fichier
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # Racine projet pour importer server
from server import database  # Accès au moteur SQLAlchemy et aux métadonnées des tables

def main():
    database.init_db()  # S'assure que la base et les tables existent
    os.makedirs("backups", exist_ok=True)  # Crée le dossier de sauvegarde s'il manque
    dump = {}  # Dictionnaire {nom_table: [lignes]} à exporter
    with database.engine.connect() as conn:  # Connexion lecture seule au moteur SQL
        for table in database.md.sorted_tables:  # Parcourt toutes les tables dans l'ordre des dépendances
            rows = conn.execute(database.select(table)).mappings().all()  # Récupère toutes les lignes en dict-like
            dump[table.name] = [dict(r) for r in rows]  # Convertit chaque ligne en dict Python sérialisable
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")  # Horodatage pour nom de fichier unique
    path = os.path.join("backups", f"momoguard_backup_{ts}.json")  # Chemin complet du fichier de sortie
    with open(path, "w", encoding="utf-8") as f:  # Ouvre le fichier JSON en écriture UTF-8
        json.dump(dump, f, ensure_ascii=False, indent=2, default=str)  # Écrit le dump formaté (dates en str)
    total = sum(len(v) for v in dump.values())  # Nombre total de lignes sauvegardées
    print(f"Sauvegarde écrite : {path} ({total} lignes)")  # Résumé en console

if __name__ == "__main__":  # Point d'entrée script
    main()  # Lance la sauvegarde
