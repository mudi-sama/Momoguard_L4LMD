"""Sauvegarde portable de la base (toutes tables -> JSON horodaté).

Fonctionne quel que soit le moteur (SQLite, MySQL, PostgreSQL).
Usage : python scripts/backup_db.py
"""
import os, sys, json, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import database

def main():
    database.init_db()
    os.makedirs("backups", exist_ok=True)
    dump = {}
    with database.engine.connect() as conn:
        for table in database.md.sorted_tables:
            rows = conn.execute(database.select(table)).mappings().all()
            dump[table.name] = [dict(r) for r in rows]
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("backups", f"momoguard_backup_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(dump, f, ensure_ascii=False, indent=2, default=str)
    total = sum(len(v) for v in dump.values())
    print(f"Sauvegarde écrite : {path} ({total} lignes)")

if __name__ == "__main__":
    main()
