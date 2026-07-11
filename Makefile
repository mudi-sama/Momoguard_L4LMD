.PHONY: install run test seed backup

install:
	pip install -r requirements.txt

run:
	python run.py

test:
	pytest -q

seed:
	python scripts/seed_demo.py

backup:
	python scripts/backup_db.py
