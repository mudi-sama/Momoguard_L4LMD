.PHONY: install run test seed backup docker-up docker-down

install:
	pip install -r requirements.txt

run:
	python app.py

test:
	pytest -q

seed:
	python scripts/seed_demo.py

backup:
	python scripts/backup_db.py

docker-up:
	docker compose up --build

docker-down:
	docker compose down
