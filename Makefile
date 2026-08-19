.PHONY: up down build logs ps
up:
	docker compose up --build -d
build:
	docker compose build
down:
	docker compose down -v
logs:
	docker compose logs -f
ps:
	docker compose ps
