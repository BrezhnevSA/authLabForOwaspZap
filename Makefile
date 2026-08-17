.PHONY: up kerberos-up kerberos-check dast-check down build logs ps
up:
	docker compose up --build -d
kerberos-up:
	docker compose --profile kerberos up --build -d
kerberos-check:
	docker compose --profile kerberos run --rm kerberos-client-check
dast-check:
	ACTION=check AUTH_MODE=protocol ./run-dast-scans.sh
build:
	docker compose build
down:
	docker compose down -v
logs:
	docker compose logs -f
ps:
	docker compose ps
