.PHONY: up down restart logs status create-user backup ps

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose down && docker compose up -d

logs:
	docker compose logs -f --tail=100

status:
	./scripts/status.sh

create-user:
	@read -p "Username: " user; ./scripts/create-user.sh $$user

create-admin:
	@read -p "Username: " user; ./scripts/create-user.sh $$user --admin

backup:
	./scripts/backup.sh

ps:
	docker compose ps
