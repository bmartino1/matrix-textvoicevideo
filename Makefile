.PHONY: up down restart logs status ps create-user create-admin backup list-users

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

ps:
	docker compose ps

create-user:
	@read -p "Username: " user; ./scripts/create-user.sh $$user

create-admin:
	@read -p "Username: " user; ./scripts/create-admin.sh $$user

backup:
	./scripts/backup.sh

list-users:
	@read -p "Admin access token: " tok; ./scripts/list-users.sh $$tok

reset-password:
	@read -p "Username: " user; read -p "Admin token: " tok; ./scripts/reset-password.sh $$user $$tok
