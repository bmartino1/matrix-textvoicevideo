.PHONY: help setup up down restart logs status users backup clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Run initial setup (interactive)
	@echo "Usage: sudo ./setup.sh --domain chat.example.com"
	@echo "  Add --no-tls for LAN-only mode"

up: ## Start all services
	docker compose up -d

down: ## Stop all services
	docker compose down

restart: ## Restart all services
	docker compose restart

logs: ## Tail logs from all services
	docker compose logs -f --tail=50

logs-synapse: ## Tail Synapse logs only
	docker compose logs -f --tail=100 synapse

status: ## Check service health
	./scripts/status.sh

user: ## Create a user (usage: make user NAME=alice)
	./scripts/create-user.sh $(NAME)

admin: ## Create an admin user (usage: make admin NAME=admin)
	./scripts/create-user.sh $(NAME) --admin

backup: ## Create full backup
	./scripts/backup.sh

clean: ## Stop services and remove containers (keeps data)
	docker compose down --remove-orphans

nuke: ## DANGER: Remove everything including data
	docker compose down -v --remove-orphans
	@echo "Data directory preserved. Run 'rm -rf data/' manually if needed."

update: ## Pull latest images and restart
	docker compose pull
	docker compose up -d
