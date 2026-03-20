.PHONY: setup deploy test-attack logs status clean help

SHELL := /bin/bash
STACK_NAME := hardening-lab
APP_IMAGE := hardening-lab/app:1.0.0
STACK_FILE := deploy/stack.yml
DASHBOARD_URL := http://localhost:5000

SETUP_SCRIPT := scripts/setup.sh
ATTACK_SCRIPT := scripts/test-attack.sh

help:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║       Container Hardening & Monitoring Lab              ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  make setup        Inicializa Swarm + Secrets + Build"
	@echo "  make deploy       Deploya stack no Swarm"
	@echo "  make test-attack  Simula ataques (valida Falco)"
	@echo "  make logs         Mostra logs dos serviços"
	@echo "  make status       Exibe status do stack"
	@echo "  make clean        Remove tudo (stack, secrets, imagem)"
	@echo ""
	@echo "  Dashboard: $(DASHBOARD_URL)"
	@echo ""

setup:
	@chmod +x $(SETUP_SCRIPT)
	@bash $(SETUP_SCRIPT)

deploy:
	@echo "[INFO] Deployando stack '$(STACK_NAME)'..."
	docker stack deploy \
		--compose-file $(STACK_FILE) \
		$(STACK_NAME)
	@echo "[INFO] Stack deployado. Aguardando convergência..."
	@sleep 8
	@docker stack services $(STACK_NAME)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║  Dashboard disponível em: $(DASHBOARD_URL)        ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "[INFO] Use 'make status' para verificar saúde dos containers."
	@echo "[INFO] Use 'make logs' para acompanhar logs em tempo real."

test-attack:
	@chmod +x $(ATTACK_SCRIPT)
	@bash $(ATTACK_SCRIPT)

logs:
	@echo "[INFO] Logs do serviço app:"
	@docker service logs $(STACK_NAME)_app --tail 50 --follow 2>/dev/null &
	@echo "[INFO] Logs do serviço falco:"
	@docker service logs $(STACK_NAME)_falco --tail 50 --follow 2>/dev/null &
	@wait

status:
	@echo ""
	@echo "=== Serviços do Stack ==="
	@docker stack services $(STACK_NAME) 2>/dev/null || echo "Stack não encontrado."
	@echo ""
	@echo "=== Containers em execução ==="
	@docker ps --filter "label=com.docker.stack.namespace=$(STACK_NAME)" \
		--format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null
	@echo ""
	@echo "=== Secrets ==="
	@docker secret ls 2>/dev/null
	@echo ""

clean:
	@echo "[INFO] Removendo stack '$(STACK_NAME)'..."
	-@docker stack rm $(STACK_NAME) 2>/dev/null
	@echo "[INFO] Aguardando containers encerrarem..."
	@sleep 10
	@echo "[INFO] Removendo secret 'db_password'..."
	-@docker secret rm db_password 2>/dev/null
	@echo "[INFO] Removendo volumes do Falco..."
	-@docker volume rm falco-rules falco-config 2>/dev/null
	@echo "[INFO] Removendo imagem '$(APP_IMAGE)'..."
	-@docker rmi $(APP_IMAGE) 2>/dev/null
	@echo "[INFO] Cleanup concluído."
	@echo "[INFO] Para desativar o Swarm: docker swarm leave --force"
