#!/usr/bin/env bash

set -euo pipefail

readonly STACK_NAME="hardening-lab"
readonly SERVICE_NAME="${STACK_NAME}_app"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_attack()  { echo -e "${RED}[ATTACK]${NC}  $*"; }
log_expect()  { echo -e "${CYAN}[EXPECT]${NC}  $*"; }
log_section() { echo -e "\n${YELLOW}━━━ $* ━━━${NC}\n"; }

get_container_id() {
    local container_id
    container_id="$(docker ps --filter "name=${SERVICE_NAME}" --format '{{.ID}}' | head -1)"

    if [[ -z "${container_id}" ]]; then
        echo -e "${RED}[ERROR]${NC} Nenhum container encontrado para '${SERVICE_NAME}'." >&2
        echo -e "${RED}[ERROR]${NC} Execute 'make deploy' antes de rodar os testes." >&2
        exit 1
    fi
    echo "${container_id}"
}

test_cat_secret() {
    log_section "Teste 1 — Leitura via cat"
    log_attack "Executando: cat /run/secrets/db_password"
    log_expect "Falco deve detectar: 'Unauthorized Access to Swarm Secrets' (CRITICAL)"

    docker exec "$1" cat /run/secrets/db_password 2>&1 || true
    echo ""
}

test_shell_spawn() {
    log_section "Teste 2 — Spawn de shell"
    log_attack "Executando: sh -c 'echo shell ativo'"
    log_expect "Falco deve detectar: 'Shell Spawned in Hardened Container' (WARNING)"

    docker exec "$1" sh -c "echo 'shell comprometido — isso nao deveria acontecer'" 2>&1 || true
    echo ""
}

test_ls_secrets() {
    log_section "Teste 3 — Listagem de /run/secrets/"
    log_attack "Executando: ls -la /run/secrets/"
    log_expect "Falco deve detectar acesso ao diretório de secrets"

    docker exec "$1" ls -la /run/secrets/ 2>&1 || true
    echo ""
}

test_copy_secret() {
    log_section "Teste 4 — Tentativa de exfiltração via cp"
    log_attack "Executando: cp /run/secrets/db_password /tmp/exfiltrado"
    log_expect "Falco deve detectar acesso ao secret + possível alerta de escrita"

    docker exec "$1" cp /run/secrets/db_password /tmp/exfiltrado 2>&1 || true
    echo ""
}

show_falco_logs() {
    log_section "Logs do Falco (últimos 30s)"
    log_info "Verificando se alertas foram gerados..."

    sleep 3

    local falco_container
    falco_container="$(docker ps --filter "name=${STACK_NAME}_falco" --format '{{.ID}}' | head -1)"

    if [[ -n "${falco_container}" ]]; then
        docker logs --since 30s "${falco_container}" 2>&1 | tail -50
    else
        log_info "Container do Falco não encontrado. Verifique 'docker service ls'."
        log_info "Os ataques simulados acima TERIAM acionado os alertas se o Falco estivesse ativo."
    fi
}

main() {
    echo -e "${YELLOW}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   Container Hardening Lab — Simulação de Ataques    ║"
    echo "║   ⚠  APENAS PARA AMBIENTE DE LABORATÓRIO            ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    local container_id
    container_id="$(get_container_id)"
    log_info "Container alvo: ${container_id}"

    test_cat_secret "${container_id}"
    test_shell_spawn "${container_id}"
    test_ls_secrets "${container_id}"
    test_copy_secret "${container_id}"
    show_falco_logs

    log_section "Resumo"
    log_info "4 testes de ataque executados."
    log_info "Verifique os logs do Falco acima para confirmar detecção."
    log_info "Em produção, esses alertas iriam para SIEM/Slack/PagerDuty."
}

main "$@"
