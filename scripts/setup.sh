#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly APP_IMAGE="hardening-lab/app:1.0.0"
readonly SECRET_NAME="db_password"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}\n"; }

check_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker não encontrado. Instale: https://docs.docker.com/engine/install/"
        exit 1
    fi
    log_info "Docker encontrado: $(docker --version)"
}

init_swarm() {
    if docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
        log_info "Swarm já está ativo."
    else
        log_info "Inicializando Docker Swarm..."
        docker swarm init --advertise-addr 127.0.0.1 || {
            log_error "Falha ao inicializar Swarm. Verifique se não há conflito de rede."
            exit 1
        }
        log_info "Swarm inicializado com sucesso."
    fi
}

create_secret() {
    if docker secret ls --format '{{.Name}}' | grep -q "^${SECRET_NAME}$"; then
        log_warn "Secret '${SECRET_NAME}' já existe. Pulando criação."
    else
        local password
        password="$(openssl rand -base64 32 | tr -d '=/+' | head -c 32)"

        echo -n "${password}" | docker secret create "${SECRET_NAME}" - || {
            log_error "Falha ao criar secret '${SECRET_NAME}'."
            exit 1
        }
        log_info "Secret '${SECRET_NAME}' criado com sucesso."
    fi
}

setup_falco_volumes() {
    log_info "Configurando volumes para o Falco..."

    docker volume create falco-rules 2>/dev/null || true
    docker volume create falco-config 2>/dev/null || true

    docker run --rm \
        -v falco-rules:/dest \
        -v "${PROJECT_ROOT}/configs/falco/rules.local.yaml:/src/rules.local.yaml:ro" \
        alpine:3.20 \
        sh -c "cp /src/rules.local.yaml /dest/rules.local.yaml"

    docker run --rm \
        -v falco-config:/dest \
        -v "${PROJECT_ROOT}/configs/falco/falco.yaml:/src/falco.yaml:ro" \
        alpine:3.20 \
        sh -c "cp /src/falco.yaml /dest/falco.yaml"

    log_info "Volumes do Falco configurados com sucesso."
}

build_image() {
    log_info "Buildando imagem '${APP_IMAGE}'..."
    docker build \
        --tag "${APP_IMAGE}" \
        --file "${PROJECT_ROOT}/Dockerfile" \
        "${PROJECT_ROOT}"

    log_info "Imagem '${APP_IMAGE}' buildada com sucesso."

    local size
    size="$(docker image inspect "${APP_IMAGE}" --format='{{.Size}}' | numfmt --to=iec 2>/dev/null || echo 'N/A')"
    log_info "Tamanho da imagem final: ${size}"
}

main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   Container Hardening Lab — Setup                   ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    log_step "1/5 — Verificando pré-requisitos"
    check_docker

    log_step "2/5 — Inicializando Docker Swarm"
    init_swarm

    log_step "3/5 — Criando Docker Secrets"
    create_secret

    log_step "4/5 — Configurando volumes do Falco"
    setup_falco_volumes

    log_step "5/5 — Buildando imagem da aplicação"
    build_image

    echo ""
    log_info "=== Setup concluído com sucesso! ==="
    echo ""
    echo -e "  Próximo passo: ${GREEN}make deploy${NC}"
    echo -e "  Dashboard:     ${CYAN}http://localhost:5000${NC}"
    echo ""
}

main "$@"
