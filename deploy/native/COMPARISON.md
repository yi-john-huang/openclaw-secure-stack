# Docker vs Native Deployment Comparison

This document helps you choose between Docker Compose and native systemd deployment for OpenClaw Secure Stack.

## Quick Decision Guide

**Use Docker Compose if:**
- ✅ Your system supports Docker Desktop or Podman
- ✅ You want maximum portability (works on macOS, Windows, Linux)
- ✅ You prefer container isolation for security
- ✅ You want DNS egress filtering (CoreDNS allowlist)
- ✅ You're comfortable with Docker tooling

**Use Native Deployment if:**
- ✅ Your system cannot run Docker Desktop (e.g., 2010 Mac Mini)
- ✅ You're on Ubuntu 24.04 LTS (headless server)
- ✅ You want to eliminate Docker daemon overhead (~200MB RAM)
- ✅ You prefer systemd for service management
- ✅ You want direct system integration and monitoring

---

## Detailed Comparison

### System Requirements

| Aspect | Docker Compose | Native (systemd) |
|--------|----------------|------------------|
| **OS Compatibility** | macOS, Windows, Linux | Ubuntu 24.04 LTS only |
| **Prerequisites** | Docker >= 20.10, Docker Compose >= 2.0 | Ubuntu 24.04, root access, internet |
| **RAM Overhead** | ~200MB (Docker daemon) | None (native processes) |
| **Disk Space** | ~1GB (Docker images + layers) | ~500MB (direct installs) |
| **Installation Time** | 5-10 minutes | 10-15 minutes |

### Installation & Setup

| Aspect | Docker Compose | Native (systemd) |
|--------|----------------|------------------|
| **Installer** | `./install.sh` | `deploy/native/install-native.sh` |
| **Interactive Prompts** | LLM auth, webhooks | LLM auth, webhooks, domain/localhost, HDD mount |
| **Onboarding** | Docker volume-based | Native filesystem (`/var/lib/openclaw`) |
| **Auto-start on Boot** | `docker compose up -d` | systemd units enabled |
| **Package Management** | Docker images (pulled) | APT + npm + uv (local builds) |

### Service Management

| Task | Docker Compose | Native (systemd) |
|------|----------------|------------------|
| **Start services** | `docker compose up -d` | `systemctl start openclaw openclaw-proxy caddy` |
| **Stop services** | `docker compose down` | `systemctl stop openclaw openclaw-proxy caddy` |
| **Restart services** | `docker compose restart` | `systemctl restart openclaw openclaw-proxy` |
| **View logs** | `docker compose logs -f <service>` | `journalctl -u <service> -f` |
| **Service status** | `docker compose ps` | `systemctl status openclaw openclaw-proxy caddy` |
| **Health check** | `docker compose ps` | `/usr/local/bin/openclaw-health-check` |
| **Auto-restart** | Docker's restart policy | systemd `Restart=on-failure` |

### Network Architecture

| Aspect | Docker Compose | Native (systemd) |
|--------|----------------|------------------|
| **Proxy access** | Docker network `internal` (172.28.0.0/16) | Localhost (127.0.0.1:8080) |
| **OpenClaw access** | Docker network `internal` | Localhost (127.0.0.1:3000) |
| **External access** | Caddy :8443 (configurable) | Caddy :443 |
| **Network isolation** | Docker bridge networks (strong) | Localhost binding + UFW (moderate) |
| **DNS filtering** | CoreDNS container (egress allowlist) | None (unrestricted outbound) |
| **Firewall** | Docker iptables rules | UFW (allow SSH/80/443, deny rest) |

### Security Isolation

| Feature | Docker Compose | Native (systemd) |
|---------|----------------|------------------|
| **Process isolation** | Linux namespaces (PID, net, mount) | Dedicated system users (no namespaces) |
| **Filesystem isolation** | Read-only containers + tmpfs | systemd `ProtectSystem=strict` |
| **Capability dropping** | `cap_drop: ALL` (Docker) | Default (no caps granted) |
| **No new privileges** | `security_opt: no-new-privileges` | systemd `NoNewPrivileges=yes` |
| **User isolation** | UID 65534 (nobody) inside container | Dedicated `openclaw` / `ocproxy` users |
| **Memory limits** | Docker `mem_limit` | systemd `MemoryMax` |
| **Outbound filtering** | CoreDNS DNS allowlist | None (relies on prompt-guard + governance) |
| **Attack surface** | Container escape vulnerabilities | Direct system access within sandbox |

**Security verdict:**
- **Docker** provides stronger isolation (namespaces, cgroups, DNS filtering)
- **Native** relies on systemd sandboxing + firewall + prompt-guard plugin
- Both are production-ready, but Docker has defense-in-depth advantages

### Storage & Data

| Aspect | Docker Compose | Native (systemd) |
|--------|----------------|------------------|
| **OpenClaw data** | Docker volume `.local-volumes/openclaw-data` | `/var/lib/openclaw/.openclaw` |
| **Proxy databases** | Docker volume `.local-volumes/proxy-data` | `/var/lib/openclaw-proxy/*.db` |
| **Audit logs** | Docker volume `.local-volumes/proxy-data` | `/mnt/data/openclaw-audit/audit.jsonl` |
| **Backups** | Manual copy of `.local-volumes/` | Daily cron → `/mnt/data/backups/` |
| **Config files** | Mounted read-only into containers | Direct read from `/opt/openclaw-secure-stack/config` |
| **Environment vars** | `.env` file (Compose reads) | `/etc/openclaw-secure-stack/*.env` (systemd reads) |

### Operations & Monitoring

| Task | Docker Compose | Native (systemd) |
|------|----------------|------------------|
| **Update proxy code** | `git pull && docker compose build && up -d` | `cd /opt/openclaw-secure-stack && git pull && systemctl restart openclaw-proxy` |
| **Update OpenClaw** | Change `OPENCLAW_IMAGE` in `.env` → restart | `cd /opt/openclaw && git pull && npm ci && systemctl restart openclaw` |
| **Backup automation** | Manual (cron + script) | Built-in (`/etc/cron.daily/openclaw-backup`) |
| **Health monitoring** | `docker compose ps` | `/usr/local/bin/openclaw-health-check` |
| **Log rotation** | Docker driver (json-file, max-size) | systemd journald + Python RotatingFileHandler |
| **Resource usage** | `docker stats` | `systemctl show -p MemoryCurrent <service>` |
| **Uninstallation** | `docker compose down -v` | `/opt/openclaw-secure-stack/deploy/native/uninstall.sh` |

### Resource Consumption (8GB RAM System)

| Component | Docker Compose | Native (systemd) |
|-----------|----------------|------------------|
| **Docker daemon** | ~200MB | N/A |
| **OpenClaw** | ~2GB (container + app) | ~3GB (direct process, MemoryMax) |
| **Proxy** | ~1.5GB (container + app) | ~2GB (direct process, MemoryMax) |
| **Caddy** | ~50MB | ~50MB |
| **CoreDNS** | ~20MB | N/A |
| **Total overhead** | ~3.8GB + daemon | ~5.05GB |
| **Available for OS** | ~4GB | ~2.95GB |

**Performance verdict:**
- Docker adds ~200MB daemon overhead
- Native services have higher `MemoryMax` (no container overhead to account for)
- Docker's layer caching speeds up rebuilds
- Native has faster startup (no image pull/extract)

### Development & Debugging

| Task | Docker Compose | Native (systemd) |
|------|----------------|------------------|
| **Local testing** | `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` | Edit systemd units, reload daemon |
| **Access OpenClaw directly** | Override `ports` in `docker-compose.override.yml` | Already on localhost (use UFW to restrict) |
| **Attach debugger** | `docker exec -it <container> /bin/sh` | Direct process access (e.g., `sudo -u openclaw`) |
| **Hot reload** | Volumes map to local code | Direct filesystem access |
| **Test changes** | Rebuild image | Restart service |

### Portability & Migration

| Aspect | Docker Compose | Native (systemd) |
|--------|----------------|------------------|
| **Cross-platform** | Yes (macOS, Windows, Linux) | No (Ubuntu 24.04 only) |
| **Export/import** | Docker images (tar) | System-specific (manual migration) |
| **Version pinning** | Image tags + digest pinning | Git tags + package versions |
| **CI/CD integration** | Excellent (Docker in Docker) | Moderate (Ansible, systemd units) |
| **Cloud deployment** | Easy (ECS, Kubernetes, Cloud Run) | Manual (VMs + provisioning) |

### Troubleshooting

| Issue | Docker Compose | Native (systemd) |
|-------|----------------|------------------|
| **Service won't start** | `docker compose logs <service>` | `journalctl -u <service> -n 100` |
| **Network issues** | Check `docker network ls`, inspect bridge | Check `ss -tlnp`, UFW rules |
| **Permission errors** | Volume mount UID mismatch | `chown` / `chmod` on `/var/lib/` |
| **Out of memory** | Adjust `mem_limit` in `docker-compose.yml` | Adjust `MemoryMax` in `*.service` |
| **Disk full** | `docker system prune` | Clean `/mnt/data/backups/`, audit logs |
| **Port conflicts** | Change `PROXY_PORT` / `CADDY_PORT` in `.env` | Edit systemd `ExecStart` (host/port) |

### Maintenance

| Task | Docker Compose | Native (systemd) |
|------|----------------|------------------|
| **Security updates** | Rebuild images monthly | `apt update && apt upgrade`, rebuild Node/Python |
| **Base image CVEs** | Update Dockerfile digest, rebuild | Update system packages |
| **Dependency updates** | `uv lock --upgrade` + rebuild | `uv sync --upgrade` + restart |
| **Config changes** | Edit files in `config/`, restart | Same, restart systemd units |
| **Certificate renewal** | Caddy auto-renews (Let's Encrypt) | Caddy auto-renews (Let's Encrypt) |

---

## Pros & Cons Summary

### Docker Compose

**Pros:**
- ✅ **Strongest security:** Network namespaces, DNS filtering, container isolation
- ✅ **Cross-platform:** Works on macOS, Windows, Linux
- ✅ **Portability:** Easy to export/import, deploy to cloud
- ✅ **Ecosystem:** Docker Hub, pre-built images, CI/CD integrations
- ✅ **Proven:** Industry-standard container orchestration

**Cons:**
- ❌ **Resource overhead:** Docker daemon consumes ~200MB RAM
- ❌ **Complexity:** Requires understanding Docker concepts (images, volumes, networks)
- ❌ **Hardware requirements:** Older systems may not support Docker Desktop
- ❌ **Image management:** Need to rebuild/pull images for updates

### Native (systemd)

**Pros:**
- ✅ **No Docker required:** Works on systems without Docker Desktop
- ✅ **Resource efficient:** No daemon overhead, direct process execution
- ✅ **System integration:** Native systemd units, journald logging, UFW firewall
- ✅ **Transparency:** Direct filesystem access, easier debugging
- ✅ **Operational simplicity:** Standard Linux service management

**Cons:**
- ❌ **OS-specific:** Ubuntu 24.04 LTS only (not portable)
- ❌ **Weaker isolation:** No network namespaces, no DNS filtering
- ❌ **Manual dependency management:** Must install Node.js, Python, Caddy via APT/npm/uv
- ❌ **Migration complexity:** Harder to move to another server or cloud

---

## Migration Path

### Docker → Native

1. **Backup Docker data:**
   ```bash
   docker compose down
   cp -r .local-volumes/openclaw-data /tmp/openclaw-backup
   cp -r .local-volumes/proxy-data /tmp/proxy-backup
   ```

2. **Run native installer on Ubuntu 24.04:**
   ```bash
   sudo bash deploy/native/install-native.sh
   ```

3. **Restore data:**
   ```bash
   sudo systemctl stop openclaw openclaw-proxy
   sudo cp -r /tmp/openclaw-backup/.openclaw/* /var/lib/openclaw/.openclaw/
   sudo cp /tmp/proxy-backup/*.db /var/lib/openclaw-proxy/
   sudo chown -R openclaw:openclaw /var/lib/openclaw
   sudo chown -R ocproxy:ocproxy /var/lib/openclaw-proxy
   sudo systemctl start openclaw openclaw-proxy
   ```

### Native → Docker

1. **Backup native data:**
   ```bash
   sudo systemctl stop openclaw openclaw-proxy
   sudo cp -r /var/lib/openclaw/.openclaw /tmp/openclaw-backup
   sudo cp /var/lib/openclaw-proxy/*.db /tmp/proxy-backup/
   ```

2. **Run Docker installer:**
   ```bash
   ./install.sh
   docker compose down
   ```

3. **Restore data:**
   ```bash
   mkdir -p .local-volumes/{openclaw-data,proxy-data}
   cp -r /tmp/openclaw-backup/* .local-volumes/openclaw-data/
   cp /tmp/proxy-backup/*.db .local-volumes/proxy-data/
   docker compose up -d
   ```

---

## Recommendation Matrix

| Use Case | Recommended Deployment |
|----------|------------------------|
| **Production server (cloud VM)** | Docker (portability, CI/CD) |
| **Production server (bare metal, modern)** | Docker (stronger isolation) |
| **Production server (bare metal, legacy)** | Native (hardware constraints) |
| **Home lab / self-hosted** | Docker (ease of use) |
| **Old Mac Mini / constrained hardware** | Native (no Docker support) |
| **Development (macOS/Windows)** | Docker (cross-platform) |
| **Development (Linux)** | Either (preference-based) |
| **Learning / experimentation** | Native (transparency) |
| **CI/CD pipeline** | Docker (containerized testing) |
| **Air-gapped environment** | Native (no image pull required) |

---

## Final Thoughts

**Choose Docker if you value:**
- Maximum security (network namespaces, DNS filtering)
- Portability across environments
- Ecosystem integration (Docker Hub, Kubernetes)

**Choose Native if you value:**
- Resource efficiency (no daemon overhead)
- Direct system integration (systemd, journald)
- Compatibility with legacy hardware

Both deployments run the **exact same security pipeline** (prompt-guard plugin, governance middleware, auth, audit). The difference is in orchestration and isolation layers, not the core security logic.

For most users, **Docker Compose is recommended** due to its stronger isolation and portability. Use native deployment when Docker is not an option or when resource constraints are critical.
