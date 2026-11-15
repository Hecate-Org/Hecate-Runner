# Hecate Background Services & Daemon Architecture

This guide advises developers and operators on the background system services available in Hecate, their security roles, and how to set them up.

---

## 1. Do You Need Background Services?

Hecate supports two primary operating modes:

* **Interactive Development (No Services Needed):**
  If you are developing rules, testing CLI commands (`hecate-agent`, `hecate-runner run`), running unit tests, or exploring hunts locally, you do **not** need systemd services. Use a standard virtual environment with `uv` as described in [`docs/ONBOARDING.md`](ONBOARDING.md).

* **Autonomous Node (Background Services Required):**
  If you want 24/7 continuous cyber threat intelligence (CTI) intake, automated hypothesis generation, scheduled SIEM sweeps, continuous Purple Team replay verification, or Slack alerting, you should deploy the systemd background services.

---

## 2. Service Catalog

| Service Unit | Tier | Purpose | Dedicated User | Env File |
| :--- | :---: | :--- | :--- | :--- |
| **`hecate-runner-daemon`** | **Required** | Continuous CTI intake (GitHub PoCs, MISP, RSS), hypothesis generation, automated hunt execution, and continuous Purple Team verification. | `hecate-reader` | `/etc/hecate/reader.env` |
| **`hecate-runner-maintenance`** | **Recommended** | Queue draining, cooldown management, automated artifact retention, and scheduled downstream publishing (MISP/GitHub/Splunk). | `hecate-writer` | `/etc/hecate/writer.env` |
| **`hecate-slack-bot`** | **Optional** | Real-time intake & BAS alerts, draft approval notifications, and interactive Slack slash commands. *(Skip if not using Slack).* | `hecate-slack` | `/etc/hecate/slack.env` |
| **`hecate-bas-broker`** | **Optional** | Unix domain socket proxy (`/run/hecate-bas/broker.sock`) for containerized adversary emulation (Atomic Red Team / CALDERA). *(Skip if only executing SIEM query verification).* | `root` / `docker` | *None (supervises socket ACL)* |

---

## 3. Quickstart: Setting Up Services

We provide a streamlined setup script that auto-detects your repository paths, builds the isolated runtime, sets up dedicated non-login system accounts, and installs the hardened systemd units:

```bash
# From the Hecate-Runner root directory:
./scripts/setup-services.sh
```

### Script Options
```bash
./scripts/setup-services.sh \
  --core /path/to/Hecate-Core \
  --workspace /path/to/Hecate-Public \
  --env-dir /etc/hecate \
  --docker-socket /var/run/docker.sock \
  --check    # Dry-run validation only
```

---

## 4. Role Isolation & Environment Files

For security, background services run under unprivileged, non-login system accounts with dedicated credential files in `/etc/hecate/` (permissions `0640`, owner `root:hecate-<role>`):

* **`reader.env` (`hecate-reader`):**
  Read-only permissions. Contains CTI API keys, LLM/model endpoint tokens, and `SPLUNK_READ_TOKEN`.
  > [!CAUTION]
  > Never put publishing keys (`SPLUNK_WRITE_TOKEN`, GitHub App private keys, or Slack app tokens) into `reader.env`.

* **`writer.env` (`hecate-writer`):**
  Publishing permissions. Contains `SPLUNK_WRITE_TOKEN`, GitHub App private key paths, and MISP export keys.

* **`slack.env` (`hecate-slack`):**
  Slack integration tokens (`SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`).

Starter templates are located in [`deploy/service-env/`](../deploy/service-env/).

---

## 5. Operations Cheatsheet

### Check Status
```bash
systemctl status hecate-runner-daemon.service hecate-runner-maintenance.service hecate-slack-bot.service hecate-bas-broker.service
```

### View Live Logs
```bash
# Daemon orchestrator logs
journalctl -u hecate-runner-daemon.service -f

# Maintenance / publisher logs
journalctl -u hecate-runner-maintenance.service -f
```

### Updating Runtime After Code Changes
Production services run against an immutable, standalone runtime in `/opt/hecate/runtime`. When code changes are pulled into `Hecate-Core` or `Hecate-Runner`, do **not** use `pip install`. Use the atomic runtime updater:

```bash
# 1. Build a new runtime stage as an ordinary user:
scripts/prepare-service-runtime.sh ../Hecate-Core /tmp/hecate-runtime-stage

# 2. Hot-swap the runtime transactionally with automatic rollback support:
sudo python3 scripts/update-service-runtime.py --runtime-stage /tmp/hecate-runtime-stage

# 3. Clean up the stage directory:
rm -rf /tmp/hecate-runtime-stage
```
Snapshots of prior runtimes are saved in `/var/backups/hecate-service-isolation/`.
