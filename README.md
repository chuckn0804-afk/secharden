# secharden

Security hardening audit tool for Windows / WSL2 environments.

`secharden` scans your local machine and reports actionable findings across five security domains: network exposure, credential hygiene, filesystem permissions, SSH configuration, and WSL2-specific risks. Findings are ranked by severity and exported as Markdown, plaintext table, or JSON.

## Features

- **Network module** — detects dangerous services bound to `0.0.0.0` (Redis, Postgres, Docker, MQTT, Elasticsearch, Prometheus, and more)
- **Credentials module** — flags sensitive env vars exposed in the shell, loose permissions on `.env` files, and unencrypted AWS credential files
- **Filesystem module** — checks SSH private key permissions, PAI config files, and world-readable secrets
- **SSH module** — audits `authorized_keys` entries and `PermitRootLogin` state
- **WSL module** — detects systemd config and verifies the Windows Firewall is enabled on all profiles

## Requirements

- [Bun](https://bun.sh) ≥ 1.0
- WSL2 (Ubuntu 22.04+) or native Linux
- PowerShell (`powershell.exe`) available for WSL firewall check (optional)

## Installation

```bash
git clone https://github.com/chuckn0804-afk/secharden.git
cd secharden
bun install
```

## Usage

```bash
# Full audit — all modules, Markdown report saved to reports/
bun run audit

# Specific module
bun run audit -- --module network

# Filter by minimum severity (critical | high | medium | low | info)
bun run audit -- --severity high

# Output formats
bun run audit -- --format markdown   # default — saves to reports/
bun run audit -- --format table      # console table only
bun run audit -- --format json       # machine-readable JSON
```

### Combining flags

```bash
bun run audit -- --module network --severity high --format json
```

## Output

Markdown reports are saved to `reports/YYYY-MM-DD-audit.md`. The `reports/` directory is git-ignored.

Sample finding:

```
### 🔴 CRITICAL — NET-001: redis bound to 0.0.0.0:6379
**Module:** network
**Detail:** Redis (0.0.0.0:6379) is exposed on all interfaces with no authentication required.
**Remediation:** Bind to 127.0.0.1 in /etc/redis/redis.conf: bind 127.0.0.1
```

## Modules

| ID prefix | Module | What it checks |
|-----------|--------|----------------|
| `NET-*` | network | Open ports bound to 0.0.0.0 |
| `CRED-*` | credentials | Env var secrets, .env permissions |
| `FS-*` | filesystem | SSH key + config file permissions |
| `SSH-*` | ssh | authorized_keys, PermitRootLogin |
| `WSL-*` | wsl | systemd, Windows Firewall profiles |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
