# Whaley — Dedicated Docker Instancer for CTF Competitions

Complete documentation for Whaley, the production-ready CTF challenge instancer.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Challenge Structure](#challenge-structure)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [Team Mode](#team-mode)
- [Admin Dashboard](#admin-dashboard)
- [Runtime Settings UI](#runtime-settings-ui)
- [Dynamic Flags & Anti-Cheat](#dynamic-flags--anti-cheat)
- [Challenge Manager](#challenge-manager)
- [Instance Forensics](#instance-forensics)
- [Resource Monitoring](#resource-monitoring)
- [Discord Notifications](#discord-notifications)
- [Production Infrastructure](#production-infrastructure)
- [Capacity Planning](#capacity-planning)
- [Security](#security)
- [Development](#development)
- [Environment Variables Reference](#environment-variables-reference)

---

## Prerequisites

- **Docker Engine 24.0+** with Docker Compose v2 plugin
- **Python 3.11+** (for local development only)
- A **Traefik** reverse proxy configured with Redis KV provider (for dynamic routing)
- A shared **Redis** instance reachable by both Whaley and Traefik
- Linux server (Ubuntu 22.04+ or Debian 12+ recommended)
- 4+ CPU cores, 8GB+ RAM (see [Capacity Planning](#capacity-planning))

### Infrastructure Model

```
                   ┌──────────────────────┐
                   │     Traefik (VM1)     │
                   │  Redis KV Provider    │
                   └──────────┬───────────┘
                              │ reads dynamic routes
                              ▼
                   ┌──────────────────────┐
                   │       Redis           │
                   └──────────▲───────────┘
                              │ writes routes
┌─────────────────┐    ┌─────┴─────────────┐
│   CTFd (VM3)    │    │  Whaley (VM2)     │
│   CTF Platform  │◄───│  Docker Instancer  │
└─────────────────┘    └────────────────────┘
                              │
                    ┌─────────┴──────────┐
                    ▼         ▼          ▼
               ┌────────┐ ┌────────┐ ┌────────┐
               │net-inst1│ │net-inst2│ │net-inst3│
               │[isolated]│ │[isolated]│ │[isolated]│
               └────────┘ └────────┘ └────────┘
```

- **Whaley (VM2):** Runs challenge containers, manages the Docker lifecycle, writes per-instance Traefik routes to Redis
- **Traefik (VM1):** Reads routes from Redis KV, terminates TLS, routes traffic to VM2 backend ports
- **CTFd (VM3):** The CTF platform; Whaley authenticates users against it and optionally manages dynamic flags

---

## Installation

### 1. Clone and Configure

```bash
git clone https://github.com/jonscafe/whaley.git
cd whaley
cp .env.example .env
nano .env
```

### 2. Essential Configuration

```env
# Authentication
AUTH_MODE=ctfd                              # "ctfd" or "none"
CTFD_URL=https://your-ctfd-instance.com
CTFD_API_KEY=ctfd_your_admin_api_key        # Required for dynamic flags + team mode detection

# Admin access
ADMIN_KEY=your_secure_admin_key             # Generate: openssl rand -hex 32
METRICS_SECRET=your_metrics_secret          # Bearer auth for /metrics endpoint

# Traefik routing
TRAEFIK_REDIS_URL=redis://redis:6379/0
TRAEFIK_BASE_DOMAIN=ctf.example
TRAEFIK_BACKEND_HOST=challenges-vm          # Hostname Traefik uses to reach VM2
TRAEFIK_TCP_EXTERNAL_PORT=5443              # Public TCP port for SNI routing

# Port range (backend bindings on VM2)
PORT_RANGE_START=20000
PORT_RANGE_END=50000

# Optional: Discord webhook for lifecycle notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/.../...
```

### 3. Add Challenges

Place challenge directories under `challenges/`:

```
challenges/
├── your-challenge/
│   ├── instance.toml          # Challenge metadata
│   ├── docker-compose.yaml    # Container definition (or .yml)
│   ├── Dockerfile
│   └── src/
│       └── app.py
```

### 4. Start

```bash
docker compose up -d
```

### Access Points

| Interface | URL | Description |
|---|---|---|
| **User Dashboard** | `http://your-server:8000/` | Challenge spawning interface (React SPA) |
| **Admin Panel** | `http://your-server:8000/admin` | Monitoring & management (React SPA) |
| **API Docs** | `http://your-server:8000/docs` | Swagger API documentation |
| **Health Check** | `http://your-server:8000/health` | Detailed health status |
| **Prometheus Metrics** | `http://your-server:8000/metrics` | Requires `Authorization: Bearer <METRICS_SECRET>` |

---

## Configuration

### Environment-File vs Runtime Settings

Whaley has two layers of configuration:

1. **Environment variables** (`.env` / `docker-compose.yaml`) — set at container startup, define the baseline
2. **Runtime settings** (database `whaley_settings` table) — can be changed via the Admin Settings UI, override environment values, persist across restarts

Most operational settings can be changed at runtime without editing files or restarting containers. See [Runtime Settings UI](#runtime-settings-ui).

### Key Configuration Categories

| Category | Key Variables |
|---|---|
| **Server** | `HOST`, `PORT`, `DEBUG` |
| **Authentication** | `AUTH_MODE`, `CTFD_URL`, `CTFD_API_KEY`, `TEAM_MODE` |
| **Instances** | `INSTANCE_TIMEOUT`, `MAX_INSTANCES_PER_USER`, `MAX_INSTANCES_PER_TEAM` |
| **Resource Limits** | `CONTAINER_MAX_MEMORY`, `CONTAINER_MAX_CPU`, `CONTAINER_PIDS_LIMIT` |
| **Ports** | `PORT_RANGE_START`, `PORT_RANGE_END` |
| **Traefik** | `TRAEFIK_REDIS_URL`, `TRAEFIK_BASE_DOMAIN`, `TRAEFIK_BACKEND_HOST` |
| **Dynamic Flags** | `DYNAMIC_FLAGS_ENABLED`, `FLAG_PREFIX` |
| **Forensics** | `FORENSICS_AUTO_CAPTURE`, `FORENSICS_MAX_SIZE_MB`, `FORENSICS_RETENTION_HOURS` |
| **Network Isolation** | `NETWORK_ISOLATION_ENABLED`, `NETWORK_ICC_DISABLED` |
| **Database** | `DATABASE_URL`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DATA_DIR` |
| **Redis** | `REDIS_URL`, `TRAEFIK_REDIS_URL` |
| **Admin** | `ADMIN_KEY`, `METRICS_SECRET`, `ADMIN_PATH`, `DISCORD_WEBHOOK_URL` |

Full reference at [Environment Variables Reference](#environment-variables-reference).

### VPS Firewall Setup

```bash
# Whaley API (user + admin access)
sudo ufw allow 8000/tcp

# Backend binding range (Traefik → VM2)
sudo ufw allow 20000:50000/tcp

# Traefik public entrypoints (on VM1, not VM2)
# Example: sudo ufw allow 443/tcp    # HTTPS
# Example: sudo ufw allow 5443/tcp   # TCP/TLS SNI
```

---

## Challenge Structure

### instance.toml

Full template: [`challenges/instance.schema.example.toml`](../challenges/instance.schema.example.toml)

```toml
id = "my-challenge-id"              # Unique slug (defaults to folder name)
name = "My Challenge Name"          # Display name (defaults to folder name)
category = "web"                    # web | pwn | rev | crypto | misc | forensics
description = "Short challenge summary"

# Routing
type = "http"                       # http | tcp | <custom protocol>
entrypoint = ""                     # Required for custom types (e.g., "ssh-challenges")
tls = true                          # Default: true for http/tcp, false for custom
tls_options = "default"             # Traefik TLS options name

# Ports & lifetime
ports = [80]                        # Internal ports to expose (first is primary)
timeout = 3600                      # Instance lifetime in seconds
extend_time = 1800                  # Extension step in seconds

# Per-challenge dynamic flags override
disable_dynamic_flags = false       # Force-disable dynamic flags for this challenge

# Optional custom connection command
connection_command = "Open in browser: {public_url}"
```

### Routing Types

| Type | Behavior | TLS | Entrypoint |
|---|---|---|---|
| `http` | HTTPS router with `Host({fqdn})` rule | Yes (default) | `TRAEFIK_HTTP_ENTRYPOINT` |
| `tcp` | SNI router with `HostSNI({fqdn})` | Yes (default) | `TRAEFIK_TCP_ENTRYPOINT` |
| `ssh` (custom) | SNI or non-TLS router | Optional | Must specify `entrypoint` |
| Other custom | Router on named entrypoint | Optional | Must specify `entrypoint` |

### connection_command Templates

Customize what users see in `connection_hint`:

**Single string:**
```toml
connection_command = "ssh ctf@{host} -p {port}"
```

**Per-routing-type map:**
```toml
[connection_command]
default = "{connection_string}"
tcp = "ncat --ssl {host} {port}"
http = "Open {public_url}"
web = "Open {public_url}"
pwn = "nc {host} {port}"
ssh = "ssh ctf@{host} -p {port}"
```

**Template variables** (supports both `{var}` and `${var}`):
- `instance_id`, `challenge_id`, `challenge_name`
- `category`, `routing_type`, `type`
- `host`, `fqdn`, `port`, `public_port`, `backend_port`, `internal_port`
- `public_url`, `url`
- `connection_string` / `connection_hint` / `connection` (auto-generated), `entrypoint`

### Multi-Port Challenge Example

```toml
id = "safe-social"
name = "Safe Social"
category = "web"
type = "http"
description = "A social media platform with XSS bot"
ports = [5173, 10003]
timeout = 3600
extend_time = 1200
```

### docker-compose.yaml

Both `.yaml` and `.yml` extensions are supported.

**Single Service:**
```yaml
services:
  web:
    build: .
    ports:
      - "${PORT_80:-8080}:80"       # PORT_<internal> env var
    environment:
      - FLAG=${FLAG}                 # Injected at spawn if dynamic flags enabled
    mem_limit: 256m
    cpus: 0.5
```

**Multi-Service:**
```yaml
services:
  backend:
    build: ./backend
    ports:
      - "${PORT_10003:-10003}:10003"
    mem_limit: 256m
    cpus: 0.5

  frontend:
    build: ./frontend
    ports:
      - "${PORT_5173:-5173}:5173"
    depends_on: [backend]
    mem_limit: 256m
    cpus: 0.5

  bot:
    build: ./bot
    depends_on: [backend, frontend]
    environment:
      - API_BASE=http://backend:10003
      - FRONTEND_BASE=http://frontend:5173
    mem_limit: 512m
    cpus: 0.5
```

> **Important:** Do NOT use `container_name` in your compose files — it prevents multiple instances from running simultaneously.

### Resource Enforcement

Whaley enforces global resource caps on **every** container at spawn time:

```
CONTAINER_MAX_MEMORY=512m     # Caps mem_limit (per-container)
CONTAINER_MAX_CPU=1.0         # Caps cpus (per-container)
CONTAINER_PIDS_LIMIT=256      # Injects pids_limit (fork bomb protection)
```

Per-challenge overrides can be set from Admin → Challenges → Resource Limits.

### Challenge Authoring Tips

- **No `container_name`** — prevents multiple instances
- **Use `PORT_<internal>` env vars** — Whaley sets these at spawn time
- **Declare `type` explicitly** — `http` for HTTPS, `tcp` for SNI TCP, custom protocol otherwise
- **Set resource limits** — `mem_limit` and `cpus` prevent abuse
- **Use `connection_command`** — provide challenge-specific snippets with template variables
- **Multi-port challenges** — list all externally-accessible ports in instance.toml
- **`disable_dynamic_flags`** — set to `true` for challenges where per-player unique flags don't apply (e.g., flags embedded in binaries that can't be replaced at runtime). Any existing CTFd challenge mapping is automatically removed when this is enabled. Admins cannot map the challenge in the Flags panel while this is set.

---

## API Reference

### Public Endpoints

#### Health & Status
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/` | GET | None | User dashboard (React SPA) |
| `/api` | GET | None | API info, auth mode |
| `/health` | GET | None | Detailed health status |
| `/metrics` | GET | `Bearer <METRICS_SECRET>` | Prometheus metrics (30+ families) |
| `/config` | GET | None | Public configuration (team mode, limits, timeout) |

#### Challenges
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/challenges` | GET | User | List active challenges |
| `/challenges/{id}` | GET | User | Challenge details |

#### Instances
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/instances` | GET | User | List user's instances |
| `/instances/spawn` | POST | User | Spawn new instance |
| `/instances/{id}` | GET | User | Get instance details |
| `/instances/{id}` | DELETE | User | Stop instance |
| `/instances/{id}/extend` | POST | User | Extend instance lifetime |

#### User
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/me` | GET | User | Current user info + instance count |
| `/me/team` | GET | User | Team info and members |

### Admin Endpoints (require `X-Admin-Key` header)

#### Dashboard & Logs
| Endpoint | Method | Description |
|---|---|---|
| `/{admin_path}` | GET | Admin dashboard (React SPA) |
| `/admin/api/stats` | GET | System statistics |
| `/admin/api/logs` | GET | Paginated event logs (with filtering) |
| `/admin/api/instances` | GET | All active instances |
| `/admin/api/instances/{id}` | DELETE | Force-stop instance |

#### Port Management
| Endpoint | Method | Description |
|---|---|---|
| `/admin/api/user-ports` | GET | All user port mappings |
| `/admin/api/port-stats` | GET | Port usage statistics |
| `/admin/api/user-ports` | DELETE | Clear all port mappings |
| `/admin/api/user-ports/{user_id}` | DELETE | Delete user's port mappings |

#### Dynamic Flags
| Endpoint | Method | Description |
|---|---|---|
| `/admin/api/flags` | GET | Flags state (mappings + suspicious, returns `suspicious_total` and `last_submission_id`) |
| `/admin/api/flags/check-submissions` | POST | Run detection scan. Use `?full_scan=true` to re-check all recent submissions; default is incremental (new only) |
| `/admin/api/flags/suspicious` | GET | Paginated suspicious entries. Accepts `?offset=0&limit=50` query params |
| `/admin/api/flags/suspicious` | DELETE | Clear all suspicious records from DB |
| `/admin/api/flags/mappings` | GET | All flag mappings |
| `/admin/api/flags/user/{user_id}` | DELETE | Delete all flags for user |
| `/admin/api/flags/{flag_id}` | DELETE | Delete specific flag |
| `/admin/api/flags/sync-challenge` | POST | Map local → CTFd challenge |
| `/admin/api/flags/mapping/{id}` | DELETE | Remove mapping |
| `/admin/api/ctfd/challenges` | GET | Fetch CTFd challenges (sync wizard) |

#### Forensics
| Endpoint | Method | Description |
|---|---|---|
| `/admin/api/forensics/stats` | GET | Forensics statistics |
| `/admin/api/forensics/toggle` | POST | Toggle auto-capture |
| `/admin/api/forensics/logs` | GET | List logs (filtered) |
| `/admin/api/forensics/logs/{id}` | GET | Get log content |
| `/admin/api/forensics/logs/{id}` | DELETE | Delete log |
| `/admin/api/forensics/logs` | DELETE | Clear all logs |
| `/admin/api/forensics/live-capture/{id}` | POST | On-demand capture |
| `/admin/api/forensics/cleanup` | POST | Manual retention cleanup |

#### Monitoring
| Endpoint | Method | Description |
|---|---|---|
| `/admin/api/monitoring/system` | GET | Host + aggregate container metrics |
| `/admin/api/monitoring/instances` | GET | Per-instance container metrics |

#### Challenge Manager
| Endpoint | Method | Description |
|---|---|---|
| `/admin/api/challenges/list` | GET | All challenges with load status |
| `/admin/api/challenges/upload` | POST | Upload zipped challenge |
| `/admin/api/challenges/{id}` | DELETE | Delete challenge directory |
| `/admin/api/challenges/{id}/files` | GET | Browse file tree |
| `/admin/api/challenges/{id}/files/{path}` | GET | Read file content |
| `/admin/api/challenges/{id}/files/{path}` | PUT | Write file |
| `/admin/api/challenges/{id}/files/{path}` | POST | Create file |
| `/admin/api/challenges/{id}/files/{path}` | DELETE | Delete file/directory |
| `/admin/api/challenges/{id}/reload` | POST | Reload instance.toml |
| `/admin/api/challenges/{id}/toggle` | POST | Toggle active/inactive |
| `/admin/api/challenges/settings` | GET | All challenge settings |
| `/admin/api/challenges/{id}/resources` | PUT | Set resource overrides |

#### Runtime Settings
| Endpoint | Method | Description |
|---|---|---|
| `/admin/api/settings` | GET | Current values + override status |
| `/admin/api/settings` | PUT | Update settings (persisted to DB) |
| `/admin/api/settings/{key}` | DELETE | Reset to environment default |
| `/admin/api/settings/load` | POST | Reload all from DB |

### API Usage Examples

#### Spawn an Instance
```bash
curl -X POST http://localhost:8000/instances/spawn \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <CTFD_TOKEN>" \
  -d '{"challenge_id": "example-web"}'
```

Response:
```json
{
  "success": true,
  "message": "Instance started successfully",
  "instance": {
    "instance_id": "example-web-abc123-def456",
    "challenge_id": "example-web",
    "routing_type": "http",
    "status": "running",
    "ports": {"80": 31234},
    "public_url": "https://example-web-abc123-def456.ctf.example",
    "public_urls": {"80": "https://example-web-abc123-def456.ctf.example"},
    "connection_hint": "https://example-web-abc123-def456.ctf.example",
    "expires_at": "2026-01-02T12:00:00+00:00"
  }
}
```

#### Stop an Instance
```bash
curl -X DELETE http://localhost:8000/instances/example-web-abc123-def456 \
  -H "Authorization: Bearer <CTFD_TOKEN>"
```

#### Extend Instance Lifetime
```bash
curl -X POST http://localhost:8000/instances/example-web-abc123-def456/extend \
  -H "Authorization: Bearer <CTFD_TOKEN>"
```

**Extension rules:**
- Extension increment comes from `instance.toml` (`extend_time`, default 1800s)
- Only allowed after at least half of `timeout` has elapsed
- Total added extension capped at `timeout` (max extra time = `timeout`)

---

## Authentication

### CTFd Mode (`AUTH_MODE=ctfd`)

Users authenticate with their CTFd access token:

```bash
curl -H "Authorization: Bearer <CTFD_ACCESS_TOKEN>" \
  http://your-instancer:8000/challenges
```

**Web UI:** Open the dashboard, enter your CTFd access token when prompted. The token is stored in browser `sessionStorage`.

Users obtain their CTFd token from CTFd → Settings → Access Tokens.

### No-Auth Mode (`AUTH_MODE=none`)

Users are identified by IP address. No authentication required:

```bash
curl http://your-instancer:8000/challenges
```

### Admin Authentication

The admin panel requires an `X-Admin-Key` header:

```bash
curl -H "X-Admin-Key: your_admin_key" \
  http://your-instancer:8000/admin/api/stats
```

The admin UI stores the key in browser `localStorage`. Admin endpoints have per-IP rate limiting (default 150 req/min).

---

## Team Mode

Whaley supports CTFd Team Mode where instances and dynamic flags are shared per-team.

### Configuration

```env
TEAM_MODE=auto        # Auto-detect from CTFd (recommended)
TEAM_MODE=enabled     # Force team mode
TEAM_MODE=disabled    # Force user mode

MAX_INSTANCES_PER_TEAM=5
```

### Auto-Detection

With `TEAM_MODE=auto`, Whaley queries CTFd's `/api/v1/configs/user_mode` at startup to detect whether the competition uses teams or users.

### Team Membership Requirement

When team mode is enabled, only users belonging to a CTFd team can access the instancer. Users without a team receive HTTP 403.

### Behavior Differences

| Feature | User Mode | Team Mode |
|---|---|---|
| **Instance Ownership** | Per-user | Per-team (shared) |
| **Instance Limit** | `MAX_INSTANCES_PER_USER` | `MAX_INSTANCES_PER_TEAM` |
| **Dynamic Flags** | Unique per user | Shared per team |
| **Who Can Stop/Extend** | Only the spawner | Any team member |
| **Instance Visibility** | Only user's instances | All team instances |
| **Suspicious Detection** | User A submits User B's flag | Team A submits Team B's flag |
| **Port Allocation** | Per-user persistence | Per-team persistence |

### Example Flow

```
User A (Team Alpha) spawns "web-challenge"
→ Instance created for Team Alpha
→ Dynamic flag generated for Team Alpha

User B (Team Alpha, same team) sees the instance
User B can extend or stop the instance

User C (Team Beta, different team) spawns "web-challenge"
→ Separate instance for Team Beta
→ Different flag
```

---

## Admin Dashboard

The admin dashboard is a React SPA accessible at `http://your-instancer:8000/admin`. It has six tabs:

### 1. Dashboard
- **Statistics cards:** Total spawns, active instances, unique users, 24h events, ports used/available, auth mode, challenges loaded
- **Active instances list:** All running instances with force-stop capability, owner info, routing details, expiry time, port mappings

### 2. Logs
Three sub-tabs:
- **Events:** Filterable, paginated event log viewer with JSON/CSV export. Filter by event type, username, limit (50-500 entries)
- **Ports:** Persistent user port mappings, filterable by user and challenge, with delete and clear-all actions
- **Forensics:** Auto-capture toggle, live capture from running instances, log viewer with copy/download, cleanup management

### 3. Flags
- **Summary stats:** Dynamic flags enabled/disabled, total flags, users with flags, suspicious count
- **Suspicious submissions:** List of detected flag-sharing incidents (paginated, 6 per page), "Check Now" manual scan, "Clear History"
- **Flag mappings:** Filterable by owner and challenge, flag content preview, per-mapping delete
- **Challenge ID mapping:** Manual mapping or CTFd Sync Wizard (auto-fetches CTFd challenges, smart name matching, one-click mapping)

### 4. Challenges
- **Upload:** Drag-and-drop or click to upload .zip challenge archives (max 50MB)
- **Challenge list:** All challenges with status badges (missing config, missing compose, loaded, not loaded), active/inactive toggle, reload config, edit files, delete
- **File editor:** Tree browser, text file editor with save and unsaved changes tracking, new file creation, file/directory deletion

### 5. Monitoring
- **System metrics:** Total/running containers, total CPU%, total memory, host CPU cores, host RAM used/total
- **Instance metrics:** Per-instance CPU and memory, sorted by CPU descending, "High usage only" filter (>50% CPU or >80% RAM), expandable container details

### 6. Settings
7 categorized sections of editable runtime settings (see [Runtime Settings UI](#runtime-settings-ui))

---

## Runtime Settings UI

The Settings tab in the admin panel allows changing most Whaley configuration at runtime without editing files or restarting.

### How It Works

1. Settings are defined in `app/main.py` as an `EDITABLE_SETTINGS` dictionary with metadata (type, min/max, label, description, section, options)
2. Environment variables and `.env` provide baseline values at startup
3. Database overrides in the `whaley_settings` table take precedence when present
4. Changes via the Settings UI are validated, persisted to the database, and applied immediately
5. Settings survive container restarts (loaded from DB at startup via `_load_settings_from_db()`)

### Editable Settings Categories

| Section | Settings |
|---|---|
| **Instance** | `INSTANCE_TIMEOUT`, `MAX_INSTANCES_PER_USER`, `MAX_INSTANCES_PER_TEAM` |
| **Resource Limits** | `CONTAINER_MAX_MEMORY`, `CONTAINER_MAX_CPU`, `CONTAINER_PIDS_LIMIT` |
| **Network & Ports** | `PORT_RANGE_START`, `PORT_RANGE_END`, `NETWORK_ISOLATION_ENABLED`, `NETWORK_ICC_DISABLED`, `PUBLIC_HOST` |
| **Traefik Routing** | `TRAEFIK_REDIS_ENABLED`, `TRAEFIK_REDIS_URL`, `TRAEFIK_BASE_DOMAIN`, `TRAEFIK_BACKEND_HOST`, `TRAEFIK_HTTP_ENTRYPOINT`, `TRAEFIK_TCP_ENTRYPOINT`, `TRAEFIK_TCP_EXTERNAL_PORT`, `TRAEFIK_HTTP_TLS_OPTIONS`, `TRAEFIK_TCP_TLS_OPTIONS` |
| **Features** | `DYNAMIC_FLAGS_ENABLED`, `FLAG_PREFIX` |
| **Authentication** | `AUTH_MODE`, `CTFD_URL`, `CTFD_API_KEY`, `TEAM_MODE`, `ADMIN_KEY`, `METRICS_SECRET`, `DISCORD_WEBHOOK_URL` |
| **Forensics** | `FORENSICS_AUTO_CAPTURE`, `FORENSICS_MAX_SIZE_MB`, `FORENSICS_TAIL_LINES`, `FORENSICS_RETENTION_HOURS`, `FORENSICS_COMPRESSION` |

### UI Features

- Type-aware inputs (checkboxes for booleans, dropdowns for enums, number inputs with min/max, text inputs for strings)
- "Override" vs "Default" badge per setting
- "Modified" badge when draft differs from saved value
- Pending change count badge, batch save
- Reset to default per setting

---

## Dynamic Flags & Anti-Cheat

When enabled, each user (or team) receives a unique flag per challenge. Whaley detects flag sharing by cross-referencing CTFd submissions against flag ownership. All flag data is stored in the database — there is no JSON file involved.

> For an exhaustive technical deep-dive (extraction algorithm, injection regex, ownership semantics, detection sequence), see [DYNAMIC-FLAGS.md](./DYNAMIC-FLAGS.md).

### Prerequisites

1. `AUTH_MODE=ctfd` (required — no-auth mode cannot verify flag ownership)
2. `DYNAMIC_FLAGS_ENABLED=true`
3. `CTFD_API_KEY` — a CTFd admin API token with flag write permissions
4. Local challenges mapped to CTFd challenge IDs (via Sync Wizard in Admin → Flags)

### How It Works

1. **Base Extraction:** Whaley scans challenge files for an existing `FLAG{...}` placeholder and extracts the inner text (the "base content")
2. **Flag Generation:** A unique flag is generated by appending `_<16 random hex>` to the base: `FLAG{base_content_a1b2c3d4e5f6g7h8}`. If no placeholder exists, a fully random 32-hex-char flag is generated
3. **CTFd Registration:** The flag is registered in CTFd as a static flag via the API
4. **File Injection:** **Every** `FLAG{...}` occurrence in challenge files is replaced with the dynamic flag before containers start
5. **Flag Reuse:** Same owner+challenge always gets the same flag (looked up before creation, returned on subsequent spawns)
6. **Incremental Checking:** Every 60 seconds, Whaley checks only **new** CTFd submissions (since the last processed submission ID). This avoids re-scanning the same data repeatedly. A full re-scan can be triggered manually via `POST /admin/api/flags/check-submissions?full_scan=true`
7. **Detection:** If a user submits a flag that belongs to a different user (or team in team mode), it's logged as suspicious

### Setup

1. Enable in configuration:
   ```env
   DYNAMIC_FLAGS_ENABLED=true
   CTFD_API_KEY=ctfd_your_admin_token
   FLAG_PREFIX=FLAG
   ```

2. Use placeholder flags in challenge files:
   ```
   FLAG{placeholder_value_here}
   ```
   Whaley finds the first `FLAG{...}` pattern, extracts the inner text (`placeholder_value_here`), and generates `FLAG{placeholder_value_here_<16hex>}`. Every `FLAG{...}` occurrence in the challenge is replaced with this unique flag.

3. Map challenges via **Admin → Flags → Challenge ID Mapping → Sync Wizard**

4. Monitor for cheating via **Admin → Flags → Check Now** (incremental) or use the full-scan option for a complete audit

### Detection Logic

| Mode | Comparison | Suspicious When |
|---|---|---|
| **User Mode** | `submitter_user_id` vs `flag_owner_user_id` | Different users |
| **Team Mode** | `submitter_team_id` vs `flag_owner_team_id` | Different teams |

Deduplication uses a SHA-256 hash of `submitter_identity|owner_identity|flag_hash` as a unique key, ensuring the same incident is never recorded twice. Suspicious submissions are paginated in the admin UI (DB-backed, not in-memory).

### Caveats

- **Spawn is fail-open:** If dynamic flag creation fails, the instance still spawns (flag stays as placeholder)
- **No auto-delete:** Flags are not deleted when instances stop/expire; manual admin cleanup available via Admin → Flags
- **Prefix matters:** File injection only replaces `{PREFIX}{...}` patterns — ensure challenge placeholders match `FLAG_PREFIX`
- **Incremental mode:** The background checker only processes new submissions. Use `full_scan=true` in the admin API if you need to re-check all recent history

---

## Challenge Manager

The admin Challenge Manager allows uploading, editing, and managing challenges entirely through the web interface.

### Features

- **Upload Challenges:** Drag-and-drop or click to upload .zip files (max 50MB, max 1000 entries, max 200MB extracted)
- **File Browser:** Tree view of all files in a challenge directory
- **Text Editor:** Edit text files in-browser with save tracking
- **Create/Delete Files:** Create new files or delete existing ones
- **Reload Config:** After editing `instance.toml`, reload without restarting
- **Active/Inactive Toggle:** Show or hide challenges from users
- **Resource Overrides:** Set per-challenge memory and CPU limits

### Security

- Path traversal protection (symlink resolution + containment check)
- Binary files marked as non-editable
- All operations confined to `CHALLENGES_DIR`
- Zip-slip validation for uploaded archives

### Challenge Status Display

| Status | Meaning |
|---|---|
| **Loaded** | `instance.toml` and compose file found, config valid |
| **Missing Config** | No `instance.toml` found |
| **Missing Compose** | No `docker-compose.yaml`/`.yml` found |
| **Not Loaded** | Config parse error or other load failure |
| **Active** | Visible to users, spawnable |
| **Inactive** | Hidden from users, spawn returns 403 |

---

## Instance Forensics

Container log capture for debugging — auto-capture on instance termination and on-demand live capture.

### Configuration

```env
FORENSICS_AUTO_CAPTURE=false       # Enable auto-capture on terminate
FORENSICS_MAX_SIZE_MB=5            # Max log size per instance capture
FORENSICS_TAIL_LINES=1000          # Max lines per container
FORENSICS_RETENTION_HOURS=168      # Auto-delete logs after 7 days
FORENSICS_COMPRESSION=true         # Gzip compress logs (~90% savings)
FORENSICS_LOG_DIR=/app/logs/forensics
```

### Capture Modes

| Mode | Trigger | Use Case |
|---|---|---|
| **Auto Capture** | Instance stop/expiry | Post-mortem debugging |
| **Live Capture** | Admin manually triggers | Real-time debugging |

### Usage

**Admin UI:** Logs → Forensics tab
- Toggle auto-capture on/off
- Select running instance → "Capture Now"
- View/download captured logs

**API:**
```bash
# Get stats
curl -H "X-Admin-Key: <key>" http://localhost:8000/admin/api/forensics/stats

# Toggle auto-capture
curl -X POST -H "X-Admin-Key: <key>" \
  "http://localhost:8000/admin/api/forensics/toggle?enabled=true"

# Live capture from running instance
curl -X POST -H "X-Admin-Key: <key>" \
  "http://localhost:8000/admin/api/forensics/live-capture/{instance_id}"

# View log content
curl -H "X-Admin-Key: <key>" \
  "http://localhost:8000/admin/api/forensics/logs/{log_id}"
```

### Resource Impact

Forensics capture is semaphore-limited (max 5 concurrent). Disk usage is minimal with compression:
- ~30 KB per instance (compressed, 1000 tail lines × 3 containers)
- ~108 MB per day for a 150-team event with active spawning

---

## Resource Monitoring

Real-time Docker container resource metrics for system health and abuse detection.

### Access

**Admin UI:** Monitoring tab
- System overview cards (containers, CPU, memory, host info)
- Per-instance container metrics sorted by CPU
- "High usage only" filter (>50% CPU or >80% RAM)

**API:**
```bash
# System metrics
curl -H "X-Admin-Key: <key>" \
  http://localhost:8000/admin/api/monitoring/system

# Per-instance metrics
curl -H "X-Admin-Key: <key>" \
  http://localhost:8000/admin/api/monitoring/instances
```

Response includes per-container: CPU%, memory usage/limit/%, network RX/TX, block I/O, PIDs.

### Usage Thresholds

| Metric | Green (OK) | Yellow (Warning) | Red (Danger) |
|---|---|---|---|
| CPU | < 50% | 50-80% | > 80% |
| Memory | < 60% | 60-80% | > 80% |

### Limitations

- Metrics are on-demand snapshots (not continuous)
- No historical storage (use external Prometheus/Grafana for trends)
- No built-in alerts (monitor the `/metrics` endpoint for alerting)
- Host metrics use Linux-specific interfaces (`/proc/meminfo`, `nproc`)

---

## Discord Notifications

Whaley can send rich Discord embed notifications for lifecycle events.

### Configuration

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/.../...
```

### Events

| Event | Embed Color | Fields |
|---|---|---|
| **Instance Spawned** | Green | Instance ID, challenge, creator, routing, ports, URL, connection hint, team, IP |
| **Spawn Failed** | Red | Challenge, requester, failure reason |
| **Instance Extended** | Yellow | Instance ID, challenge, who extended, extension seconds, new expiry |
| **Instance Stopped** | Orange | Instance ID, challenge, reason (user/admin/expired), who stopped, owner |

Leave `DISCORD_WEBHOOK_URL` empty to disable notifications.

---

## Production Infrastructure

### Components

| Component | Technology | Role |
|---|---|---|
| **Application** | FastAPI + uvicorn | HTTP API, lifecycle orchestration |
| **Frontend** | React 18 + TypeScript + Vite | User and admin SPAs |
| **Database** | PostgreSQL (default) or SQLite | Event logs, port mappings, flags, settings |
| **Distributed Locking** | Redis (with local asyncio fallback) | Spawn critical section, port allocation |
| **Dynamic Routing** | Redis KV (Traefik provider) | Per-instance HTTP/TCP router keys |
| **Container Runtime** | Docker Engine + Compose v2 | Challenge container lifecycle |
| **Network Isolation** | Docker bridge networks | Per-instance network segmentation |

### Database Choice

| Feature | SQLite | PostgreSQL (Default) |
|---|---|---|
| **Setup** | Zero config | Requires server |
| **Scaling** | Single worker | Multi-worker safe |
| **Use Case** | Development, small events | Production, large events |

### Distributed Locking

| Without Redis | With Redis |
|---|---|
| Single worker only | Multi-worker safe |
| `asyncio.Lock()` | Redis SETNX locks |
| Memory-based, process-local | Distributed, survives worker restarts |

> **Important:** Without Redis, only run with 1 worker. With Redis, multiple Gunicorn workers are safe.

### Network Isolation

Each instance gets its own Docker bridge network. Benefits:
- Instances cannot communicate with each other
- Prevents lateral movement between challenges
- Automatic network cleanup on termination

```env
NETWORK_ISOLATION_ENABLED=true    # Recommended
NETWORK_ICC_DISABLED=true         # Prevent inter-container communication
```

### Deployment Modes

**Development (single worker, SQLite):**
```yaml
services:
  instancer:
    environment:
      - DATABASE_URL=sqlite+aiosqlite:///./data/whaley.db
      # REDIS_URL not needed — uses local asyncio locks
```

**Production (multi-worker, PostgreSQL, Redis):**
```yaml
services:
  redis:
    image: redis:7-alpine

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=whaley
      - POSTGRES_PASSWORD=whaley
      - POSTGRES_DB=whaley
    volumes:
      - postgres_data:/var/lib/postgresql/data

  instancer:
    depends_on: [redis, postgres]
    environment:
      - DATABASE_URL=postgresql+asyncpg://whaley:whaley@postgres:5432/whaley
      - REDIS_URL=redis://redis:6379/0
    command: gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
```

---

## Capacity Planning

### Estimation Formula

```
Concurrent Instances = Teams × Active Challenges × Concurrency Factor
RAM Required = 200 MB (overhead) + (Concurrent Instances × Avg RAM per Instance)
Ports Required = Concurrent Instances × Ports per Challenge
Networks Required = Concurrent Instances

Concurrency Factors:
- Jeopardy CTF: 0.3–0.5   (not all teams active simultaneously)
- Attack-Defense: 0.8–1.0 (all teams need instances)
```

### Infrastructure Overhead

| Component | RAM | CPU | Disk |
|---|---|---|---|
| Whaley App | ~100 MB | 0.1–0.5 cores | — |
| Redis | ~50 MB | 0.05 cores | ~10 MB |
| PostgreSQL DB | ~50 MB | 0.1 cores | 1–100 MB |
| Per-Instance Network | ~1 MB | minimal | — |
| **Total Overhead** | **~200 MB** | **~0.5 cores** | **~100 MB** |

### Server Recommendations

| Event Size | CPU | RAM | Storage | Example |
|---|---|---|---|---|
| **Small** (≤50 teams) | 4 cores | 8 GB | 40 GB SSD | Local CTFs |
| **Medium** (50–150 teams) | 8–16 cores | 32–64 GB | 100–200 GB SSD | University CTFs |
| **Large** (150–300 teams) | 32+ cores | 128+ GB | 500 GB NVMe | National CTFs |

### Example: National CTF (150 teams, Team Mode)

```
Profile:
- Teams: 150 (TEAM_MODE=enabled)
- Active challenges: 8
- Avg ports per challenge: 2
- Avg RAM per instance: 256 MB

Peak Load Calculation:
- Concurrent instances: 150 × 8 × 0.4 = 480 instances
- RAM: 200 MB + (480 × 256 MB) = ~123 GB
- Ports: 480 × 2 = 960 ports
- Networks: 480 isolated networks

Realistic Deployment:
- Server: 16 cores, 64 GB RAM, 200 GB NVMe
- Workers: 1 (SQLite) or 4 (PostgreSQL + Redis)
- PORT_RANGE: 10000–40000 (30,000 ports)
- INSTANCE_TIMEOUT: 1800 (30 min)
- MAX_INSTANCES_PER_TEAM: 5
```

### Recommended Resource Limits by Challenge Type

| Challenge Type | CPU | Memory | Processes |
|---|---|---|---|
| Static Web | 0.25 | 128 MB | 50 |
| Dynamic Web (Flask/Node) | 0.5 | 256 MB | 100 |
| PWN (binary) | 0.5 | 128 MB | 50 |
| Crypto/Rev | 0.25 | 64 MB | 25 |
| Complex (multi-service) | 1.0 | 512 MB | 150 |

---

## Security

### Implemented Controls

| Control | Mechanism |
|---|---|
| Admin authentication | `X-Admin-Key` header + per-IP rate limiting (150/min) |
| User rate limiting | Sliding window (10 req/min for spawn/stop/extend) |
| Metrics protection | Bearer token via `METRICS_SECRET`, constant-time comparison |
| Path traversal prevention | Symlink resolution + containment check for file operations |
| Zip upload protection | Max size (50MB), max entries (1000), max extracted (200MB), zip-slip validation |
| Security headers | CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy |
| Network isolation | Per-instance bridge network, optional ICC disabled |
| Resource caps | Enforced memory, CPU, PID limits on all containers |
| Fork bomb protection | `CONTAINER_PIDS_LIMIT` (default 256) per container |
| Ownership enforcement | Instance access checked against user identity + team membership |

### Considerations

- CORS allows all origins (`allow_credentials=false` for security)
- Admin key stored in browser `localStorage` by admin UI
- In no-auth mode, user identity comes from forwarded headers
- Monitoring host checks use Linux-specific interfaces

---

## Development

### Local Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm ci
cd ..

# Run backend
DEBUG=true python -m uvicorn app.main:app --reload

# Run frontend dev server (in separate terminal)
cd frontend
npm run dev
```

### Project Structure

```
whaley/
├── app/                          # FastAPI backend (Python)
│   ├── main.py                   # App entry point, all route handlers
│   ├── config.py                 # Pydantic Settings
│   ├── models.py                 # Pydantic API models
│   ├── auth.py                   # Authentication + team mode
│   ├── docker_manager.py         # Challenge lifecycle
│   ├── docker_client.py          # Docker SDK wrapper
│   ├── port_manager.py           # Port allocation
│   ├── traefik_redis.py          # Traefik Redis KV
│   ├── distributed_lock.py       # Distributed locking
│   ├── flag_manager.py           # Dynamic flags + anti-cheat
│   ├── forensics.py              # Container log capture
│   ├── monitoring.py             # Resource metrics
│   ├── logger.py                 # Event logging
│   ├── discord_webhook.py        # Discord notifications
│   ├── database/
│   │   ├── connection.py         # Async SQLAlchemy engine
│   │   └── models.py             # ORM models
│   └── static/                   # Built frontend assets
├── frontend/                     # React + TypeScript + Vite
│   ├── src/
│   │   ├── main.tsx              # User app entry
│   │   ├── admin.tsx             # Admin app entry
│   │   ├── admin/                # Admin pages + types
│   │   ├── user/                 # User app + types
│   │   ├── shared/               # API, components, hooks, utils
│   │   └── styles/               # Global CSS + Tailwind
│   ├── package.json
│   ├── vite.config.js
│   └── tailwind.config.js
├── challenges/                   # Challenge definitions
├── data/                         # Persistent data directory
├── logs/                         # Event logs + forensics
├── docs/                         # Documentation
├── docker-compose.yaml           # Production deployment
├── Dockerfile                    # Multi-stage build
├── requirements.txt
└── .env.example
```

---

## Environment Variables Reference

### Server

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `8000` | Listen port |
| `DEBUG` | `false` | Debug mode |

### Authentication

| Variable | Default | Description |
|---|---|---|
| `AUTH_MODE` | `none` | `ctfd` or `none` |
| `CTFD_URL` | — | CTFd instance URL |
| `CTFD_API_KEY` | — | CTFd admin API key |
| `TEAM_MODE` | `auto` | `auto`, `enabled`, or `disabled` |

### Instances

| Variable | Default | Description |
|---|---|---|
| `INSTANCE_TIMEOUT` | `3600` | Default instance lifetime (seconds) |
| `MAX_INSTANCES_PER_USER` | `3` | Max concurrent instances per user |
| `MAX_INSTANCES_PER_TEAM` | `5` | Max concurrent instances per team |

### Resource Limits

| Variable | Default | Description |
|---|---|---|
| `CONTAINER_MAX_MEMORY` | `512m` | Max memory per container |
| `CONTAINER_MAX_CPU` | `1.0` | Max CPU per container |
| `CONTAINER_PIDS_LIMIT` | `256` | Max PIDs per container (fork bomb protection) |

### Ports

| Variable | Default | Description |
|---|---|---|
| `PORT_RANGE_START` | `30000` | Start of backend bind range |
| `PORT_RANGE_END` | `40000` | End of backend bind range |

### Traefik Redis KV

| Variable | Default | Description |
|---|---|---|
| `TRAEFIK_REDIS_ENABLED` | `true` | Enable Redis KV route registration |
| `TRAEFIK_REDIS_URL` | `REDIS_URL` fallback | Redis endpoint for Traefik KV |
| `TRAEFIK_BASE_DOMAIN` | `ctf.example` | Per-instance domain suffix |
| `TRAEFIK_BACKEND_HOST` | `challenges-vm` | Hostname Traefik uses to reach backend ports |
| `TRAEFIK_HTTP_ENTRYPOINT` | `websecure` | Traefik HTTP entrypoint name |
| `TRAEFIK_TCP_ENTRYPOINT` | `tcp-challenges` | Traefik TCP entrypoint name |
| `TRAEFIK_TCP_EXTERNAL_PORT` | `5443` | Public TCP port for SNI routing |
| `TRAEFIK_HTTP_TLS_OPTIONS` | `default` | TLS options for HTTP routers |
| `TRAEFIK_TCP_TLS_OPTIONS` | `tcp-default` | TLS options for TCP routers |
| `TRAEFIK_BLOCK_ALL_ADDRESS` | `127.0.0.1:9` | TCP catch-all drop target |
| `TRAEFIK_DASHBOARD_USERS` | — | Basic auth users for Traefik dashboard |
| `TRAEFIK_PERMANENT_KEYS_FILE` | — | YAML file with additional permanent keys |
| `TRAEFIK_PERMANENT_KEYS_JSON` | — | JSON with additional permanent keys |

### Dynamic Flags

| Variable | Default | Description |
|---|---|---|
| `DYNAMIC_FLAGS_ENABLED` | `false` | Enable per-owner unique flags |
| `FLAG_PREFIX` | `FLAG` | Prefix for generated flags |

### Forensics

| Variable | Default | Description |
|---|---|---|
| `FORENSICS_AUTO_CAPTURE` | `false` | Auto-capture logs on terminate |
| `FORENSICS_MAX_SIZE_MB` | `5` | Max log size per instance capture |
| `FORENSICS_TAIL_LINES` | `1000` | Max lines per container |
| `FORENSICS_RETENTION_HOURS` | `168` | Auto-delete after (hours) |
| `FORENSICS_COMPRESSION` | `true` | Gzip compress logs |

### Network Isolation

| Variable | Default | Description |
|---|---|---|
| `NETWORK_ISOLATION_ENABLED` | `true` | Create isolated network per instance |
| `NETWORK_ICC_DISABLED` | `true` | Disable inter-container communication |
| `NETWORK_PREFIX` | `whaley` | Prefix for instance network names |

### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://whaley:whaley@postgres:5432/whaley` | Database connection string |
| `POSTGRES_USER` | `whaley` | PostgreSQL user |
| `POSTGRES_PASSWORD` | `whaley` | PostgreSQL password |
| `POSTGRES_DB` | `whaley` | PostgreSQL database name |
| `DATA_DIR` | `/app/data` | Data directory (forensics, event logs) |

### Extra Hosts

| Variable | Default | Description |
|---|---|---|
| `EXTRA_HOST_NAME` | `main-vm` | Hostname for /etc/hosts entry (Traefik host resolution) |
| `EXTRA_HOST_IP` | `10.0.0.2` | IP for /etc/hosts entry |

### Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | — | Redis URL for distributed locking |

### Admin

| Variable | Default | Description |
|---|---|---|
| `ADMIN_KEY` | — | Secret key for admin access |
| `ADMIN_PATH` | `admin` | URL path for admin dashboard |
| `ADMIN_RATE_LIMIT` | `150` | Admin requests per minute per IP |
| `METRICS_SECRET` | — | Bearer secret for `/metrics` endpoint |
| `DISCORD_WEBHOOK_URL` | — | Discord webhook for notifications |

### Other

| Variable | Default | Description |
|---|---|---|
| `CHALLENGES_DIR` | `/challenges` | Challenge definitions directory |
| `PUBLIC_HOST` | `auto` | Public hostname/IP for user-facing URLs |
| `TRUSTED_PROXIES` | — | Comma-separated proxy IPs/CIDRs for IP extraction |
| `DOCKER_NETWORK` | — | Docker network for infrastructure (compose-managed) |
