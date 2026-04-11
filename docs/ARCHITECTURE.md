# Whaley Architecture Guide

This document is a comprehensive architecture reference for Whaley — the dedicated Docker instancer for CTF competitions. It covers every module, data flow, and design decision relevant to maintainers and contributors.

## Table of Contents

- [Project Overview](#project-overview)
- [Repository Structure](#repository-structure)
- [Runtime Architecture](#runtime-architecture)
- [Startup & Shutdown Sequence](#startup--shutdown-sequence)
- [Core Subsystems](#core-subsystems)
- [Request Flows](#request-flows)
- [Data & Persistence](#data--persistence)
- [Frontend Architecture](#frontend-architecture)
- [Build & Deployment Pipeline](#build--deployment-pipeline)
- [Security Guardrails](#security-guardrails)
- [Prometheus Metrics](#prometheus-metrics)
- [Admin Surface Map](#admin-surface-map)
- [Troubleshooting Playbook](#troubleshooting-playbook)
- [Extension Points](#extension-points)

---

## Project Overview

Whaley provides isolated Docker challenge instances to CTF participants. Each user (or team, in team mode) gets their own set of containers, reachable via dynamically-generated Traefik routes. The system handles the full lifecycle: spawn, extend, stop, and automatic expiry.

### Core Capabilities

| Capability | Description |
|---|---|
| **Instance Lifecycle** | Spawn / stop / extend with ownership and rate-limit enforcement |
| **Dynamic Routing** | Per-instance Traefik HTTP/TCP routers written to Redis KV at runtime |
| **Port Allocation** | Deterministic lane-based port assignment with database persistence |
| **Authentication** | CTFd Bearer-token validation or IP-based no-auth mode |
| **Team Mode** | Shared instances and flags per team, with team ownership semantics |
| **Dynamic Flags** | Per-owner unique flags injected into challenge files at spawn time |
| **Suspicious Submission Detection** | Cross-references CTFd submissions against flag ownership |
| **Instance Forensics** | Auto-capture or live-capture container logs on termination |
| **Resource Monitoring** | Per-container CPU, memory, network, block I/O, and PID metrics |
| **Discord Notifications** | Rich embed notifications for spawn/stop/extend/failure events |
| **Admin Management** | Web UI for challenges, settings, logs, flags, forensics, monitoring |
| **Prometheus Metrics** | 30+ metric families for SLO tracking and operational observability |

---

## Repository Structure

```
whaley/
├── app/                          # FastAPI backend
│   ├── __init__.py
│   ├── main.py                   # FastAPI app, all route handlers, lifespan, metrics
│   ├── config.py                 # Pydantic Settings (50+ env vars with defaults)
│   ├── models.py                 # Pydantic request/response models
│   ├── auth.py                   # CTFd token validation, team mode, no-auth IP identity
│   ├── docker_manager.py         # Challenge loading, spawn/stop/extend lifecycle
│   ├── docker_client.py          # Docker SDK wrapper (async over docker-py)
│   ├── port_manager.py           # Lane-based port allocation with DB persistence
│   ├── traefik_redis.py          # Traefik Redis KV dynamic router/service keys
│   ├── distributed_lock.py       # Redis distributed lock with asyncio local fallback
│   ├── flag_manager.py           # Dynamic flag generation, CTFd registration, submission check
│   ├── forensics.py              # Container log capture, indexing, retention
│   ├── monitoring.py             # Container/system resource metrics via Docker stats
│   ├── logger.py                 # Event logging to SQLite/PostgreSQL + memory cache
│   ├── discord_webhook.py        # Discord rich-embed notifications for lifecycle events
│   ├── database/
│   │   ├── __init__.py
│   │   ├── connection.py         # Async SQLAlchemy engine & session factory
│   │   └── models.py             # ORM models (7 tables)
│   └── static/                   # Built frontend assets (output of Vite build)
│       ├── index.html            # User-facing React SPA
│       ├── admin.html            # Admin panel React SPA
│       ├── assets/               # Hashed JS/CSS/font bundles
│       ├── icon.png              # Favicon
│       ├── app.js                # Legacy user dashboard (no longer used)
│       └── style.css             # Legacy stylesheet (no longer used)
├── frontend/                     # React + TypeScript + Vite source
│   ├── package.json
│   ├── vite.config.js            # Multi-page build (main + admin), output to ../app/static
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   ├── index.html                # User SPA entry point
│   ├── admin.html                # Admin SPA entry point
│   └── src/
│       ├── main.tsx              # User app bootstrap
│       ├── admin.tsx             # Admin app bootstrap
│       ├── admin/
│       │   ├── AdminApp.tsx      # Admin auth + 6-tab navigation
│       │   ├── pages/
│       │   │   ├── DashboardPage.tsx
│       │   │   ├── ChallengesPage.tsx
│       │   │   ├── FlagsPage.tsx
│       │   │   ├── LogsPage.tsx
│       │   │   ├── MonitoringPage.tsx
│       │   │   └── SettingsPage.tsx
│       │   └── types/
│       ├── user/
│       │   ├── UserApp.tsx       # User challenge spawning UI
│       │   └── types.ts
│       └── shared/
│           ├── api/              # HTTP client + admin/user API functions
│           ├── components/       # UI primitives (Badge, Button, Card, Modal, etc.)
│           ├── hooks/            # useConfirm, useToast
│           ├── types/            # Shared TypeScript types
│           └── utils/            # format, time, download helpers
├── challenges/                   # Challenge definitions (instance.toml + compose files)
├── data/                         # Persistent data directory
├── logs/
│   ├── forensics/                # Captured container logs (plain or gzipped)
│   └── events.jsonl              # Event log output
├── docs/
│   ├── ARCHITECTURE.md           # This file
│   ├── DOCUMENTATION.md          # User/operator documentation
│   ├── DYNAMIC-FLAGS.md          # Deep-dive on dynamic flags subsystem
│   └── IDENTITY.md               # MCTF 5.0 brand identity notes
├── images/                       # Screenshots
├── reports/                      # Security audit reports
├── Dockerfile                    # Multi-stage: Node frontend + Python backend
├── docker-compose.yaml           # Production deployment (instancer + Redis)
├── requirements.txt              # Python dependencies
├── .env.example                  # Full configuration reference
├── .env.prod                     # Production configuration (sensitive)
└── LICENSE
```

---

## Runtime Architecture

### In-Process Managers

All core managers are module-level singletons, instantiated at import or during lifespan startup:

| Manager | Module | Role |
|---|---|---|
| `PortManager` | `port_manager.py` | Port allocation/release, lane distribution |
| `DockerManager` | `docker_manager.py` | Challenge lifecycle orchestration |
| `EventLogger` | `logger.py` | Event persistence to DB + memory cache |
| `FlagManager` | `flag_manager.py` | Dynamic flag lifecycle |
| `ForensicsManager` | `forensics.py` | Container log capture/retrieval |
| `MonitoringManager` | `monitoring.py` | Resource metrics collection |
| `DistributedLockManager` | `distributed_lock.py` | Redis or local asyncio locks |
| `DockerClient` | `docker_client.py` | Docker SDK wrapper |
| `TraefikRedisProvider` | `traefik_redis.py` | Redis KV router management |
| `DiscordWebhookNotifier` | `discord_webhook.py` | Lifecycle event notifications |

**Design Implication:** Most runtime state (active instances, challenge configs, port maps) is process-local and memory-backed. Horizontal scaling requires Redis locks and external persistence (PostgreSQL). On restart, in-memory state is rebuilt via `cleanup_stale_instances_on_startup()`.

### Singleton Access Pattern

Each manager exposes a lazy singleton via a `get_*()` function:

```python
# Example pattern
_flag_manager: Optional[FlagManager] = None

def get_flag_manager() -> FlagManager:
    global _flag_manager
    if _flag_manager is None:
        _flag_manager = FlagManager(...)
    return _flag_manager
```

For managers requiring async initialization, `init_*()` and `close_*()` functions are called during the FastAPI lifespan.

---

## Startup & Shutdown Sequence

### Startup (in order)

```
1. init_database()                    # Async SQLAlchemy engine + table creation
2. init_lock_manager(REDIS_URL)       # Redis or local lock backend
3. init_event_logger()                # Determine max existing log ID
4. port_manager.initialize()          # Load persisted port mappings from DB
5. init_auth()                        # CTFd client initialization
6. docker_manager.load_challenges()   # Parse all instance.toml files
7. docker_manager.load_challenge_settings()  # Active/inactive + resource overrides
8. _load_settings_from_db()           # Apply persisted setting overrides (30+ keys)
9. init_traefik_provider()            # Bootstrap permanent Redis KV keys
10. docker_manager.cleanup_stale_instances_on_startup()  # Orphan cleanup
11. docker_manager.start_cleanup_task()    # Background 60s cleanup loop
12. init_team_mode()                   # Auto-detect or use configured team mode
13. Start _auto_check_submissions()    # Background 60s submission checker
14. Log SYSTEM_START event
```

### Shutdown (in order)

```
1. Log SYSTEM_STOP event
2. Cancel submission checker background task
3. Cancel cleanup background task
4. close_traefik_provider()
5. close_lock_manager()
6. close_database()
```

---

## Core Subsystems

### 1. Authentication & Identity (`auth.py`)

**Two modes:**

**CTFd Mode** (`AUTH_MODE=ctfd`):
- Validates `Authorization: Bearer <token>` against CTFd `/api/v1/users/me`
- Enriches with team metadata via CTFd team endpoints
- Multi-strategy team member resolution (members endpoint, team details, /teams/me, user list filter)
- Returns `UserInfo` with user_id, username, team_id, team_name

**No-Auth Mode** (`AUTH_MODE=none`):
- Identifies users by IP from `X-Forwarded-For` or `X-Real-IP` headers
- Creates pseudo-user with ID prefix `user_`
- Falls back to "anonymous" if no IP available

**Team Mode:**
- `TEAM_MODE=auto`: queries CTFd `/api/v1/configs/user_mode` to detect
- `TEAM_MODE=enabled`: forces team mode, requires team membership
- `TEAM_MODE=disabled`: forces user mode
- When enabled, users without a CTFd team are refused (403)

### 2. Docker Client (`docker_client.py`)

Async wrapper over the `docker-py` SDK. All blocking operations run via `loop.run_in_executor()`.

**Network Management:**
- `create_isolated_network()` — bridge driver with ICC/internal options, whaley labels
- `remove_network()`, `list_whaley_networks()`

**Image Management:**
- `build_image()` — with build args and cache control

**Container Management:**
- `run_container()`, `stop_container()`, `remove_container()`
- `get_container_logs()`, `get_container_stats()` — full resource snapshot

**Compose Operations (subprocess bridge):**
- `compose_up()` / `compose_down()` — shells out to `docker compose`
- `list_compose_projects()` / `remove_compose_project()` — force-cleans per-spawn resources
- `list_containers_by_project()` — finds containers by compose project label

**Resource Cleanup:**
- `cleanup_whaley_resources()` — orphan sweep for networks and per-spawn images
- Uses a safety window to avoid deleting newly-created resources
- Maintains a reserved network list for infrastructure-level networks

### 3. Docker Manager (`docker_manager.py`)

The core orchestrator. This is the largest module (~1400 lines).

**Challenge Loading:**
- Parses `instance.toml` from each subdirectory of `CHALLENGES_DIR`
- Supports `.yaml` and `.yml` compose files
- `_lint_compose_file()` detects pinned subnets and IPs (non-fatal warnings)
- Loads active/inactive status and resource overrides from `ChallengeSettings` DB table

**Spawn Critical Section:**
1. Validate challenge exists and is active
2. Enter global spawn semaphore (max 10 concurrent spawns)
3. Acquire distributed lock on `spawn:{owner_id}` key
4. Enforce `MAX_INSTANCES_PER_USER` / `MAX_INSTANCES_PER_TEAM`
5. Prevent duplicate running instance for same owner+challenge
6. Generate `instance_id` = `{challenge_id}-{owner_id[:8]}-{uuid_hex[:8]}`
7. Allocate ports via `PortManager` (with up to 3 retries on conflict)
8. Create dynamic flag if enabled
9. Set up connection hints (Traefik FQDN or direct host:port)
10. Copy challenge to temp directory, inject flags, enforce resource limits
11. Run `docker compose up` via SDK
12. Register Traefik route via Redis provider
13. On failure: best-effort cleanup (compose down, route delete, port release, network removal)

**Stop Flow:**
1. Verify ownership (user or team member)
2. Optionally auto-capture forensics logs
3. `docker compose down`
4. Delete Traefik route
5. Remove isolated network
6. Clean per-spawn images/volumes
7. Release ports
8. Log event, send Discord notification

**Extend Policy:**
- Extension step comes from `instance.toml` (`extend_time`, default 1800s)
- Allowed only after half of `timeout` has elapsed
- Total added extension capped at `timeout` (max extra = `timeout`)

**Background Cleanup (every 60s):**
- Stops expired RUNNING instances
- Every ~10 minutes: sweeps orphan networks/images
- Every ~60 minutes: cleans old forensics logs

### 4. Port Manager (`port_manager.py`)

Deterministic, lane-based port allocation with database persistence.

**Lane-Based Algorithm:**
- Port range divided into N lanes (up to 32)
- Blake2b hash of `{user_id}:{challenge_id}:{internal_port}` maps to a primary lane
- Each lane maintains a cursor for next-available scanning
- Falls back to other lanes in deterministic order if primary lane is full
- Before use, verifies port is actually free via `socket.bind()` (scavenger check)

**Persistence:**
- Port assignments stored in `user_port_mappings` DB table
- On respawn, same user+challenge gets the same ports (when available)
- Allocation acquires distributed locks: per-user+challenge + global allocator

**Retry Logic:**
- Spawn retries up to 3 times on port conflicts
- Each retry re-allocates fresh ports

### 5. Traefik Redis Provider (`traefik_redis.py`)

Writes dynamic router/service configuration into Redis KV for Traefik to consume.

**Permanent Keys (bootstrapped at startup):**
- Default TCP catch-all route (block-all, priority 1)
- Optional CTFd redirect middleware
- Optional dashboard basic auth users
- Additional keys from YAML file or JSON string

**Per-Instance Routes:**
- **HTTP:** Router with `Host({fqdn})` rule, TLS, load balancer targeting `{backend_host}:{backend_port}`
- **TCP:** SNI router with `HostSNI({fqdn})`, TLS passthrough, load balancer address
- **Custom (SSH, etc.):** Dedicated entrypoint, optional TLS

**Cleanup:**
- `delete_instance_route()` scans Redis with pattern matching to remove all keys for an instance
- Uses Redis pipeline for atomic batch writes

### 6. Distributed Lock (`distributed_lock.py`)

Redis-based distributed lock with graceful fallback to local `asyncio.Lock`.

- **Redis mode:** uses `redis.asyncio` with `SET NX` semantics
- **Local mode:** transparent `asyncio.Lock` per name
- `acquire()` is an async context manager with configurable timeout
- `acquire_multiple()` acquires locks in sorted order to prevent deadlocks
- `is_distributed` property signals whether Redis is active

### 7. Flag Manager (`flag_manager.py`)

Complete dynamic flag lifecycle management. All data is stored in the database (`FlagMappingModel`, `SuspiciousSubmissionModel`, and `WhaleySettings` models); the legacy `logs/flag_mappings.json` file has been removed.

> Full technical details (extraction algorithm, injection regex, ownership semantics, detection sequence diagrams) are in [DYNAMIC-FLAGS.md](./DYNAMIC-FLAGS.md).

**Flag Format:** `{FLAG_PREFIX}{base_content}_{16 hex chars}` (default: `FLAG{...}`)
- `base_content` is the inner text extracted from the first `PREFIX{...}` placeholder found in challenge files
- If no placeholder exists, falls back to fully random: `PREFIX{<32 hex chars>}`

**Spawn-Time Flow:**
1. `_extract_base_flag_content()` — scans for `PREFIX{...}`, extracts the inner text (priority: flag files > config > source files)
2. `generate_flag(base_content)` → `FLAG{base_content_<16hex>}`
3. `create_flag_for_owner()` — creates flag in CTFd via API, inserts into `flag_mappings` DB table, updates in-memory indexes (`user_flags`, `owner_flags`, `flag_lookup`)
4. `_inject_flag_into_files()` — replaces **every** `PREFIX{...}` occurrence with the dynamic flag (regex `PREFIX{[^}\n]+}`)
5. **Per-challenge override:** If `disable_dynamic_flags = true` is set in `instance.toml`, the spawn skips flag creation entirely. Existing CTFd challenge mappings are pruned on load/reload. The admin Flags panel prevents mapping the challenge while this is set.

**Flag Reuse:** Same owner+challenge always gets the same flag (looked up from in-memory index before creating a new one).

**Suspicious Submission Detection:**
- **Incremental mode (default):** Tracks `last_submission_id` in `whaley_settings`. Only checks CTFd submissions with `id > last_submission_id`, avoiding repeated re-scanning of the same data
- **Full scan mode:** `POST /admin/api/flags/check-submissions?full_scan=true` re-checks all recent submissions regardless of checkpoint
- Fetches newest 5 pages (up to 250 submissions) from CTFd, cross-references `provided` flag against `flag_lookup`
- Ownership comparison: user_id in user mode, team_id in team mode
- Deduplication via SHA-256 unique key: `hash(submitter_identity|owner_identity|flag_hash)` stored in DB with unique index
- New suspicious entries inserted into `suspicious_submissions` table immediately; admin API supports paginated queries

**Startup:** `initialize()` loads all indexes from DB (flag mappings, challenge mapping, suspicious unique keys, last submission checkpoint) into memory for fast lookups. Lazy — called on first `await get_flag_manager()`.

### 8. Instance Forensics (`forensics.py`)

Captures Docker container logs for debugging and post-mortem analysis.

**Capture Modes:**
- **Auto Capture:** on instance termination (configurable via `FORENSICS_AUTO_CAPTURE`)
- **Live Capture:** on-demand from running instances

**Capture Process:**
1. Get container IDs via `docker compose ps -q`
2. For each container: `docker inspect` for name, `docker logs --tail --timestamps` for content
3. Enforce size limit (per capture) and tail line limit (per container)
4. Write header with metadata followed by per-container sections
5. Plain text or gzip-compressed output

**Index:** JSON-based `index.json` in forensics log directory. Thread-safe via Lock.

**Retention:** Auto-cleanup of logs older than `FORENSICS_RETENTION_HOURS` (default 168h / 7 days).

**Concurrency:** Semaphore-limited (max 5 concurrent captures).

### 9. Resource Monitoring (`monitoring.py`)

Real-time Docker container resource metrics.

**Per-Container:** CPU%, memory usage/limit/%, network RX/TX, block read/write, PIDs.

**Per-Instance:** Aggregated totals across all containers in a compose project.

**System:** Total/running containers, aggregate CPU/memory, host CPU cores, host memory (from `/proc/meminfo` on Linux).

**CPU Calculation:** Standard Docker formula — `(cpu_delta / system_cpu_delta) * online_cpus * 100`.

### 10. Event Logger (`logger.py`)

Structured event logging to SQLite/PostgreSQL with memory cache.

**Event Types:** INSTANCE_SPAWN, INSTANCE_SPAWN_FAILED, INSTANCE_STOP, INSTANCE_EXTEND, INSTANCE_EXPIRED, USER_LOGIN, USER_LOGIN_FAILED, AUTH_FAILURE, FLAG_CREATED, FLAG_DELETED, SUSPICIOUS_SUBMISSION, SYSTEM_START, SYSTEM_STOP.

**Architecture:**
- Async `log()` writes to DB via background task, also stores in memory cache (max 1000 entries)
- `get_entries()` queries DB with pagination and filtering
- `get_stats()` returns totals, counts by type, unique users, 24h activity

### 11. Discord Webhook (`discord_webhook.py`)

Sends rich Discord embeds for lifecycle events:
- **Spawn:** green embed with instance details, routing info, connection hints
- **Spawn Failure:** red embed with challenge, requester, failure reason
- **Extend:** yellow embed with extension amount, new expiry
- **Stop:** orange embed with stop reason (user/admin/expired)

Disabled when `DISCORD_WEBHOOK_URL` is empty.

### 12. Runtime Metrics (`main.py` inline)

High-frequency operational metrics tracked in memory for Prometheus export:

- **Spawn latency histogram:** 9 buckets (0.25s to 60s), inflight count
- **Operation counters:** tuples of (operation, outcome, reason_label, challenge_id)
- **Failure reason classifiers:** `_classify_spawn_failure_reason()` and `_classify_operation_failure_reason()` bucket failures into low-cardinality labels

---

## Request Flows

### Spawn Instance (`POST /instances/spawn`)

```
Client Request
  → User rate limit check (sliding window, 10/min)
  → Challenge active check
  → get_current_user() dependency
  → DockerManager.spawn_instance()
    → Determine owner_id (team_id or user_id)
    → Spawn semaphore acquire (max 10 concurrent)
    → Distributed lock acquire (spawn:{owner_id})
    → Instance limit check
    → Duplicate running check
    → _do_spawn_instance()
      → Generate instance_id
      → PortManager.allocate_ports_for_user() (with 3 retries)
      → FlagManager.create_flag_for_owner() (if enabled)
      → Build connection hints
      → Compose labels injection (whaley.managed, whaley.owner, whaley.created_at)
      → Resource limits enforcement (memory, CPU, PIDs)
      → Flag injection into challenge files
      → Isolated network creation (if enabled)
      → docker compose up -d --build
      → TraefikRedisProvider.register_instance_route()
      → Store instance in memory
      → Release lock
    → Release semaphore
  → Log event, Discord notification, metrics recording
  → Return PublicSpawnResponse
```

### Stop Instance (`DELETE /instances/{instance_id}`)

```
Client Request
  → User rate limit check
  → get_current_user() dependency
  → Find instance in memory
  → Ownership check (user or team member)
  → Forensics auto-capture (if enabled)
  → docker compose down
  → TraefikRedisProvider.delete_instance_route()
  → Remove isolated network (if created)
  → DockerClient.remove_compose_project() (clean per-spawn images/volumes)
  → PortManager.release_instance_ports()
  → Remove from memory
  → Log event, Discord notification
```

### Extend Instance (`POST /instances/{instance_id}/extend`)

```
Client Request
  → User rate limit check
  → get_current_user() dependency
  → DockerManager.extend_instance()
    → Find instance, ownership check
    → Validate: RUNNING status
    → Validate: extend_time configured
    → Validate: half-timeout elapsed since creation
    → Validate: total extension ≤ timeout cap
    → Update expires_at in memory
  → Log event, Discord notification
```

### Resource Cleanup Lifecycle

Whaley has a multi-layered cleanup strategy to prevent resource leaks (orphan containers, networks, images, volumes). Cleanup happens at four levels:

#### Level 1: Per-Instance Stop Cleanup (Synchronous)

When an instance is stopped (user action, admin force-stop, or expiry), the `stop_instance()` flow tears down everything tied to that instance:

1. **Forensics auto-capture** — if enabled, container logs are dumped before teardown
2. **`docker compose down`** — stops and removes containers for the project
3. **Traefik route deletion** — pattern-scans Redis for all `http/routers/{id}*`, `http/services/{id}*`, `tcp/routers/{id}*`, `tcp/services/{id}*` keys and deletes them
4. **Isolated network removal** — removes the per-instance bridge network (if network isolation was enabled)
5. **`remove_compose_project()`** — force-removes any remaining resources by label:
   - Containers matching `com.docker.compose.project={project_name}`
   - Networks matching the same project label (with force-disconnect fallback)
   - Volumes matching the same project label (optional, default true)
   - **Per-spawn images** — removes images whose tag starts with `{project_name}-` (e.g., `web-challenge-abc123-def456-web:latest`). Base/pulled images like `nginx:alpine` or `python:3.11` are never matched since they don't start with a project-name prefix.
6. **Port release** — returns allocated ports to the available pool
7. **In-memory state removal** — instance deleted from `docker_manager.instances` dict

#### Level 2: Background Expiry Loop (Every 60s)

`DockerManager.start_cleanup_task()` runs a continuous `asyncio` loop:

```
Every 60 seconds:
  → Scan in-memory instances for expired RUNNING instances
  → Call stop_instance() for each (triggers Level 1 cleanup)
  → Log INSTANCE_EXPIRED event
  → Send Discord notification

Every ~10 minutes (10 iterations):
  → Orphan sweep via DockerClient.cleanup_whaley_resources()
    → Passes active project names as a safety set
    → 5-minute safety window (never removes resources younger than 300s)

Every ~60 minutes (60 iterations):
  → Forensics retention cleanup (delete logs older than FORENSICS_RETENTION_HOURS)
  → Reset iteration counter
```

#### Level 3: Orphan Sweep (`cleanup_whaley_resources()`)

Catches resources that survived a failed teardown (crash, partial cleanup, labels stripped):

**Reserved Networks (never touched):**
`bridge`, `host`, `none`, `ctf-instances`, `mctf-monitoring_default`, `whaley-redis`, `whaley_default`

**Orphan Network Detection:**
- Scan all Docker networks
- Skip reserved names and networks with attached containers
- For each network, attempt to derive a project name:
  - `whaley-{project}` → named isolation network → extract `{project}`
  - `{project}_default` → compose-managed default network → extract `{project}`
- If the project is NOT in the active set → candidate for removal
- **Safety window:** skip networks younger than `older_than_seconds` (5 min during normal operation, 0 at startup)

**Orphan Per-Spawn Image Detection:**
- Scan all Docker images
- Skip base images (contain `/` in the name part, e.g., `docker.io/library/nginx`)
- Match tags against the Whaley project pattern: `{challenge-id}-{num}-{6+hex}-{service}:{tag}`
- Extract the project name from the match
- If the project is NOT in the active set → candidate for removal
- **Safety window:** same `older_than_seconds` check via image `Created` timestamp

#### Level 4: Startup Stale Cleanup

On process restart, `cleanup_stale_instances_on_startup()` runs before any new instances are spawned:

1. **Discover stale projects** via three sources:
   - `list_compose_projects()` — finds all compose projects by `com.docker.compose.project` container label
   - `list_whaley_networks()` — finds networks with `whaley.managed=true` label, extracts project names from `whaley-{project}` naming pattern
   - Static name heuristic — `_is_managed_instance_project_name()` pattern match
2. **Identify managed projects** — a project is considered Whaley-managed if it has:
   - `whaley.managed=true` label, OR
   - `whaley.instance_id` label matching project name, OR
   - A matching whaley-prefixed network, OR
   - A name matching the instance ID pattern (`{challenge}-{owner}-{hex}`)
3. **Tear down each stale project** via `remove_compose_project()` — removes containers, networks, volumes, per-spawn images
4. **Delete Traefik routes** for each project name
5. **Release ports** for each project name
6. **Final orphan sweep** — calls `cleanup_whaley_resources(active_project_names=set(), older_than_seconds=0)` with empty active set and zero safety window (nothing is running yet, so no risk of race conditions)

#### Cleanup Summary Diagram

```
Instance Stop (user/admin/expiry)
  │
  ├─ docker compose down          ← containers gone
  ├─ Traefik route delete         ← Redis keys purged
  ├─ Isolated network remove      ← bridge net gone
  ├─ remove_compose_project()     ← residual containers, networks, volumes, per-spawn images
  └─ Port release                 ← ports back in pool

Background Loop (60s tick)
  │
  ├─ Expired instances → stop (triggers above)
  ├─ Every 10 min → orphan sweep
  │     Networks: whaley-* and *_default without active project → remove
  │     Images:   {project}-{service}:tag without active project → remove
  │     5-min safety window protects in-flight spawns
  └─ Every 60 min → forensics retention cleanup

Startup Stale Cleanup (before any spawn)
  │
  ├─ Discover via compose labels + network labels + name heuristic
  ├─ Tear down each stale project
  ├─ Clear Traefik routes + release ports
  └─ Final orphan sweep (zero safety window, no race risk)
```

---

## Data & Persistence

### In-Memory (process-local, volatile)

| Data | Location |
|---|---|
| Active instances | `docker_manager.instances` dict |
| Loaded challenge configs | `docker_manager.challenges` dict |
| Allocated ports | `port_manager.allocated_ports` / `instance_ports` |
| Rate limit tracking | `_admin_rate_limit`, `_user_rate_limit` dicts in main.py |
| Runtime metrics | `_spawn_latency_*`, `_runtime_operation_counters` |
| Flag index | `FlagManager.flag_lookup`, `user_flags`, `owner_flags` |
| Auth mode cache | `_team_mode_enabled`, `_ctfd_mode_cache` |

### Database (SQLAlchemy — PostgreSQL default, SQLite fallback)

| Table | Purpose |
|---|---|
| `user_port_mappings` | Persistent port allocation per user+challenge |
| `event_logs` | Full event audit trail |
| `challenge_settings` | Active/inactive toggles, per-challenge resource overrides |
| `whaley_settings` | Global runtime setting overrides (challenge_mapping, last_submission_id) |
| `instance_states` | Schema exists (for future instance recovery) |
| `flag_mappings` | Dynamic flag assignments per owner+challenge |
| `suspicious_submissions` | Detected flag-sharing incidents |

### File-Persisted

| Path | Content |
|---|---|
| `logs/forensics/index.json` | Forensics log metadata index |
| `logs/forensics/*.log[.gz]` | Captured container logs |
| `logs/events.jsonl` | JSON-lines event log output |

> **Note:** All dynamic flag data (mappings, suspicious submissions, challenge mapping, last submission checkpoint) is stored exclusively in the database (`flag_mappings`, `suspicious_submissions`, and `whaley_settings` tables). The legacy `logs/flag_mappings.json` file has been removed.

### External State

- **Docker daemon:** containers, networks, images, compose projects (via SDK + CLI)
- **CTFd:** users, teams, dynamic flags, submissions (via REST API)
- **Redis:** lock keys, Traefik KV router/service keys

---

## Frontend Architecture

### Build Pipeline

The frontend is a **React 18 + TypeScript + Vite** application split into two SPAs:

```
frontend/src/
├── main.tsx → UserApp (mounts on #root)
└── admin.tsx → AdminApp (mounts on #admin-root)
```

**Build output:** `frontend/` builds into `app/static/` via Vite (configured in `vite.config.js`):
- `index.html` → user SPA entry
- `admin.html` → admin SPA entry
- `assets/` → hashed JS/CSS/font bundles

**Docker build:** Multi-stage — first stage runs `npm ci && npm run build` in Node 20 Alpine, second stage copies built assets into the Python image.

### User Application (`UserApp.tsx`)

- **CTFd mode:** Shows token login panel, stores token in `sessionStorage`
- **No-auth mode:** Auto-authenticates
- **Challenge Deck:** Lists active challenges with category badges, deploy buttons
- **Active Instances:** Lifecycle cards with endpoint copy, connection hints, countdown timers, extend/stop buttons
- **Auto-refresh:** Instances and health polled every 10s, clock ticks every 1s

### Admin Application (`AdminApp.tsx`)

Six tabs, URL hash-based navigation:

| Tab | Component | Features |
|---|---|---|
| **Dashboard** | `DashboardPage` | Stats cards, active instances list, force-stop |
| **Logs** | `LogsPage` | Event log viewer (filtered/paginated), port mappings, forensics (stats, toggle, live capture, log viewer) |
| **Flags** | `FlagsPage` | Flag mappings, suspicious submissions, CTFd sync wizard |
| **Challenges** | `ChallengesPage` | Upload zip, file browser/editor, active toggle, reload config |
| **Monitoring** | `MonitoringPage` | System metrics, per-instance container CPU/RAM, high-usage filter |
| **Settings** | `SettingsPage` | 30+ editable settings with type-aware inputs, sectioned layout, change tracking |

### Shared UI Components

All UI components live in `frontend/src/shared/components/ui/`:
- `Badge` — color-coded status tags (neutral/success/warning/danger/info)
- `Button` — variants (primary/secondary/danger/ghost), sizes (sm/md)
- `Card` — Dark gradient container with border
- `EmptyState` — Placeholder for empty/no-data states
- `Input`, `Select`, `Textarea` — Form inputs with consistent dark styling
- `Loader` — Spinning border animation
- `Modal` — Overlay dialog with backdrop blur
- `Tabs` — Horizontal tab navigation

### Design System

- **Colors:** graphite #0D0D0D, anthracite #262626, steel #737373, deepviolet #200F38, mist #F2F2F2
- **Fonts:** Chakra Petch (display), Public Sans (body), IBM Plex Mono (monospace)
- **Styling:** Tailwind CSS with custom theme, dark background with purple accent
- **Background:** Radial gradient with CSS grid overlay effect

---

## Build & Deployment Pipeline

### Docker Multi-Stage Build

```dockerfile
# Stage 1: Node 20 Alpine — builds frontend
FROM node:20-alpine AS frontend-builder
COPY frontend/ ./
RUN npm ci --include=dev
RUN npm install -g vite
RUN npm run build

# Stage 2: Python 3.11 Slim — runs backend
FROM python:3.11-slim
# Install Docker CLI + compose plugin
# Copy Python deps + app code
# Overlay compiled SPA assets from Stage 1
COPY --from=frontend-builder /build/app/static/index.html ./app/static/
COPY --from=frontend-builder /build/app/static/admin.html ./app/static/
COPY --from=frontend-builder /build/app/static/assets ./app/static/
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose Deployment

```
Services:
  redis        — Redis 7 Alpine, append-only persistence, healthcheck
  postgres     — PostgreSQL 16 Alpine, persistent volume, healthcheck
  instancer    — Whaley app, depends on healthy redis + postgres

Networks:
  ctf-instances — bridge network for inter-service communication

Volumes:
  redis_data    — Redis AOF persistence
  postgres_data — PostgreSQL data persistence
  /var/run/docker.sock — Mounted for container management
  ./challenges  — Challenge definitions (rw)
  ./logs        — Event logs, forensics
  ./data        — Forensics, event logs, misc data
```

---

## Security Guardrails

### Implemented Controls

| Control | Mechanism |
|---|---|
| **Admin authentication** | `X-Admin-Key` header, per-IP rate limiting (default 150/min) |
| **User rate limiting** | Sliding window, 10 requests/min for spawn/stop/extend |
| **Metrics protection** | Bearer token via `METRICS_SECRET`, constant-time comparison |
| **Path traversal prevention** | Symlink resolution + containment check for all file operations |
| **Zip upload protection** | Max size (50MB), max entries (1000), max extracted (200MB), zip-slip validation |
| **Security headers** | CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy |
| **Network isolation** | Per-instance bridge network with optional ICC disabled |
| **Resource caps** | Memory, CPU, PID limits enforced on all containers |
| **Fork bomb protection** | `CONTAINER_PIDS_LIMIT` (default 256) |
| **Ownership enforcement** | Instance access checked against user identity + team membership |
| **Trusted proxy support** | CIDR-aware IP extraction for admin endpoints |
| **String escaping** | Prometheus label values escaped per exposition format spec |

### Known Considerations

- **CORS:** Allows all origins (`allow_credentials=false`)
- **Admin key storage:** Browser `localStorage` (admin UI)
- **No-auth IP trust:** Uses forwarded headers directly (not trusted-proxy filtered)
- **Monitoring host checks:** Linux-specific (`/proc/meminfo`, `nproc`)

---

## Prometheus Metrics

Exposed at `GET /metrics` (protected by `METRICS_SECRET` Bearer token).

### Metric Families (30+)

| Category | Metrics |
|---|---|
| **Instances** | Total by status, owner, team, challenge; owner saturation ratios |
| **Lifecycle** | Per-instance expiry timestamps, age seconds, connection info |
| **Alerts** | Instances expiring within 5/10 min, stale STARTING instances (>2 min) |
| **Ports** | Allocated count, available count, utilization percent |
| **Challenges** | Loaded count, active count |
| **Flags** | Total dynamic flags assigned, suspicious submission count |
| **Forensics** | Auto-capture on/off, total log count, auto/live breakdown, total size |
| **Runtime Ops** | Operation outcome counters (spawn/stop/extend with success/failure + reason) |
| **Spawn Latency** | Histogram (9 buckets: 0.25s–60s), inflight count |
| **Event Logs** | Total entries, counts by event type, unique users, 24h activity |

### Label Conventions

- `outcome`: `success` | `failure`
- `operation`: `spawn` | `stop` | `extend`
- `challenge_id`: normalized, `unknown` if not applicable
- `reason`: normalized failure reason (underscore-separated, max 64 chars)

---

## Admin Surface Map

### Authentication: `verify_admin_key()` dependency

Checks `X-Admin-Key` header + per-IP rate limit.

### Endpoints by Domain

**Dashboard & Logs:**
```
GET  /{admin_path}                          — Admin SPA
GET  /admin/api/stats                       — Event logger stats + instances + ports
GET  /admin/api/logs                        — Paginated event logs (filtered)
GET  /admin/api/instances                   — All active instances
DELETE /admin/api/instances/{id}             — Force-stop (admin override)
```

**Port Management:**
```
GET    /admin/api/user-ports                — All user port mappings
GET    /admin/api/port-stats                — Port usage statistics
DELETE /admin/api/user-ports                — Clear all mappings
DELETE /admin/api/user-ports/{user_id}       — Delete user's ports
```

**Dynamic Flags:**
```
GET    /admin/api/flags                     — Full flags state
POST   /admin/api/flags/check-submissions   — Manual submission check
GET    /admin/api/flags/suspicious          — List suspicious entries
DELETE /admin/api/flags/suspicious          — Clear suspicious list
GET    /admin/api/flags/mappings            — All flag mappings
DELETE /admin/api/flags/user/{user_id}       — Delete user's flags
DELETE /admin/api/flags/{flag_id}            — Delete single flag
POST   /admin/api/flags/sync-challenge       — Map local → CTFd challenge
DELETE /admin/api/flags/mapping/{id}         — Remove mapping
GET    /admin/api/ctfd/challenges            — Fetch CTFd challenges (sync wizard)
```

**Forensics:**
```
GET    /admin/api/forensics/stats           — Forensics statistics
POST   /admin/api/forensics/toggle          — Enable/disable auto-capture
GET    /admin/api/forensics/logs            — List logs (filtered)
GET    /admin/api/forensics/logs/{id}        — Get log content
DELETE /admin/api/forensics/logs/{id}        — Delete specific log
DELETE /admin/api/forensics/logs            — Clear all logs
POST   /admin/api/forensics/live-capture/{id} — On-demand capture
POST   /admin/api/forensics/cleanup          — Manual retention cleanup
```

**Monitoring:**
```
GET /admin/api/monitoring/system            — System-level metrics
GET /admin/api/monitoring/instances         — Per-instance container metrics
```

**Challenge Management:**
```
GET    /admin/api/challenges/list            — List all challenges
POST   /admin/api/challenges/upload          — Zip upload
DELETE /admin/api/challenges/{id}            — Delete challenge directory
GET    /admin/api/challenges/{id}/files      — Browse file tree
GET    /admin/api/challenges/{id}/files/{path} — Read file
PUT    /admin/api/challenges/{id}/files/{path} — Write file
POST   /admin/api/challenges/{id}/files/{path} — Create file
DELETE /admin/api/challenges/{id}/files/{path} — Delete file/directory
POST   /admin/api/challenges/{id}/reload     — Reload config
POST   /admin/api/challenges/{id}/toggle     — Toggle active/inactive
GET    /admin/api/challenges/settings         — All challenge settings
PUT    /admin/api/challenges/{id}/resources   — Set resource overrides
```

**Runtime Settings:**
```
GET    /admin/api/settings                   — Current values with override status
PUT    /admin/api/settings                   — Update settings (validated, persisted, applied)
DELETE /admin/api/settings/{key}             — Reset to default
POST   /admin/api/settings/load              — Reload all from DB
```

---

## Troubleshooting Playbook

### Spawn fails immediately
1. Check challenge has valid `instance.toml` and compose file
2. Verify port range capacity (`/admin/api/port-stats`)
3. Check Docker daemon availability and compose output in error message
4. Verify resource caps aren't overly restrictive
5. Check Redis connectivity (lock acquisition failures)

### User cannot spawn despite low load
1. Check owner already has same challenge running (duplicate block)
2. Verify `MAX_INSTANCES_PER_USER` / `MAX_INSTANCES_PER_TEAM` limits
3. Check challenge active flag (admin toggle)
4. Verify user isn't rate-limited (10 req/min window)
5. In team mode: verify user belongs to a CTFd team

### Team mode behavior seems wrong
1. Check `TEAM_MODE` setting (enabled/disabled/auto)
2. Verify CTFd `user_mode` detection and API key permissions
3. Check whether user has `team_id` from CTFd token validation
4. Verify team member resolution via admin flags/logs

### Dynamic flags not generated
1. `DYNAMIC_FLAGS_ENABLED=true`
2. `AUTH_MODE=ctfd` (required for dynamic flags)
3. `CTFD_URL` and `CTFD_API_KEY` valid
4. Challenge mapping exists in admin flags panel
5. `FLAG_PREFIX` matches placeholder convention in challenge files

### Forensics missing
1. Auto-capture enabled (check toggle in admin forensics tab)
2. Capture size/tail limits not too small
3. Disk permissions for `FORENSICS_LOG_DIR`
4. Instance must be running for live capture

### Port conflicts or exhaustion
1. Check port range is large enough for expected concurrent instances
2. Verify no external processes using ports in the allocation range
3. Check `user_port_mappings` table for stale entries
4. Port allocation retries up to 3 times automatically

---

## Extension Points

### Safe Extension Points
- **New admin APIs:** Add routes in `main.py` with `verify_admin_key` dependency
- **New challenge metadata:** Extend `ChallengeConfig` in `docker_manager.py`
- **New event types:** Add to `EventType` enum in `logger.py`, log in appropriate handlers
- **New monitoring metrics:** Extend `MonitoringManager` data model
- **New settings:** Add to `EDITABLE_SETTINGS` dict and `_load_settings_from_db()` type map in `main.py`
- **New frontend pages:** Add component in `frontend/src/admin/pages/`, wire into `AdminApp.tsx` tabs

### High-Risk Modification Zones
- **Spawn/stop critical sections** in `docker_manager.py` — lock ordering and cleanup guarantees
- **Lock semantics** in `distributed_lock.py` — deadlock prevention, timeout behavior
- **Port allocation persistence** in `port_manager.py` — conflict safety guarantees
- **Dynamic flag ownership logic** in `flag_manager.py` — user vs team comparison paths
- **Traefik route registration** in `traefik_redis.py` — key naming and cleanup completeness

---

## Known Gaps

1. **Instance recovery:** Active instance state is held in memory; on restart, the in-memory map is lost. The `instance_states` ORM table exists but is not wired into active recovery flows.
2. **Auth IP trust asymmetry:** Admin IP extraction is trusted-proxy-aware; no-auth user identity uses forwarded headers directly.
3. **Platform assumptions:** Monitoring host metrics rely on Linux-specific interfaces (`/proc/meminfo`, `nproc`).
4. **Compose orchestration:** While many Docker operations use the SDK, compose lifecycle still shells out to `docker compose`, requiring Docker CLI availability.
5. **Flag manager logging:** Some `FlagManager` logging calls are invoked synchronously (missing `await`), which may result in log entries being silently dropped.
