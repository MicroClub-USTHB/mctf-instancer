"""Docker container management for challenge instances."""
import os
import re
import shutil
import yaml
import tempfile
import asyncio
import tomllib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
import uuid

from .config import settings
from .models import (
    ChallengeInfo, ChallengeType, Instance, InstanceStatus, UserInfo, utcnow
)
from .port_manager import PortManager
from .flag_manager import get_flag_manager
from .forensics import get_forensics_manager
from .discord_webhook import get_discord_notifier
from .distributed_lock import get_lock_manager
from .docker_client import get_docker_client, DockerError
from .traefik_redis import get_traefik_provider


class ChallengeConfig:
    """Challenge configuration loaded from disk."""
    
    def __init__(self, challenge_dir: Path):
        self.path = challenge_dir
        self.challenge_dir = challenge_dir / "challenge"
        self.config_file = challenge_dir / "instance.toml"
        # Support both .yaml and .yml extensions
        self.compose_file = self._find_compose_file(self.challenge_dir)
        self._config: Dict = {}
        self._load_config()
    
    def _find_compose_file(self, challenge_dir: Path) -> Path:
        """Find docker-compose file with either .yaml or .yml extension."""
        yaml_file = challenge_dir / "docker-compose.yaml"
        yml_file = challenge_dir / "docker-compose.yml"
        
        if yaml_file.exists():
            return yaml_file
        elif yml_file.exists():
            return yml_file
        else:
            # Return default path (will fail validation later)
            return yaml_file
    
    def _load_config(self) -> None:
        """Load challenge configuration."""
        if not self.config_file.exists():
            raise ValueError(f"Challenge config not found: {self.config_file}")
        
        with open(self.config_file, "rb") as f:
            self._config = tomllib.load(f)

        if not isinstance(self._config, dict):
            raise ValueError(f"Invalid instance.toml format for {self.path.name}")

    @staticmethod
    def _to_bool(value, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    @staticmethod
    def _normalize_command_map(command_map: Dict[Any, Any]) -> Dict[str, str]:
        normalized: Dict[str, str] = {}
        for key, value in command_map.items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            candidate = value.strip()
            if candidate:
                normalized[key.strip().lower()] = candidate
        return normalized
    
    @property
    def id(self) -> str:
        return self._config.get("id", self.path.name)
    
    @property
    def name(self) -> str:
        return self._config.get("name", self.path.name)
    
    @property
    def category(self) -> ChallengeType:
        cat = self._config.get("category", "misc").lower()
        try:
            return ChallengeType(cat)
        except ValueError:
            return ChallengeType.MISC
    
    @property
    def description(self) -> Optional[str]:
        return self._config.get("description")
    
    @property
    def ports(self) -> List[int]:
        """Get the internal ports that should be exposed."""
        return self._config.get("ports", [])
    
    @property
    def timeout(self) -> int:
        """Get instance timeout in seconds."""
        return self._config.get("timeout", settings.INSTANCE_TIMEOUT)

    @property
    def extend_time(self) -> int:
        """Get extend increment in seconds for each successful extend action."""
        value = self._config.get("extend_time", 1800)
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = 1800
        return max(0, parsed)

    @property
    def routing_type(self) -> str:
        """Routing type used to build Traefik routers (http/tcp/ssh/etc)."""
        route_type = str(self._config.get("type", "")).strip().lower()
        if route_type:
            return route_type

        # Backward compatibility: infer routing type from category when missing.
        if self.category == ChallengeType.WEB:
            return "http"
        return "tcp"

    @property
    def entrypoint(self) -> Optional[str]:
        """Optional dedicated Traefik entrypoint for non-standard TCP routes."""
        value = self._config.get("entrypoint")
        if value:
            return str(value)
        return None

    @property
    def tls_enabled(self) -> bool:
        """Whether Traefik should terminate TLS for this challenge route."""
        default = self.routing_type in ("http", "tcp")
        return self._to_bool(self._config.get("tls"), default)

    @property
    def tls_options(self) -> Optional[str]:
        """Optional Traefik TLS options name override."""
        value = self._config.get("tls_options")
        if value:
            return str(value)
        return None

    @property
    def disable_dynamic_flags(self) -> bool:
        """If True, dynamic flags are disabled for this challenge regardless of global setting."""
        return self._to_bool(self._config.get("disable_dynamic_flags"), False)

    @property
    def connection_command_template(self) -> Optional[str]:
        """Optional custom connection command template from instance.toml."""
        value = self._config.get("connection_command")

        if isinstance(value, str):
            template = value.strip()
            return template or None

        if isinstance(value, dict):
            command_map = self._normalize_command_map(value)
            if not command_map:
                return None

            match_order = [
                self.routing_type.lower(),
                self.category.value.lower(),
                "default",
            ]
            for key in match_order:
                candidate = command_map.get(key)
                if candidate:
                    return candidate

            # Fallback to first valid table entry.
            return next(iter(command_map.values()), None)

        return None
    
    def to_info(self) -> ChallengeInfo:
        """Convert to ChallengeInfo model."""
        return ChallengeInfo(
            id=self.id,
            name=self.name,
            category=self.category,
            routing_type=self.routing_type,
            entrypoint=self.entrypoint,
            tls_enabled=self.tls_enabled,
            description=self.description,
            ports=self.ports
        )


class DockerManager:
    """
    Manages Docker containers for challenge instances.
    
    Features:
    - Uses Docker SDK (docker-py) for container management
    - Creates isolated networks per instance
    - Uses distributed locking for safe concurrent spawns
    """
    
    def __init__(self, port_manager: PortManager):
        self.port_manager = port_manager
        self.challenges: Dict[str, ChallengeConfig] = {}
        self.instances: Dict[str, Instance] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

        # Distributed lock manager (replaces asyncio.Lock per user)
        self._lock_manager = get_lock_manager()

        # Global semaphore to limit concurrent spawns (prevent resource exhaustion)
        self._spawn_semaphore = asyncio.Semaphore(10)  # Max 10 concurrent spawns

        # Docker client (initialized lazily)
        self._docker = None
        self._traefik_provider = get_traefik_provider()

        # Per-challenge resource override cache (loaded from DB)
        self._challenge_resource_overrides: Dict[str, Dict] = {}

        # Inactive challenge IDs (loaded from DB)
        self._inactive_challenges: set = set()

        # Lifecycle hooks for real-time notifications (WebSocket, etc.)
        self._lifecycle_hooks: List[Callable] = []

    def add_lifecycle_hook(self, hook: Callable) -> None:
        """Register an async callback invoked on spawn/stop/extend/expire.

        Signature: hook(event: str, instance: Instance, **extra) -> None
        """
        self._lifecycle_hooks.append(hook)

    async def _fire_lifecycle_hook(self, event: str, instance: Instance, **extra: Any) -> None:
        for hook in self._lifecycle_hooks:
            try:
                await hook(event, instance, **extra)
            except Exception:
                pass
    
    @property
    def docker(self):
        """Get Docker client (lazy initialization)."""
        if self._docker is None:
            self._docker = get_docker_client()
        return self._docker
    
    def load_challenges(self) -> None:
        """Load all challenge configurations from the challenges directory."""
        challenges_path = Path(settings.CHALLENGES_DIR)
        
        if not challenges_path.exists():
            print(f"Challenges directory not found: {challenges_path}")
            return
        
        # Clear existing challenges before reloading
        self.challenges.clear()
        
        for item in challenges_path.iterdir():
            if item.is_dir():
                config_file = item / "instance.toml"
                # Support both .yaml and .yml extensions, inside the challenge/ subdir
                compose_yaml = item / "challenge" / "docker-compose.yaml"
                compose_yml = item / "challenge" / "docker-compose.yml"
                has_compose = compose_yaml.exists() or compose_yml.exists()
                
                if config_file.exists() and has_compose:
                    try:
                        config = ChallengeConfig(item)
                        self.challenges[config.id] = config
                        print(f"Loaded challenge: {config.name} ({config.id})")
                        # Lint the compose file for known footguns and warn.
                        compose_path = compose_yaml if compose_yaml.exists() else compose_yml
                        for warning in self._lint_compose_file(compose_path):
                            print(f"[Lint] {config.id}: {warning}")
                    except Exception as e:
                        print(f"Failed to load challenge from {item}: {e}")

    @staticmethod
    def _lint_compose_file(compose_path: Path) -> List[str]:
        """Inspect a challenge's docker-compose for known footguns.

        Returns a list of human-readable warnings. Non-fatal — the challenge
        still loads — but operators should see and fix these before peak load.

        Currently checks:
          - networks.<name>.ipam.config[*].subnet pinned. Per-spawn bridges
            create a fresh network each time, and Docker IPAM enforces
            non-overlapping subnets host-wide. A pinned subnet means at most
            one team can run this challenge at a time before subsequent
            spawns fail with `Pool overlaps with other one on this address
            space`. Bit nightmare on 2026-04-30.
          - services.<name>.networks.<net>.ipv4_address pinned. Same family
            of bug — only meaningful inside a pinned subnet.
        """
        warnings: List[str] = []
        try:
            with open(compose_path) as f:
                data = yaml.safe_load(f) or {}
        except Exception as exc:
            return [f"failed to parse {compose_path.name}: {exc}"]

        for net_name, net_cfg in (data.get("networks") or {}).items():
            if not isinstance(net_cfg, dict):
                continue
            ipam = net_cfg.get("ipam") or {}
            for entry in (ipam.get("config") or []):
                if isinstance(entry, dict) and entry.get("subnet"):
                    warnings.append(
                        f"network '{net_name}' pins subnet={entry['subnet']!r}; "
                        "this prevents parallel spawns (Pool overlaps). Remove "
                        "the ipam.config block and let Docker auto-allocate."
                    )

        for svc_name, svc_cfg in (data.get("services") or {}).items():
            if not isinstance(svc_cfg, dict):
                continue
            svc_nets = svc_cfg.get("networks")
            if not isinstance(svc_nets, dict):
                continue
            for net_name, net_attach in svc_nets.items():
                if isinstance(net_attach, dict) and net_attach.get("ipv4_address"):
                    warnings.append(
                        f"service '{svc_name}' pins ipv4_address on network "
                        f"'{net_name}'; only works alongside a pinned subnet, "
                        "which itself prevents parallel spawns. Use the service "
                        "name as a hostname instead (Docker embedded DNS)."
                    )

        return warnings
    
    def get_challenges(self) -> List[ChallengeInfo]:
        """Get list of all challenges (including inactive, for admin)."""
        return [c.to_info() for c in self.challenges.values()]
    
    def get_active_challenges(self) -> List[ChallengeInfo]:
        """Get list of active challenges only (for user dashboard)."""
        return [
            c.to_info() for c in self.challenges.values()
            if c.id not in self._inactive_challenges
        ]
    
    def is_challenge_active(self, challenge_id: str) -> bool:
        """Check if a challenge is active."""
        return challenge_id not in self._inactive_challenges
    
    async def load_challenge_settings(self) -> None:
        """Load challenge settings (active/inactive, resource overrides) from database."""
        try:
            from .database.connection import get_async_session
            from .database.models import ChallengeSettings
            from sqlalchemy import select
            
            async with get_async_session() as session:
                result = await session.execute(select(ChallengeSettings))
                settings_list = result.scalars().all()
            
            self._inactive_challenges.clear()
            self._challenge_resource_overrides.clear()
            
            for cs in settings_list:
                if cs.is_active == 0:
                    self._inactive_challenges.add(cs.challenge_id)
                overrides = {}
                if cs.max_memory:
                    overrides['max_memory'] = cs.max_memory
                if cs.max_cpu:
                    overrides['max_cpu'] = cs.max_cpu
                if overrides:
                    self._challenge_resource_overrides[cs.challenge_id] = overrides
            
            print(f"Loaded challenge settings: {len(self._inactive_challenges)} inactive, {len(self._challenge_resource_overrides)} with resource overrides")
        except Exception as e:
            print(f"Warning: Failed to load challenge settings from DB: {e}")
    
    def get_challenge(self, challenge_id: str) -> Optional[ChallengeConfig]:
        """Get a specific challenge configuration."""
        return self.challenges.get(challenge_id)
    
    def get_user_instances(self, user_id: str) -> List[Instance]:
        """Get all instances for a user."""
        return [i for i in self.instances.values() if i.user_id == user_id]
    
    def get_user_instance_count(self, user_id: str) -> int:
        """Get the count of active instances for a user."""
        return len([
            i for i in self.instances.values() 
            if i.user_id == user_id and i.status in [InstanceStatus.RUNNING, InstanceStatus.STARTING]
        ])
    
    def get_owner_instances(self, owner_id: str, team_mode: bool = False) -> List[Instance]:
        """
        Get all instances for an owner (team or user depending on mode).
        In team mode, owner_id is the team_id.
        In user mode, owner_id is the user_id.
        """
        if team_mode:
            return [i for i in self.instances.values() if i.team_id == owner_id]
        else:
            return [i for i in self.instances.values() if i.user_id == owner_id]
    
    def get_owner_instance_count(self, owner_id: str, team_mode: bool = False) -> int:
        """
        Get the count of active instances for an owner (team or user).
        """
        instances = self.get_owner_instances(owner_id, team_mode)
        return len([
            i for i in instances 
            if i.status in [InstanceStatus.RUNNING, InstanceStatus.STARTING]
        ])

    def _is_managed_instance_project_name(self, project_name: str) -> bool:
        """Check whether a compose project name matches Whaley instance naming."""
        try:
            challenge_prefix, owner_fragment, random_suffix = project_name.rsplit("-", 2)
        except ValueError:
            return False

        if challenge_prefix not in self.challenges:
            return False
        if not owner_fragment or len(owner_fragment) > 8:
            return False
        return bool(re.fullmatch(r"[0-9a-f]{8}", random_suffix))

    def get_disabled_flag_challenge_ids(self) -> set:
        """Return the set of challenge IDs that have per-challenge dynamic flags disabled."""
        return {
            cid for cid, cfg in self.challenges.items()
            if cfg.disable_dynamic_flags
        }

    @staticmethod
    def _is_port_conflict_error(error_message: str) -> bool:
        """Detect Docker bind failures caused by already allocated host ports."""
        lowered = error_message.lower()
        return (
            "port is already allocated" in lowered
            or "address already in use" in lowered
            or "bind for 0.0.0.0:" in lowered
            or ("listen tcp" in lowered and "bind" in lowered)
        )

    def _initialize_instance_connection_preview(
        self,
        challenge: ChallengeConfig,
        instance: Instance,
        route_internal_port: int,
        route_external_port: int,
    ) -> None:
        """Set provisional connection fields before containers and routes are up."""
        default_connection_hint: Optional[str] = None

        if settings.TRAEFIK_REDIS_ENABLED:
            fqdn = settings.get_instance_domain(instance.instance_id)
            if challenge.routing_type == "http":
                instance.public_url = f"https://{fqdn}"
                instance.public_urls = {route_internal_port: instance.public_url}
                default_connection_hint = instance.public_url
            elif challenge.routing_type == "tcp":
                instance.public_url = f"{fqdn}:{settings.TRAEFIK_TCP_EXTERNAL_PORT}"
                instance.public_urls = {route_internal_port: instance.public_url}
                default_connection_hint = f"ncat --ssl {fqdn} {settings.TRAEFIK_TCP_EXTERNAL_PORT}"
            else:
                instance.public_url = fqdn
                instance.public_urls = {route_internal_port: instance.public_url}
                if challenge.entrypoint:
                    default_connection_hint = (
                        f"{fqdn} via Traefik entrypoint {challenge.entrypoint}"
                    )
        else:
            public_host = settings.get_public_host()
            public_urls: Dict[int, str] = {}
            for internal_port, external_port in instance.ports.items():
                public_urls[internal_port] = f"{public_host}:{external_port}"
            instance.public_urls = public_urls
            if public_urls:
                instance.public_url = public_urls.get(route_internal_port)
                if not instance.public_url:
                    first_internal_port = list(instance.ports.keys())[0]
                    instance.public_url = public_urls[first_internal_port]
                default_connection_hint = instance.public_url

        instance.connection_hint = self._resolve_connection_hint(
            challenge=challenge,
            instance=instance,
            route_internal_port=route_internal_port,
            route_backend_port=route_external_port,
            default_connection=default_connection_hint,
        )

    async def cleanup_stale_instances_on_startup(self) -> Dict[str, int]:
        """Remove stale Whaley challenge projects left running before this process started."""
        summary = {
            "projects": 0,
            "containers": 0,
            "networks": 0,
            "volumes": 0,
            "routes": 0,
        }

        try:
            compose_projects = await self.docker.list_compose_projects()
        except Exception as exc:
            print(f"[Startup] Warning: failed to list compose projects: {exc}")
            return summary

        network_project_hints: set = set()
        try:
            whaley_networks = await self.docker.list_whaley_networks()
            network_prefix = f"{settings.NETWORK_PREFIX}-"
            for network in whaley_networks:
                network_name = network.get("name")
                if isinstance(network_name, str) and network_name.startswith(network_prefix):
                    network_project_hints.add(network_name[len(network_prefix):])
        except Exception as exc:
            print(f"[Startup] Warning: failed to list Whaley networks: {exc}")

        managed_projects: List[str] = []
        for project in compose_projects:
            project_name = project.get("project_name")
            if not project_name:
                continue

            labels_list = project.get("labels") or []
            has_managed_label = any(
                isinstance(labels, dict) and labels.get("whaley.managed") == "true"
                for labels in labels_list
            )
            has_instance_label = any(
                isinstance(labels, dict) and labels.get("whaley.instance_id") == project_name
                for labels in labels_list
            )

            has_whaley_network_hint = project_name in network_project_hints

            if (
                has_managed_label
                or has_instance_label
                or has_whaley_network_hint
                or self._is_managed_instance_project_name(project_name)
            ):
                managed_projects.append(project_name)

        managed_projects = sorted(set(managed_projects))
        if not managed_projects:
            print("[Startup] No stale Whaley challenge containers found")
            return summary

        print(f"[Startup] Cleaning {len(managed_projects)} stale Whaley project(s)")

        for project_name in managed_projects:
            try:
                cleaned = await self.docker.remove_compose_project(project_name, remove_volumes=True)
                summary["projects"] += 1
                summary["containers"] += cleaned.get("containers", 0)
                summary["networks"] += cleaned.get("networks", 0)
                summary["volumes"] += cleaned.get("volumes", 0)
                print(f"[Startup] Removed stale project {project_name}")
            except Exception as exc:
                print(f"[Startup] Warning: failed to remove project {project_name}: {exc}")
                continue

            try:
                await self._traefik_provider.delete_instance_route(project_name)
                summary["routes"] += 1
            except Exception:
                pass

            self.port_manager.release_instance_ports(project_name)
            self.instances.pop(project_name, None)

        print(
            "[Startup] Stale cleanup summary: "
            f"projects={summary['projects']} containers={summary['containers']} "
            f"networks={summary['networks']} volumes={summary['volumes']}"
        )

        # Final orphan sweep: catches networks/images that didn't belong to
        # a recognised compose project (e.g. labels stripped, image tags left
        # by failed teardowns). Pass empty active set since nothing is alive
        # at startup; older_than_seconds=0 since there are no in-flight spawns.
        try:
            extra = await self.docker.cleanup_whaley_resources(
                active_project_names=set(),
                older_than_seconds=0,
            )
            if extra.get("networks", 0) or extra.get("images", 0):
                print(
                    f"[Startup] Orphan sweep: networks={extra.get('networks',0)} "
                    f"images={extra.get('images',0)}"
                )
                summary["networks"] += extra.get("networks", 0)
                summary["images"] = extra.get("images", 0)
        except Exception as exc:
            print(f"[Startup] Warning: orphan sweep failed: {exc}")

        return summary

    @staticmethod
    def _render_connection_command_template(template: str, variables: Dict[str, str]) -> str:
        """Render connection command placeholders like {var} or ${var}."""

        def _replace(match: re.Match[str]) -> str:
            key = match.group(1)
            return variables.get(key, match.group(0))

        rendered = re.sub(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}", _replace, template)
        rendered = re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", _replace, rendered)
        return rendered

    def _resolve_connection_hint(
        self,
        challenge: ChallengeConfig,
        instance: Instance,
        route_internal_port: int,
        route_backend_port: int,
        default_connection: Optional[str],
    ) -> Optional[str]:
        """Resolve final connection hint using optional challenge command template."""
        template = challenge.connection_command_template
        if not template:
            return default_connection

        fqdn = settings.get_instance_domain(instance.instance_id)
        host = fqdn if settings.TRAEFIK_REDIS_ENABLED else settings.get_public_host()

        if settings.TRAEFIK_REDIS_ENABLED and challenge.routing_type == "tcp":
            public_port = str(settings.TRAEFIK_TCP_EXTERNAL_PORT)
        elif settings.TRAEFIK_REDIS_ENABLED and challenge.routing_type == "http":
            public_port = "443"
        elif settings.TRAEFIK_REDIS_ENABLED:
            public_port = ""
        else:
            public_port = str(route_backend_port)

        effective_port = public_port or str(route_backend_port)

        context = {
            "instance_id": instance.instance_id,
            "challenge_id": challenge.id,
            "challenge_name": challenge.name,
            "category": challenge.category.value,
            "routing_type": challenge.routing_type,
            "type": challenge.routing_type,
            "entrypoint": challenge.entrypoint or "",
            "host": host,
            "fqdn": fqdn,
            "port": effective_port,
            "public_port": public_port,
            "backend_port": str(route_backend_port),
            "internal_port": str(route_internal_port),
            "public_url": instance.public_url or "",
            "url": instance.public_url or "",
            "connection_string": default_connection or "",
            "connection_hint": default_connection or "",
            "connection": default_connection or "",
        }

        rendered = self._render_connection_command_template(template, context).strip()
        return rendered or default_connection
    
    async def spawn_instance(
        self, 
        challenge_id: str, 
        user_id: str,
        username: Optional[str] = None,
        user_info: Optional[UserInfo] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str, Optional[Instance]]:
        """
        Spawn a new challenge instance.
        
        Uses distributed locking for safe concurrent access.
        Creates isolated Docker network for the instance.
        
        In team mode:
        - Instance is owned by the team
        - Instance limit is per-team
        - Locking is per-team to prevent race conditions
        
        In user mode:
        - Instance is owned by the user
        - Instance limit is per-user
        - Locking is per-user
        """
        
        # Check if challenge exists (can be done outside lock)
        challenge = self.get_challenge(challenge_id)
        if not challenge:
            return False, f"Challenge not found: {challenge_id}", None
        
        # Determine owner_id for locking and limit checks
        if team_mode and user_info and user_info.team_id:
            owner_id = user_info.team_id
            max_instances = settings.MAX_INSTANCES_PER_TEAM
        else:
            owner_id = user_id
            max_instances = settings.MAX_INSTANCES_PER_USER
        
        # Acquire global semaphore to limit concurrent spawns
        async with self._spawn_semaphore:
            # Acquire distributed lock for this owner
            lock_name = f"spawn:{owner_id}"
            async with self._lock_manager.acquire(lock_name, timeout=60):
                # Check owner instance limit (inside lock to prevent race)
                if self.get_owner_instance_count(owner_id, team_mode) >= max_instances:
                    if team_mode:
                        return False, f"Your team has reached the maximum instance limit ({max_instances})", None
                    else:
                        return False, f"Maximum instances limit reached ({max_instances})", None
                
                # Check if owner already has this challenge running (inside lock)
                for instance in self.get_owner_instances(owner_id, team_mode):
                    if instance.challenge_id == challenge_id and instance.status == InstanceStatus.RUNNING:
                        if team_mode:
                            return False, "Your team already has this challenge running", None
                        else:
                            return False, "You already have this challenge running", None
                
                # Continue with spawn logic (now protected by lock)
                return await self._do_spawn_instance(
                    challenge_id, user_id, username, challenge,
                    user_info=user_info, team_mode=team_mode
                )
    
    async def _do_spawn_instance(
        self,
        challenge_id: str,
        user_id: str,
        username: Optional[str],
        challenge: ChallengeConfig,
        user_info: Optional[UserInfo] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str, Optional[Instance]]:
        """Internal method to perform the actual spawn (called within lock)."""
        
        # Determine owner_id for instance naming
        if team_mode and user_info and user_info.team_id:
            owner_id = user_info.team_id
            owner_name = user_info.team_name or f"team_{user_info.team_id}"
        else:
            owner_id = user_id
            owner_name = username or user_id
        
        # Generate instance ID
        instance_id = f"{challenge_id}-{owner_id[:8]}-{uuid.uuid4().hex[:8]}"

        if not challenge.ports:
            return False, f"Challenge '{challenge_id}' has no exposed ports configured", None
        
        # Generate network name for isolation
        network_name = None
        if settings.NETWORK_ISOLATION_ENABLED:
            network_name = f"{settings.NETWORK_PREFIX}-{instance_id}"

        route_internal_port = challenge.ports[0]
        
        # Create instance object with team info if applicable
        instance = Instance(
            instance_id=instance_id,
            challenge_id=challenge_id,
            user_id=user_id,
            username=username or user_id,
            routing_type=challenge.routing_type,
            status=InstanceStatus.STARTING,
            ports={},
            expires_at=utcnow() + timedelta(seconds=challenge.timeout),
            # Team mode fields
            team_id=user_info.team_id if team_mode and user_info else None,
            team_name=user_info.team_name if team_mode and user_info else None,
            owner_id=owner_id  # user_id in user mode, team_id in team mode
        )
        
        # Store network name
        if network_name:
            instance.network_name = network_name

        self.instances[instance_id] = instance
        
        # Create dynamic flag if enabled (and not disabled per-challenge)
        dynamic_flag = None
        if settings.DYNAMIC_FLAGS_ENABLED and settings.AUTH_MODE == "ctfd" and not challenge.disable_dynamic_flags:
            try:
                flag_mgr = await get_flag_manager()
                base_flag_content = self._extract_base_flag_content(challenge.challenge_dir, settings.FLAG_PREFIX)
                # In team mode, create flag for team; otherwise for user
                success, msg, flag_content = await flag_mgr.create_flag_for_owner(
                    local_challenge_id=challenge_id,
                    owner_id=owner_id,
                    owner_name=owner_name,
                    instance_id=instance_id,
                    team_mode=team_mode,
                    # Also pass user info for logging/tracking
                    user_id=user_id,
                    username=username or user_id,
                    team_id=user_info.team_id if user_info else None,
                    team_name=user_info.team_name if user_info else None,
                    base_flag_content=base_flag_content
                )
                if success:
                    dynamic_flag = flag_content
                    if team_mode:
                        print(f"Created dynamic flag for team {owner_name} on {challenge_id}")
                    else:
                        print(f"Created dynamic flag for {username} on {challenge_id}")
                else:
                    print(f"Failed to create dynamic flag: {msg}")
            except Exception as e:
                print(f"Error creating dynamic flag: {e}")

        max_port_retry_attempts = 3
        last_error = "Unknown error"

        # Start containers and then publish dynamic routes to Traefik.
        for attempt in range(1, max_port_retry_attempts + 1):
            port_mapping = await self.port_manager.allocate_ports_for_user(
                instance_id=instance_id,
                user_id=owner_id,
                challenge_id=challenge_id,
                internal_ports=challenge.ports,
                username=owner_name,
            )

            if port_mapping is None:
                last_error = "No available ports"
                break

            route_external_port = port_mapping.get(route_internal_port)
            if route_external_port is None:
                self.port_manager.release_instance_ports(instance_id)
                last_error = "Failed to determine backend port for Traefik route"
                break

            instance.status = InstanceStatus.STARTING
            instance.error_message = None
            instance.ports = port_mapping
            instance.container_ids = []
            instance.public_url = None
            instance.public_urls = {}
            self._initialize_instance_connection_preview(
                challenge=challenge,
                instance=instance,
                route_internal_port=route_internal_port,
                route_external_port=route_external_port,
            )

            try:
                await self._start_containers(instance, challenge, dynamic_flag=dynamic_flag)

                if settings.TRAEFIK_REDIS_ENABLED:
                    public_endpoint = await self._traefik_provider.register_instance_route(
                        instance_id=instance.instance_id,
                        route_type=challenge.routing_type,
                        backend_port=route_external_port,
                        dedicated_entrypoint=challenge.entrypoint,
                        tls_enabled=challenge.tls_enabled,
                        tls_options=challenge.tls_options,
                    )
                    instance.public_url = public_endpoint
                    instance.public_urls = {route_internal_port: public_endpoint}

                    default_connection_hint = instance.connection_hint
                    fqdn = settings.get_instance_domain(instance.instance_id)
                    if challenge.routing_type == "tcp":
                        default_connection_hint = f"ncat --ssl {fqdn} {settings.TRAEFIK_TCP_EXTERNAL_PORT}"
                    elif challenge.routing_type == "http":
                        default_connection_hint = public_endpoint

                    instance.connection_hint = self._resolve_connection_hint(
                        challenge=challenge,
                        instance=instance,
                        route_internal_port=route_internal_port,
                        route_backend_port=route_external_port,
                        default_connection=default_connection_hint,
                    )

                instance.status = InstanceStatus.RUNNING
                asyncio.create_task(self._fire_lifecycle_hook("instance_spawned", instance))
                return True, "Instance started successfully", instance
            except Exception as e:
                error_detail = str(e)
                last_error = error_detail
                instance.status = InstanceStatus.ERROR
                instance.error_message = error_detail

                # Best-effort cleanup for partially started compose projects and routes.
                try:
                    await self.docker.compose_down(
                        project_name=instance.instance_id,
                        compose_file=challenge.compose_file,
                        work_dir=challenge.challenge_dir,
                        remove_volumes=True,
                        remove_orphans=True,
                    )
                except Exception:
                    pass

                try:
                    await self._traefik_provider.delete_instance_route(instance.instance_id)
                except Exception:
                    pass

                self.port_manager.release_instance_ports(instance_id)

                # Cleanup network if created
                if network_name:
                    try:
                        await self.docker.remove_network(network_name, force=True)
                    except Exception:
                        pass

                if self._is_port_conflict_error(error_detail) and attempt < max_port_retry_attempts:
                    print(
                        f"[Spawn] Port conflict for {instance_id} "
                        f"(attempt {attempt}/{max_port_retry_attempts}), retrying with new port allocation"
                    )
                    continue

                break

        # Clean up instance from memory on terminal failure.
        self.instances.pop(instance_id, None)
        if last_error in ("No available ports", "Failed to determine backend port for Traefik route"):
            return False, last_error, None
        return False, f"Failed to start instance: {last_error}", None
    
    def _extract_base_flag_content(self, challenge_path: Path, flag_prefix: str) -> Optional[str]:
        """
        Scan challenge files for the first flag matching FLAG_PREFIX{...} and return
        the inner content (without prefix and braces). Returns None if not found.
        Priority: dedicated flag files > compose/Dockerfile > source files.
        """
        pattern = re.compile(rf'{re.escape(flag_prefix)}\{{([^}}]+)\}}', re.IGNORECASE)

        candidates: list = []
        for fname in ['flag', 'flag.txt']:
            p = challenge_path / fname
            if p.exists() and p.is_file():
                candidates.append(p)
        for fname in ['docker-compose.yaml', 'docker-compose.yml', 'Dockerfile']:
            p = challenge_path / fname
            if p.exists() and p.is_file():
                candidates.append(p)
        for ext in ['*.py', '*.js', '*.php', '*.html', '*.txt', '*.sh', '*.env', '*.c', '*.cpp', '*.go']:
            candidates.extend(challenge_path.rglob(ext))

        for filepath in candidates:
            try:
                content = filepath.read_text(encoding='utf-8')
                match = pattern.search(content)
                if match:
                    return match.group(1)
            except Exception:
                continue

        return None

    def _inject_flag_into_files(
        self,
        challenge_path: Path,
        dynamic_flag: str,
        flag_prefix: str = "FLAG"
    ) -> int:
        """
        Inject dynamic flag into challenge files.
        Scans for flag files and replaces placeholder flags with the dynamic flag.
        Returns count of replacements made.
        """
        import re
        
        replacements = 0
        
        # Pattern to match flags with the given prefix: PREFIX{...}
        # `[^}\n]+` (vs the old `[^}]+`) prevents the regex from bridging across
        # newlines when a flag template is missing its closing brace. Without
        # `\n` in the negation set, an unclosed `mctf{` on one line would match
        # forward into any later `}` in the file (e.g. `${some_var}` in a bash
        # script), and the substitution would corrupt unrelated source. Seen
        # in the wild on the right-there forensics challenge.
        flag_pattern = re.compile(
            rf'{re.escape(flag_prefix)}\{{[^}}\n]+\}}',
            re.IGNORECASE
        )
        
        # Files to scan for flag injection
        flag_files = ['flag', 'flag.txt']
        
        # Collect all files to process
        files_to_process = []
        
        # Recursively find ALL flag files in the entire challenge directory
        for fname in flag_files:
            # Find in root
            fpath = challenge_path / fname
            if fpath.exists() and fpath.is_file():
                files_to_process.append(fpath)
            # Find recursively in all subdirectories
            files_to_process.extend(challenge_path.rglob(fname))
        
        # Also find pattern-matched flag files recursively
        flag_patterns = ['flag-*', 'flag_*', '*.flag']
        for pattern in flag_patterns:
            files_to_process.extend(challenge_path.rglob(pattern))
        
        # Add config files in root
        config_files = ['docker-compose.yaml', 'docker-compose.yml', 'Dockerfile']
        for fname in config_files:
            fpath = challenge_path / fname
            if fpath.exists() and fpath.is_file():
                files_to_process.append(fpath)
        
        # Also find Dockerfile in subdirectories (for multi-container challenges)
        files_to_process.extend(challenge_path.rglob('Dockerfile'))
        files_to_process.extend(challenge_path.rglob('docker-compose.yml'))
        files_to_process.extend(challenge_path.rglob('docker-compose.yaml'))
        
        # Recursively check ALL subdirectories for source files containing flags
        for ext in ['*.py', '*.js', '*.php', '*.html', '*.txt', '*.sh', '*.env', '*.c', '*.cpp', '*.go']:
            files_to_process.extend(challenge_path.rglob(ext))
        
        # Remove duplicates
        files_to_process = list(set(files_to_process))
        
        for filepath in files_to_process:
            try:
                if not filepath.is_file():
                    continue
                    
                # Read file content
                try:
                    content = filepath.read_text(encoding='utf-8')
                except UnicodeDecodeError:
                    continue  # Skip binary files
                
                # Check if flag pattern exists
                if flag_pattern.search(content):
                    # Replace all flag occurrences
                    new_content = flag_pattern.sub(dynamic_flag, content)
                    
                    if new_content != content:
                        filepath.write_text(new_content, encoding='utf-8')
                        replacements += 1
                        print(f"Injected flag into: {filepath.relative_to(challenge_path)}")
                        
            except Exception as e:
                print(f"Error processing {filepath}: {e}")
        
        return replacements
    
    def _enforce_resource_limits(
        self,
        compose_file: Path,
        challenge_id: str
    ) -> None:
        """
        Enforce maximum resource limits into a docker-compose file.
        
        Reads the compose file, checks each service's resource settings,
        and caps them at the global or per-challenge maximum.
        Also adds pids_limit for fork bomb protection.
        """
        try:
            with open(compose_file) as f:
                compose_data = yaml.safe_load(f)
            
            if not compose_data or 'services' not in compose_data:
                return
            
            # Get per-challenge overrides from DB cache
            challenge_limits = self._challenge_resource_overrides.get(challenge_id, {})
            
            max_memory = challenge_limits.get('max_memory') or settings.CONTAINER_MAX_MEMORY
            max_cpu = float(challenge_limits.get('max_cpu') or settings.CONTAINER_MAX_CPU)
            pids_limit = settings.CONTAINER_PIDS_LIMIT
            
            modified = False
            for service_name, service_config in compose_data.get('services', {}).items():
                if not isinstance(service_config, dict):
                    continue
                
                # Enforce memory limit
                if max_memory:
                    current_mem = service_config.get('mem_limit')
                    if not current_mem or self._parse_memory(str(current_mem)) > self._parse_memory(max_memory):
                        service_config['mem_limit'] = max_memory
                        modified = True
                    # Also set memswap_limit equal to mem_limit to prevent swap usage
                    service_config['memswap_limit'] = service_config.get('mem_limit', max_memory)
                
                # Enforce CPU limit
                if max_cpu > 0:
                    current_cpu = service_config.get('cpus')
                    if current_cpu is None or float(current_cpu) > max_cpu:
                        service_config['cpus'] = max_cpu
                        modified = True
                
                # Enforce PID limit (fork bomb protection)
                if pids_limit > 0:
                    service_config['pids_limit'] = pids_limit
                    modified = True
            
            if modified:
                with open(compose_file, 'w') as f:
                    yaml.dump(compose_data, f, default_flow_style=False)
                print(f"Enforced resource limits for {challenge_id}: mem={max_memory}, cpu={max_cpu}, pids={pids_limit}")
        
        except Exception as e:
            print(f"Warning: Failed to enforce resource limits: {e}")
    
    @staticmethod
    def _parse_memory(mem_str: str) -> int:
        """Parse memory string (e.g., '256m', '1g') to bytes."""
        mem_str = str(mem_str).strip().lower()
        multipliers = {'b': 1, 'k': 1024, 'm': 1024**2, 'g': 1024**3}
        if mem_str[-1] in multipliers:
            return int(float(mem_str[:-1]) * multipliers[mem_str[-1]])
        return int(mem_str)

    def _inject_whaley_labels_into_compose(self, compose_file: Path, instance: Instance) -> None:
        """Inject labels into compose services so Whaley can recover/cleanup by ownership."""
        try:
            with open(compose_file) as f:
                compose_data = yaml.safe_load(f)

            if not compose_data or "services" not in compose_data:
                return

            managed_labels = {
                "whaley.managed": "true",
                "whaley.instance_id": instance.instance_id,
                "whaley.challenge_id": instance.challenge_id,
            }

            modified = False
            for service_config in compose_data.get("services", {}).values():
                if not isinstance(service_config, dict):
                    continue

                labels = service_config.get("labels")
                if isinstance(labels, dict):
                    for key, value in managed_labels.items():
                        if labels.get(key) != value:
                            labels[key] = value
                            modified = True
                    continue

                if isinstance(labels, list):
                    passthrough: List[str] = []
                    mapped: Dict[str, str] = {}
                    for item in labels:
                        if not isinstance(item, str):
                            continue
                        if "=" not in item:
                            passthrough.append(item)
                            continue
                        key, value = item.split("=", 1)
                        mapped[key] = value

                    service_modified = False
                    for key, value in managed_labels.items():
                        if mapped.get(key) != value:
                            mapped[key] = value
                            service_modified = True

                    if service_modified:
                        modified = True
                        service_config["labels"] = passthrough + [
                            f"{key}={value}" for key, value in mapped.items()
                        ]
                    continue

                service_config["labels"] = managed_labels.copy()
                modified = True

            if modified:
                with open(compose_file, "w") as f:
                    yaml.dump(compose_data, f, default_flow_style=False)

        except Exception as e:
            print(f"Warning: Failed to inject Whaley labels: {e}")

    async def _start_containers(
        self, 
        instance: Instance, 
        challenge: ChallengeConfig,
        dynamic_flag: Optional[str] = None
    ) -> None:
        """Start Docker containers for an instance using docker-compose."""
        
        # Determine working directory and compose file path
        # Always create a temp copy to inject resource limits and/or flags
        work_dir = challenge.challenge_dir
        compose_file = challenge.compose_file
        temp_dir = None

        # Always use a temp copy so per-instance labels and runtime mutations never touch source files.
        needs_temp = True

        if needs_temp:
            try:
                # Create a temporary copy of the challenge directory to prevent race conditions
                # when multiple users spawn the same challenge simultaneously
                temp_dir = tempfile.mkdtemp(prefix=f"challenge_{instance.instance_id}_")
                temp_path = Path(temp_dir)

                # Copy challenge files to temp directory
                shutil.copytree(challenge.challenge_dir, temp_path / "challenge", dirs_exist_ok=True)
                work_dir = temp_path / "challenge"
                compose_file = work_dir / challenge.compose_file.name
                
                # Inject dynamic flag if provided
                if dynamic_flag:
                    count = self._inject_flag_into_files(
                        work_dir,
                        dynamic_flag,
                        settings.FLAG_PREFIX
                    )
                    if count > 0:
                        print(f"Injected flag into {count} files for {instance.instance_id}")

                # Inject ownership labels so stale containers can be discovered after restarts.
                self._inject_whaley_labels_into_compose(compose_file, instance)
                
                # Enforce resource limits into compose file
                self._enforce_resource_limits(compose_file, instance.challenge_id)
                
            except Exception as e:
                print(f"Temp dir setup error: {e}")
                # Cleanup temp dir on error
                if temp_dir:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                raise
        
        # Create isolated network if enabled
        network_name = getattr(instance, 'network_name', None)
        if settings.NETWORK_ISOLATION_ENABLED and network_name:
            try:
                await self.docker.create_isolated_network(
                    network_name=network_name,
                    enable_icc=not settings.NETWORK_ICC_DISABLED
                )
                print(f"Created isolated network: {network_name}")
            except DockerError as e:
                print(f"Warning: Failed to create isolated network: {e}")
                # Continue with default network
                network_name = None
        
        # Build environment with port mappings
        env = os.environ.copy()
        env["INSTANCE_ID"] = instance.instance_id
        
        for internal_port, external_port in instance.ports.items():
            env[f"PORT_{internal_port}"] = str(external_port)
        
        # Add dynamic flag to environment if provided
        if dynamic_flag:
            env["FLAG"] = dynamic_flag
            env["DYNAMIC_FLAG"] = dynamic_flag
        
        # Add network to environment if using isolation
        if network_name:
            env["DOCKER_NETWORK"] = network_name
        
        try:
            # Use Docker SDK for compose operations
            container_ids, output = await self.docker.compose_up(
                project_name=instance.instance_id,
                compose_file=compose_file,
                work_dir=work_dir,
                environment=env,
                network_name=network_name or settings.DOCKER_NETWORK,
                build=True
            )
            
            instance.container_ids = container_ids
            
        finally:
            # Clean up temporary directory after build completes
            # The image is built, so we don't need the temp files anymore
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def stop_instance(
        self, 
        instance_id: str, 
        user_id: Optional[str] = None,
        team_id: Optional[str] = None,
        team_mode: bool = False,
        terminate_reason: str = "user_stop",
    ) -> Tuple[bool, str]:
        """
        Stop and remove a challenge instance.
        
        In team mode, checks team ownership instead of user ownership.
        terminate_reason controls forensics metadata (user_stop/admin_stop/expired).
        """
        
        instance = self.instances.get(instance_id)
        if not instance:
            return False, "Instance not found"
        
        # Check ownership based on mode
        if team_mode:
            # In team mode, any team member can stop their team's instance
            if team_id and instance.team_id != team_id:
                return False, "Your team doesn't own this instance"
        else:
            # In user mode, only the user who created can stop
            if user_id and instance.user_id != user_id:
                return False, "You don't own this instance"
        
        challenge = self.get_challenge(instance.challenge_id)
        if not challenge:
            return False, "Challenge configuration not found"
        
        instance.status = InstanceStatus.STOPPING
        
        # Capture logs before stopping (Instance Forensics - Auto Capture)
        try:
            forensics = get_forensics_manager()
            if forensics.auto_capture_enabled:
                await forensics.capture_instance_logs(
                    instance_id=instance.instance_id,
                    project_name=instance.instance_id,
                    challenge_id=instance.challenge_id,
                    challenge_name=challenge.name,
                    owner_id=instance.owner_id or instance.user_id,
                    owner_name=instance.team_name or instance.username,
                    spawned_by=instance.username,
                    terminate_reason=terminate_reason,
                    team_id=instance.team_id,
                    team_name=instance.team_name,
                    capture_type="auto"
                )
        except Exception as e:
            print(f"[Forensics] Auto capture failed for {instance.instance_id}: {e}")
        
        try:
            # Use Docker SDK for compose down
            await self.docker.compose_down(
                project_name=instance.instance_id,
                compose_file=challenge.compose_file,
                work_dir=challenge.challenge_dir,
                remove_volumes=True,
                remove_orphans=True
            )

            route_cleanup_warning = None
            if settings.TRAEFIK_REDIS_ENABLED:
                try:
                    await self._traefik_provider.delete_instance_route(instance.instance_id)
                except Exception as exc:
                    route_cleanup_warning = f"Traefik key cleanup warning: {exc}"
                    print(f"[TraefikRedis] {route_cleanup_warning}")
            
            # Remove isolated network if created
            network_name = getattr(instance, 'network_name', None)
            if network_name:
                try:
                    await self.docker.remove_network(network_name, force=True)
                    print(f"Removed isolated network: {network_name}")
                except Exception as e:
                    print(f"Warning: Failed to remove network {network_name}: {e}")

            # Cleanup per-spawn images and any compose-created networks/volumes
            # that compose-down may have missed. Safe by-project-name filter so
            # base images (nginx:alpine, python:..., redis:...) are never touched.
            try:
                cleaned = await self.docker.remove_compose_project(
                    project_name=instance_id,
                    remove_volumes=True,
                )
                summary_bits = [f"{k}={v}" for k, v in cleaned.items() if v > 0]
                if summary_bits:
                    print(f"[Cleanup] Post-stop sweep for {instance_id}: {' '.join(summary_bits)}")
            except Exception as e:
                print(f"Warning: post-stop sweep failed for {instance_id}: {e}")

            # Release ports
            self.port_manager.release_instance_ports(instance_id)

            # Capture instance data for lifecycle hook before removal
            stopped_instance = instance
            asyncio.create_task(
                self._fire_lifecycle_hook("instance_stopped", stopped_instance)
            )

            # Remove from tracking
            instance.status = InstanceStatus.STOPPED
            del self.instances[instance_id]

            if route_cleanup_warning:
                return True, f"Instance stopped successfully ({route_cleanup_warning})"
            return True, "Instance stopped successfully"
            
        except Exception as e:
            return False, f"Failed to stop instance: {str(e)}"
    
    async def extend_instance(
        self, 
        instance_id: str, 
        user_id: str, 
        team_id: Optional[str] = None,
        team_mode: bool = False
    ) -> Tuple[bool, str, int]:
        """
        Extend the lifetime of an instance.

        Rules:
        - Extend step is configured per challenge via instance.toml (extend_time).
        - Extend is only allowed after at least half of timeout elapsed.
        - Total added extension time cannot exceed challenge timeout.

        In team mode, any team member can extend their team's instance.
        """

        instance = self.instances.get(instance_id)
        if not instance:
            return False, "Instance not found", 0

        # Check ownership based on mode
        if team_mode:
            if team_id and instance.team_id != team_id:
                return False, "Your team doesn't own this instance", 0
        else:
            if instance.user_id != user_id:
                return False, "You don't own this instance", 0

        if instance.status != InstanceStatus.RUNNING:
            return False, "Only running instances can be extended", 0

        challenge = self.get_challenge(instance.challenge_id)
        if not challenge:
            return False, "Challenge configuration not found", 0

        timeout_seconds = max(1, int(challenge.timeout))
        extend_step = int(challenge.extend_time)

        if extend_step <= 0:
            return False, "Extension is disabled for this challenge", 0

        now = utcnow()
        elapsed_seconds = max(0, int((now - instance.created_at).total_seconds()))
        required_elapsed = timeout_seconds // 2
        if elapsed_seconds < required_elapsed:
            wait_seconds = required_elapsed - elapsed_seconds
            return (
                False,
                f"Extension available in {wait_seconds}s (requires at least half timeout elapsed)",
                0,
            )

        base_expiry = instance.created_at + timedelta(seconds=timeout_seconds)
        used_extension = max(0, int((instance.expires_at - base_expiry).total_seconds()))
        remaining_extension_budget = max(0, timeout_seconds - used_extension)

        if remaining_extension_budget <= 0:
            return False, f"Extension limit reached (max extra {timeout_seconds}s)", 0

        applied_extension = min(extend_step, remaining_extension_budget)
        instance.expires_at = instance.expires_at + timedelta(seconds=applied_extension)

        asyncio.create_task(self._fire_lifecycle_hook("instance_extended", instance))

        remaining_after = remaining_extension_budget - applied_extension
        return (
            True,
            f"Instance extended by {applied_extension}s ({remaining_after}s extension budget left)",
            applied_extension,
        )
    
    async def cleanup_expired(self) -> None:
        """Clean up expired instances."""
        now = utcnow()
        expired = [
            i for i in self.instances.values()
            if i.expires_at < now and i.status == InstanceStatus.RUNNING
        ]
        
        for instance in expired:
            print(f"Cleaning up expired instance: {instance.instance_id}")

            challenge = self.get_challenge(instance.challenge_id)
            success, message = await self.stop_instance(
                instance_id=instance.instance_id,
                terminate_reason="expired",
            )

            if not success:
                print(f"[Cleanup] Failed to stop expired instance {instance.instance_id}: {message}")
                continue

            try:
                from .logger import get_event_logger

                logger = get_event_logger()
                await logger.log_instance_expired(
                    instance_id=instance.instance_id,
                    challenge_id=instance.challenge_id,
                    user_id=instance.user_id,
                )
            except Exception as exc:
                print(f"[Cleanup] Failed to log expiry for {instance.instance_id}: {exc}")

            try:
                notifier = get_discord_notifier()
                await notifier.notify_instance_stopped(
                    instance_id=instance.instance_id,
                    challenge_id=instance.challenge_id,
                    challenge_name=challenge.name if challenge else None,
                    stopped_by="system",
                    reason="expired",
                    owner_username=instance.username,
                    owner_user_id=instance.user_id,
                    team_id=instance.team_id,
                    team_name=instance.team_name,
                    message=message,
                )
            except Exception as exc:
                print(f"[Cleanup] Failed to send webhook for {instance.instance_id}: {exc}")
    
    async def start_cleanup_task(self) -> None:
        """Start the background cleanup task."""
        async def cleanup_loop():
            cleanup_counter = 0
            while True:
                await asyncio.sleep(60)  # Check every minute
                await self.cleanup_expired()

                cleanup_counter += 1

                # Every 10 iterations (~10 min): orphan sweep for networks + per-spawn
                # images that survived a failed teardown. 5-min safety window protects
                # in-flight spawns.
                if cleanup_counter % 10 == 0:
                    try:
                        active = set(self.instances.keys())
                        cleaned = await self.docker.cleanup_whaley_resources(
                            active_project_names=active,
                            older_than_seconds=300,
                        )
                        if cleaned.get("networks", 0) or cleaned.get("images", 0):
                            print(f"[Docker] Orphan sweep: networks={cleaned.get('networks',0)} images={cleaned.get('images',0)}")
                    except Exception as e:
                        print(f"[Docker] Orphan sweep failed: {e}")

                # Forensics log cleanup every hour (60 iterations)
                if cleanup_counter >= 60:
                    cleanup_counter = 0
                    try:
                        forensics = get_forensics_manager()
                        await forensics.cleanup_old_logs()
                    except Exception as e:
                        print(f"[Forensics] Log cleanup failed: {e}")

        self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
