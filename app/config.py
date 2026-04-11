"""Configuration settings for the instancer."""
import os
import socket
import httpx
from typing import Optional
from pydantic_settings import BaseSettings


def get_public_ip() -> str:
    """Try to detect public IP address."""
    # Try external services first
    ip_services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
        "https://ipecho.net/plain",
    ]
    
    for service in ip_services:
        try:
            response = httpx.get(service, timeout=3.0)
            if response.status_code == 200:
                ip = response.text.strip()
                if ip:
                    return ip
        except Exception:
            continue
    
    # Fallback: try to get local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    
    # Final fallback
    return "localhost"


class Settings(BaseSettings):
    """Application settings."""
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Instance settings
    INSTANCE_TIMEOUT: int = 3600  # 1 hour default timeout
    MAX_INSTANCES_PER_USER: int = 3
    MAX_INSTANCES_PER_TEAM: int = 5  # Team limit (typically higher than user)
    
    # Team mode settings
    # "auto" = detect from CTFd, "enabled" = force team mode, "disabled" = force user mode
    TEAM_MODE: str = "auto"
    
    # Port range for instances
    PORT_RANGE_START: int = 30000
    PORT_RANGE_END: int = 40000
    
    # Docker settings
    DOCKER_NETWORK: str = "ctf-instances"
    
    # Container resource limits (enforced on all instances)
    CONTAINER_MAX_MEMORY: str = "512m"  # Max memory per container (e.g., "256m", "1g")
    CONTAINER_MAX_CPU: float = 1.0  # Max CPU cores per container (e.g., 0.5, 1.0)
    CONTAINER_PIDS_LIMIT: int = 256  # Max PIDs per container (fork bomb protection)
    
    # Authentication settings
    AUTH_MODE: str = "ctfd"  # "ctfd" or "none"
    CTFD_URL: Optional[str] = None
    CTFD_API_KEY: Optional[str] = None  # Admin API key for validation
    
    # Dynamic flag settings
    DYNAMIC_FLAGS_ENABLED: bool = False  # Enable per-user dynamic flags
    FLAG_PREFIX: str = "FLAG"  # Prefix for generated flags
    
    # Admin dashboard settings
    ADMIN_KEY: Optional[str] = None  # Secret key for admin dashboard access
    METRICS_SECRET: Optional[str] = None  # Bearer secret for /metrics endpoint
    DISCORD_WEBHOOK_URL: Optional[str] = None  # Discord webhook for lifecycle notifications

    # URL path segment under which the admin dashboard HTML is served.
    # Set to a hard-to-guess token (e.g. ADMIN_PATH=admin-<hex>) to keep the
    # dashboard URL out of crawlers / wordlists. Default "admin" preserves
    # backward compatibility. Note: this only hides the dashboard *page* —
    # the /admin/api/* endpoints still live at their canonical paths and are
    # protected by ADMIN_KEY + per-IP rate limit, not by URL obscurity.
    ADMIN_PATH: str = "admin"

    # Rate limiting for admin endpoints (requests per minute)
    ADMIN_RATE_LIMIT: int = 150  # Max requests per minute per IP
    
    # Instance Forensics settings (Docker log capture)
    # Auto Capture: automatically dump logs when instance terminates
    FORENSICS_AUTO_CAPTURE: bool = False  # OFF by default (can be toggled via admin panel)
    # Log size limits
    FORENSICS_MAX_SIZE_MB: int = 5  # Max log size per instance (MB)
    FORENSICS_TAIL_LINES: int = 1000  # Max lines to capture per container
    # Retention
    FORENSICS_RETENTION_HOURS: int = 168  # Auto-delete logs older than this (168 = 7 days)
    # Compression
    FORENSICS_COMPRESSION: bool = True  # Compress logs with gzip
    # Storage path
    FORENSICS_LOG_DIR: str = "/app/logs/forensics"
    
    # Trusted proxies for X-Forwarded-For header
    # Only trust these IPs to set forwarded headers (prevents IP spoofing)
    # Use comma-separated values, e.g., "127.0.0.1,10.0.0.1" or "*" to trust all (not recommended)
    TRUSTED_PROXIES: str = "127.0.0.1,::1,10.0.0.2"
    
    # Challenge configs directory
    CHALLENGES_DIR: str = "/challenges"
    
    # Database settings (SQLite by default, can use PostgreSQL)
    DATABASE_URL: Optional[str] = None  # e.g., sqlite+aiosqlite:///./data/whaley.db
    DATA_DIR: str = "/app/data"  # Directory for SQLite database
    
    # Redis for distributed locking and state management
    REDIS_URL: Optional[str] = None  # e.g., redis://localhost:6379/0

    # Traefik Redis KV provider settings
    TRAEFIK_REDIS_ENABLED: bool = True
    TRAEFIK_REDIS_URL: Optional[str] = None  # Falls back to REDIS_URL when empty
    TRAEFIK_REDIS_KEY_PREFIX: str = "traefik"
    TRAEFIK_BASE_DOMAIN: str = "ctf.example"
    TRAEFIK_BACKEND_HOST: str = "challenges-vm"
    TRAEFIK_HTTP_ENTRYPOINT: str = "websecure"
    TRAEFIK_TCP_ENTRYPOINT: str = "tcp-challenges"
    TRAEFIK_TCP_EXTERNAL_PORT: int = 5443
    TRAEFIK_HTTP_TLS_OPTIONS: str = "default"
    TRAEFIK_TCP_TLS_OPTIONS: str = "default"
    TRAEFIK_BLOCK_ALL_ADDRESS: str = "127.0.0.1:9"
    TRAEFIK_DASHBOARD_USERS: Optional[str] = None
    TRAEFIK_PERMANENT_KEYS_FILE: Optional[str] = None
    TRAEFIK_PERMANENT_KEYS_JSON: Optional[str] = None
    
    # Network isolation settings
    NETWORK_ISOLATION_ENABLED: bool = True  # Create isolated network per instance
    NETWORK_ICC_DISABLED: bool = True  # Disable inter-container communication
    NETWORK_PREFIX: str = "whaley"  # Prefix for instance networks
    
    # Public URL for instance access (auto-detect if "auto" or empty)
    PUBLIC_HOST: str = "auto"
    
    # Logging
    LOG_FILE: str = "/app/logs/events.jsonl"
    USER_PORTS_FILE: str = "/app/logs/user_ports.json"
    
    def get_public_host(self) -> str:
        """Get the public host, auto-detecting if needed."""
        if self.PUBLIC_HOST and self.PUBLIC_HOST.lower() not in ("auto", ""):
            return self.PUBLIC_HOST
        return get_public_ip()

    def get_traefik_redis_url(self) -> Optional[str]:
        """Resolve Traefik Redis URL with REDIS_URL fallback."""
        return self.TRAEFIK_REDIS_URL or self.REDIS_URL

    def get_instance_domain(self, instance_id: str) -> str:
        """Build instance FQDN using the configured base domain."""
        return f"{instance_id}.{self.TRAEFIK_BASE_DOMAIN}"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
