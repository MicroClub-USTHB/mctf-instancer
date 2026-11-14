"""
Docker container resource monitoring for Whaley.

Provides real-time CPU and memory metrics for:
- Individual container instances
- Total system overhead
- Resource usage trends
"""
import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime, timezone

from .docker_client import get_docker_client


def utcnow() -> datetime:
    """Get current UTC time."""
    return datetime.now(timezone.utc)


@dataclass
class ContainerMetrics:
    """Resource metrics for a single container."""
    container_id: str
    container_name: str
    cpu_percent: float
    memory_usage_mb: float
    memory_limit_mb: float
    memory_percent: float
    network_rx_mb: float
    network_tx_mb: float
    block_read_mb: float
    block_write_mb: float
    pids: int


@dataclass
class InstanceMetrics:
    """Aggregated metrics for a challenge instance (all its containers)."""
    instance_id: str
    challenge_id: str
    challenge_name: str
    owner_id: str
    owner_name: str
    container_count: int
    total_cpu_percent: float
    total_memory_mb: float
    containers: List[ContainerMetrics]
    timestamp: str


@dataclass
class SystemMetrics:
    """Overall system metrics."""
    total_containers: int
    running_containers: int
    total_cpu_percent: float
    total_memory_mb: float
    host_cpu_cores: int
    host_memory_total_mb: float
    host_memory_used_mb: float
    host_memory_percent: float
    timestamp: str


class MonitoringManager:
    """
    Manages Docker container resource monitoring.
    
    Uses `docker stats` command to collect real-time metrics.
    """
    
    def __init__(self):
        self._cache_ttl = 2  # Cache metrics for 2 seconds
        self._last_update: Optional[datetime] = None
        self._cached_metrics: Dict[str, ContainerMetrics] = {}
    
    async def get_container_metrics(self, container_ids: List[str]) -> Dict[str, ContainerMetrics]:
        """
        Get metrics for specific containers using Docker SDK.
        
        Args:
            container_ids: List of container IDs to monitor
            
        Returns:
            Dict mapping container_id to ContainerMetrics
        """
        if not container_ids:
            return {}
        
        try:
            docker_client = get_docker_client()
            metrics = {}
            
            for container_id in container_ids:
                try:
                    # Get container stats (stream=False for single snapshot)
                    stats = await docker_client.get_container_stats(container_id, stream=False)
                    
                    if not stats:
                        continue
                    
                    # Calculate CPU percentage
                    cpu_percent = self._calculate_cpu_percent(stats)
                    
                    # Parse memory
                    memory_stats = stats.get('memory_stats', {})
                    memory_usage = memory_stats.get('usage', 0)
                    memory_limit = memory_stats.get('limit', 0)
                    
                    memory_usage_mb = memory_usage / (1024 * 1024)
                    memory_limit_mb = memory_limit / (1024 * 1024)
                    memory_percent = (memory_usage / memory_limit * 100) if memory_limit > 0 else 0.0
                    
                    # Parse network I/O
                    networks = stats.get('networks', {})
                    network_rx = sum(net.get('rx_bytes', 0) for net in networks.values())
                    network_tx = sum(net.get('tx_bytes', 0) for net in networks.values())
                    network_rx_mb = network_rx / (1024 * 1024)
                    network_tx_mb = network_tx / (1024 * 1024)
                    
                    # Parse block I/O
                    blkio_stats = stats.get('blkio_stats', {})
                    io_service_bytes = blkio_stats.get('io_service_bytes_recursive', [])
                    block_read = sum(entry.get('value', 0) for entry in io_service_bytes if entry.get('op') == 'Read')
                    block_write = sum(entry.get('value', 0) for entry in io_service_bytes if entry.get('op') == 'Write')
                    block_read_mb = block_read / (1024 * 1024)
                    block_write_mb = block_write / (1024 * 1024)
                    
                    # PIDs
                    pids_stats = stats.get('pids_stats', {})
                    pids = pids_stats.get('current', 0)
                    
                    # Get container name
                    container_name = stats.get('name', container_id[:12])
                    if container_name.startswith('/'):
                        container_name = container_name[1:]
                    
                    metrics[container_id[:12]] = ContainerMetrics(
                        container_id=container_id[:12],
                        container_name=container_name,
                        cpu_percent=round(cpu_percent, 2),
                        memory_usage_mb=round(memory_usage_mb, 2),
                        memory_limit_mb=round(memory_limit_mb, 2),
                        memory_percent=round(memory_percent, 2),
                        network_rx_mb=round(network_rx_mb, 2),
                        network_tx_mb=round(network_tx_mb, 2),
                        block_read_mb=round(block_read_mb, 2),
                        block_write_mb=round(block_write_mb, 2),
                        pids=pids
                    )
                    
                except Exception as e:
                    print(f"[Monitoring] Failed to get stats for container {container_id[:12]}: {e}")
                    continue
            
            return metrics
            
        except Exception as e:
            print(f"[Monitoring] Error getting container metrics: {e}")
            return {}
    
    def _calculate_cpu_percent(self, stats: dict) -> float:
        """
        Calculate CPU percentage from Docker stats.
        
        Docker calculates CPU % as:
        (cpu_delta / system_cpu_delta) * number_cpus * 100
        """
        try:
            cpu_stats = stats.get('cpu_stats', {})
            precpu_stats = stats.get('precpu_stats', {})
            
            cpu_delta = cpu_stats.get('cpu_usage', {}).get('total_usage', 0) - \
                       precpu_stats.get('cpu_usage', {}).get('total_usage', 0)
            
            system_delta = cpu_stats.get('system_cpu_usage', 0) - \
                          precpu_stats.get('system_cpu_usage', 0)
            
            if system_delta > 0 and cpu_delta > 0:
                # Get number of CPUs
                online_cpus = cpu_stats.get('online_cpus', len(cpu_stats.get('cpu_usage', {}).get('percpu_usage', [1])))
                if online_cpus == 0:
                    online_cpus = 1
                
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
                return cpu_percent
            
            return 0.0
        except Exception as e:
            print(f"[Monitoring] Error calculating CPU: {e}")
            return 0.0
    
    async def get_instance_metrics(
        self,
        instance_id: str,
        challenge_id: str,
        challenge_name: str,
        owner_id: str,
        owner_name: str,
        container_ids: List[str]
    ) -> Optional[InstanceMetrics]:
        """
        Get aggregated metrics for a challenge instance.
        
        Args:
            instance_id: Instance identifier
            challenge_id: Challenge ID
            challenge_name: Challenge name
            owner_id: Owner ID
            owner_name: Owner name
            container_ids: List of container IDs in this instance
            
        Returns:
            InstanceMetrics or None if failed
        """
        if not container_ids:
            return None
        
        container_metrics = await self.get_container_metrics(container_ids)
        
        if not container_metrics:
            return None
        
        # Aggregate metrics
        total_cpu = sum(m.cpu_percent for m in container_metrics.values())
        total_memory = sum(m.memory_usage_mb for m in container_metrics.values())
        
        return InstanceMetrics(
            instance_id=instance_id,
            challenge_id=challenge_id,
            challenge_name=challenge_name,
            owner_id=owner_id,
            owner_name=owner_name,
            container_count=len(container_metrics),
            total_cpu_percent=round(total_cpu, 2),
            total_memory_mb=round(total_memory, 2),
            containers=list(container_metrics.values()),
            timestamp=utcnow().isoformat()
        )
    
    async def get_system_metrics(self) -> SystemMetrics:
        """
        Get overall system metrics using Docker SDK.
        Excludes Whaley infrastructure containers (instancer, redis).
        
        Returns:
            SystemMetrics with host and container stats
        """
        try:
            docker_client = get_docker_client()
            
            # Get all running containers (already filtered by docker_client which excludes Whaley infra)
            containers = await docker_client.list_containers()
            container_ids = [c['Id'] for c in containers]
            
            total_containers = len(container_ids)
            running_containers = total_containers
            
            # Get metrics for all containers
            if container_ids:
                container_metrics = await self.get_container_metrics(container_ids)
                total_cpu = sum(m.cpu_percent for m in container_metrics.values())
                total_memory = sum(m.memory_usage_mb for m in container_metrics.values())
            else:
                total_cpu = 0.0
                total_memory = 0.0
            
            # Get host system info
            host_info = await self._get_host_info()
            
            return SystemMetrics(
                total_containers=total_containers,
                running_containers=running_containers,
                total_cpu_percent=round(total_cpu, 2),
                total_memory_mb=round(total_memory, 2),
                host_cpu_cores=host_info["cpu_cores"],
                host_memory_total_mb=host_info["memory_total_mb"],
                host_memory_used_mb=host_info["memory_used_mb"],
                host_memory_percent=host_info["memory_percent"],
                timestamp=utcnow().isoformat()
            )
            
        except Exception as e:
            print(f"[Monitoring] Error getting system metrics: {e}")
            # Return default metrics
            return SystemMetrics(
                total_containers=0,
                running_containers=0,
                total_cpu_percent=0.0,
                total_memory_mb=0.0,
                host_cpu_cores=1,
                host_memory_total_mb=0.0,
                host_memory_used_mb=0.0,
                host_memory_percent=0.0,
                timestamp=utcnow().isoformat()
            )
    
    async def _get_host_info(self) -> Dict:
        """Get host system information (CPU cores, memory)."""
        try:
            # Get CPU cores
            cpu_result = await asyncio.create_subprocess_exec(
                "nproc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            cpu_stdout, _ = await asyncio.wait_for(cpu_result.communicate(), timeout=5)
            cpu_cores = int(cpu_stdout.decode().strip()) if cpu_stdout else 1
            
            # Get memory info from /proc/meminfo (Linux)
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                
                mem_total = 0
                mem_available = 0
                
                for line in meminfo.split('\n'):
                    if line.startswith('MemTotal:'):
                        mem_total = int(line.split()[1]) / 1024  # Convert KB to MB
                    elif line.startswith('MemAvailable:'):
                        mem_available = int(line.split()[1]) / 1024
                
                mem_used = mem_total - mem_available
                mem_percent = (mem_used / mem_total * 100) if mem_total > 0 else 0.0
                
                return {
                    "cpu_cores": cpu_cores,
                    "memory_total_mb": round(mem_total, 2),
                    "memory_used_mb": round(mem_used, 2),
                    "memory_percent": round(mem_percent, 2)
                }
            except Exception:
                # Fallback for non-Linux or if /proc/meminfo not available
                return {
                    "cpu_cores": cpu_cores,
                    "memory_total_mb": 0.0,
                    "memory_used_mb": 0.0,
                    "memory_percent": 0.0
                }
                
        except Exception as e:
            print(f"[Monitoring] Error getting host info: {e}")
            return {
                "cpu_cores": 1,
                "memory_total_mb": 0.0,
                "memory_used_mb": 0.0,
                "memory_percent": 0.0
            }


# Singleton instance
_monitoring_manager: Optional[MonitoringManager] = None


def get_monitoring_manager() -> MonitoringManager:
    """Get the global MonitoringManager instance."""
    global _monitoring_manager
    if _monitoring_manager is None:
        _monitoring_manager = MonitoringManager()
    return _monitoring_manager
