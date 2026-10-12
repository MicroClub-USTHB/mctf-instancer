"""Shared runtime singletons.

Lives in its own module so both main.py and the route modules in app/routers/
can import the same instances without an import cycle through main.py.
"""
from pathlib import Path

from .config import settings
from .docker_manager import DockerManager
from .port_manager import PortManager

# Global managers.
port_manager = PortManager(settings.PORT_RANGE_START, settings.PORT_RANGE_END)
docker_manager = DockerManager(port_manager)

# Static files directory.
STATIC_DIR = Path(__file__).parent / "static"
