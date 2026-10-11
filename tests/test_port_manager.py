"""Unit tests for the deterministic lane-based port allocator.

These exercise the pure in-memory allocation logic. `_is_port_available`
normally probes the OS with a socket bind; we stub it to depend only on the
allocator's own bookkeeping so the tests are deterministic and host-agnostic.
"""
import pytest

from app.port_manager import PortManager


@pytest.fixture
def pm():
    """A small allocator whose availability depends only on its own set."""
    m = PortManager(port_start=10000, port_end=10009)  # 10 ports
    # Ignore real OS sockets: a port is available iff we haven't reserved it.
    m._is_port_available = lambda port: port not in m.allocated_ports
    return m


def test_allocations_are_in_range_and_unique(pm):
    ports = [pm.allocate_port(f"inst{i}") for i in range(10)]
    assert all(p is not None for p in ports)
    assert all(10000 <= p <= 10009 for p in ports)
    assert len(set(ports)) == 10, "every allocation must be unique"


def test_exhaustion_returns_none(pm):
    for i in range(10):
        assert pm.allocate_port(f"inst{i}") is not None
    assert pm.allocate_port("overflow") is None
    assert pm.get_allocated_count() == 10
    assert pm.get_available_count() == 0


def test_allocate_ports_rolls_back_on_partial_failure(pm):
    # Range holds 10 ports; asking for 11 must fail atomically.
    got = pm.allocate_ports("inst", 11)
    assert got == []
    assert pm.get_allocated_count() == 0, "a failed multi-allocation must leave nothing reserved"
    assert pm.get_instance_ports("inst") == set()


def test_allocate_ports_success(pm):
    got = pm.allocate_ports("inst", 3)
    assert len(got) == 3
    assert len(set(got)) == 3
    assert pm.get_instance_ports("inst") == set(got)


def test_release_port_frees_it_for_reuse(pm):
    p = pm.allocate_port("inst")
    assert p is not None
    pm.release_port(p)
    assert p not in pm.allocated_ports
    # Fill the rest and confirm the freed port can be handed out again.
    reused = {pm.allocate_port(f"x{i}") for i in range(10)}
    assert p in reused


def test_release_instance_ports_frees_all(pm):
    pm.allocate_ports("inst", 4)
    assert pm.get_allocated_count() == 4
    pm.release_instance_ports("inst")
    assert pm.get_allocated_count() == 0
    assert pm.get_instance_ports("inst") == set()


def test_allocate_specific_port_respects_range_and_reservation(pm):
    assert pm.allocate_specific_port("inst", 9999) is False  # below range
    assert pm.allocate_specific_port("inst", 10011) is False  # above range
    assert pm.allocate_specific_port("inst", 10005) is True
    # Same port cannot be handed out twice.
    assert pm.allocate_specific_port("other", 10005) is False


def test_is_port_in_range(pm):
    assert pm._is_port_in_range(10000) is True
    assert pm._is_port_in_range(10009) is True
    assert pm._is_port_in_range(9999) is False
    assert pm._is_port_in_range(10010) is False


def test_hash_to_lane_is_deterministic(pm):
    a = pm._hash_to_lane("user1", "chall1", 80)
    b = pm._hash_to_lane("user1", "chall1", 80)
    assert a == b
    assert 0 <= a < pm._lane_count


def test_organized_allocation_is_stable_per_owner(pm):
    # The same owner/challenge/internal-port maps to a stable primary lane,
    # so its first allocation is reproducible across fresh allocators.
    p1 = pm._allocate_organized_port("inst1", "userA", "web/echo", 80)

    pm2 = PortManager(port_start=10000, port_end=10009)
    pm2._is_port_available = lambda port: port not in pm2.allocated_ports
    p2 = pm2._allocate_organized_port("inst2", "userA", "web/echo", 80)

    assert p1 == p2, "organized allocation must be deterministic for the same owner/challenge/port"
