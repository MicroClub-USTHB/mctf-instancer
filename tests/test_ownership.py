"""Integration tests for per-team / per-user ownership and quota logic.

These drive the real DockerManager against an in-memory instance store. The
ownership checks in stop_instance are early gates that return before any
Docker interaction, so they are exercised here without a Docker daemon. The
quota helpers (get_owner_instances / get_owner_instance_count) are likewise
pure over the in-memory store.

This is the security-critical core of per-team isolation: a player must not be
able to tear down another team's (or user's) instance.
"""
from datetime import timedelta

import pytest

from app.docker_manager import DockerManager
from app.models import Instance, InstanceStatus, utcnow
from app.port_manager import PortManager


def make_dm():
    return DockerManager(PortManager(10000, 10050))


def add_instance(dm, instance_id, user_id, team_id=None, status=InstanceStatus.RUNNING):
    dm.instances[instance_id] = Instance(
        instance_id=instance_id,
        challenge_id="web/echo",
        user_id=user_id,
        team_id=team_id,
        status=status,
        expires_at=utcnow() + timedelta(hours=1),
    )


# --- ownership enforcement on stop ---------------------------------------

@pytest.mark.asyncio
async def test_team_mode_denies_other_team():
    dm = make_dm()
    add_instance(dm, "i1", user_id="alice", team_id="teamA")
    ok, msg = await dm.stop_instance("i1", user_id="bob", team_id="teamB", team_mode=True)
    assert ok is False
    assert "team doesn't own" in msg.lower()


@pytest.mark.asyncio
async def test_team_mode_allows_same_team_past_ownership_gate():
    dm = make_dm()
    add_instance(dm, "i1", user_id="alice", team_id="teamA")
    # A different user on the SAME team passes the ownership gate. No challenge
    # is registered, so it stops at the next check — proving the gate let it by
    # rather than rejecting on ownership.
    ok, msg = await dm.stop_instance("i1", user_id="carol", team_id="teamA", team_mode=True)
    assert ok is False
    assert "team doesn't own" not in msg.lower()
    assert "challenge configuration not found" in msg.lower()


@pytest.mark.asyncio
async def test_user_mode_denies_other_user():
    dm = make_dm()
    add_instance(dm, "i1", user_id="alice")
    ok, msg = await dm.stop_instance("i1", user_id="bob", team_mode=False)
    assert ok is False
    assert "don't own" in msg.lower()


@pytest.mark.asyncio
async def test_stop_unknown_instance():
    dm = make_dm()
    ok, msg = await dm.stop_instance("nope", user_id="alice", team_mode=False)
    assert ok is False
    assert "not found" in msg.lower()


# --- quota / owner-scoped counting ---------------------------------------

def test_owner_instances_group_by_team_in_team_mode():
    dm = make_dm()
    add_instance(dm, "i1", user_id="alice", team_id="teamA")
    add_instance(dm, "i2", user_id="bob", team_id="teamA")   # same team, different user
    add_instance(dm, "i3", user_id="carol", team_id="teamB")

    assert dm.get_owner_instance_count("teamA", team_mode=True) == 2
    assert dm.get_owner_instance_count("teamB", team_mode=True) == 1


def test_owner_instances_group_by_user_in_user_mode():
    dm = make_dm()
    add_instance(dm, "i1", user_id="alice")
    add_instance(dm, "i2", user_id="alice")
    add_instance(dm, "i3", user_id="bob")

    assert dm.get_owner_instance_count("alice", team_mode=False) == 2
    assert dm.get_owner_instance_count("bob", team_mode=False) == 1


def test_only_active_instances_count_toward_quota():
    dm = make_dm()
    add_instance(dm, "i1", user_id="alice", status=InstanceStatus.RUNNING)
    add_instance(dm, "i2", user_id="alice", status=InstanceStatus.STARTING)
    add_instance(dm, "i3", user_id="alice", status=InstanceStatus.STOPPED)
    add_instance(dm, "i4", user_id="alice", status=InstanceStatus.ERROR)

    # Only RUNNING + STARTING count against the quota.
    assert dm.get_owner_instance_count("alice", team_mode=False) == 2
