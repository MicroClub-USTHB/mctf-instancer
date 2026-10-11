# Tests

Unit tests for the instancer's pure logic (no Docker / Redis / CTFd required).

## Running

```bash
pip install -r requirements-dev.txt
pytest
```

CI runs the same on Python 3.11 (`.github/workflows/ci.yml`).

## Scope so far

- `test_port_manager.py` — deterministic lane-based port allocation: range
  safety, uniqueness, exhaustion, atomic multi-allocation rollback, release,
  and owner-stable organized allocation.
- `test_auth_helpers.py` — CTFd member-payload normalization across the
  various shapes CTFd returns.

These cover the host-independent core. Integration tests that exercise real
Docker spawns, team-ownership enforcement end-to-end, and the CTFd auth flow
are the next layer to add.
