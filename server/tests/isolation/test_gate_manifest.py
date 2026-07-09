import subprocess
import sys
from pathlib import Path

ISO = Path(__file__).parent

# the 19 §16 gate files — one per §16 clause (see the plan's Task→§16 map)
GATE_FILES = [
    "test_stream_leak.py",            # cross-tenant stream leak
    "test_cross_cell_read.py",        # cookie/token cross-cell read
    "test_ws_routing.py",             # WS handshake routing
    "test_single_flight.py",          # single-flight acquire
    "test_refcount.py",               # refcount exactly-once / no use-after-free
    "test_stream_cap.py",             # half-open pin cap
    "test_disable_teardown.py",       # disable/revoke teardown
    "test_scheduler_signing.py",      # scheduler per-cell signing
    "test_forged_route.py",           # router-trust forged route
    "test_shared_dir.py",             # shared-dir / key-distinctness
    "test_verdict_tenant_binding.py", # cross-tenant verdict, keys forced identical
    "test_rotation_anchor.py",        # rotation trust anchor
    "test_keys_eviction_race.py",     # keys() under eviction race
    "test_rate_limit_isolation.py",   # rate-limiter isolation
    "test_egress_isolation.py",       # webhook/ntfy egress isolation
    "test_backup_restore.py",         # backup/restore fail-closed
    "test_outbox_idempotency.py",     # outbox idempotency
    "test_scheduler_durability.py",   # scheduler durability
    "test_scheduler_fairness.py",     # scheduler fairness / FD budget
]


def test_all_nineteen_gate_files_present():
    missing = [f for f in GATE_FILES if not (ISO / f).is_file()]
    assert not missing, f"§16 gate files missing: {missing}"
    assert len(GATE_FILES) == 19


def test_each_gate_file_collects_at_least_one_test():
    for f in GATE_FILES:
        out = subprocess.run(
            [sys.executable, "-m", "pytest", str(ISO / f), "--collect-only", "-q"],
            capture_output=True, text=True)
        assert out.returncode == 0, f"{f} collected no tests (returncode={out.returncode}):\n{out.stdout}\n{out.stderr}"
