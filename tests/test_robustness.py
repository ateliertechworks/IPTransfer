"""Crash consistency, packaging from a Git checkout, and secure LAN discovery."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from universal_p2p_sync.storage.database import normalize_database_url

from .conftest import mdns_disabled, pair, wait_until

ROOT = Path(__file__).resolve().parent.parent

WRITER = textwrap.dedent(
    """
    import asyncio, sys
    from universal_p2p_sync import AsyncSyncNode

    async def main(url, data_dir):
        node = AsyncSyncNode("echo", "u", "crashy", database_url=url, data_dir=data_dir,
                             listen_host="127.0.0.1", enable_discovery=False)
        await node.start()
        group = await node.create_group("Crash test")
        print("GROUP", group.id, flush=True)
        i = 0
        while True:
            await node.publish(group.id, "notes", f"n{i % 25}", {"i": i, "pad": "x" * 200})
            if i % 10 == 0:
                await node.delete(group.id, "notes", f"n{(i + 7) % 25}") if i else None
            print("WROTE", i, flush=True)
            i += 1

    asyncio.run(main(sys.argv[1], sys.argv[2]))
    """
)


@pytest.mark.multiprocess
async def test_state_is_consistent_after_a_hard_crash(make_secure_node, pg_database,
                                                      tmp_path) -> None:
    url = pg_database()
    script = tmp_path / "writer.py"
    script.write_text(WRITER)
    proc = subprocess.Popen(
        [sys.executable, str(script), url, str(tmp_path / "keys")],
        stdout=subprocess.PIPE, text=True,
    )
    group_id = None
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if line.startswith("GROUP"):
                group_id = line.split()[1]
            if line.startswith("WROTE") and int(line.split()[1]) >= 120:
                break
        os.kill(proc.pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
    finally:
        proc.wait(10)
    assert group_id is not None

    node, _ = await make_secure_node("echo", "crashy", database_url=url,
                                     data_dir=tmp_path / "keys")
    status = await node.get_sync_status(group_id)
    engine = create_engine(normalize_database_url(url))
    schema = node.schema
    with engine.connect() as conn:
        q = lambda sql: conn.execute(text(sql.replace("S.", f'"{schema}".'))).scalar()  # noqa: E731
        max_seq = q("SELECT max(seq) FROM S.changes")
        assert q("SELECT count(*) FROM S.changes") == max_seq == status.local_changes
        assert q("SELECT next_seq FROM S.groups") == max_seq + 1
        assert q("SELECT count(DISTINCT record_id) FROM S.changes") == q(
            "SELECT count(*) FROM S.records")
        # Every record shows the newest change written for it.
        assert q("""SELECT count(*) FROM S.records r WHERE r.version <> (
                      SELECT c.change_id FROM S.changes c WHERE c.record_id = r.record_id
                      ORDER BY c.seq DESC LIMIT 1)""") == 0
    engine.dispose()
    record = await node.publish(group_id, "notes", "after-crash", {"ok": True})
    assert record.data == {"ok": True}


@pytest.mark.multiprocess
def test_package_installs_from_a_git_checkout(tmp_path) -> None:
    """Build and install the package the way ``pip install git+...`` does."""
    checkout = tmp_path / "checkout"
    has_commits = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"], capture_output=True
    ).returncode == 0
    if has_commits:
        subprocess.run(["git", "clone", "-q", str(ROOT), str(checkout)], check=True)
    else:  # repository without commits yet: use the working tree files
        shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns(
            ".venv", ".git", "*.egg-info", "__pycache__", ".pytest_cache", "build", "dist"))
    wheels = tmp_path / "wheels"
    build = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "-q", "--no-deps", "-w", str(wheels),
         str(checkout)], capture_output=True, text=True,
    )
    if build.returncode != 0 and "network" in (build.stderr or "").lower():
        pytest.skip("building needs network access for setuptools")
    assert build.returncode == 0, build.stderr
    (wheel,) = wheels.glob("universal_p2p_sync-*.whl")
    target = tmp_path / "site"
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--no-deps", "--target",
                    str(target), str(wheel)], check=True)
    check = subprocess.run(
        [sys.executable, "-I", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); sys.path.extend(sys.argv[2:]);"
         "import universal_p2p_sync as u, universal_p2p_sync.storage.database as d;"
         "assert u.__file__.startswith(sys.argv[1]), u.__file__;"
         "assert (d.MIGRATIONS_DIR / 'versions' / '0001_initial.py').exists();"
         "assert (d.MIGRATIONS_DIR / 'env.py').exists();"
         "print(u.__version__, u.SyncNode.__name__)",
         str(target), *[p for p in sys.path if p]],
        capture_output=True, text=True,
    )
    assert check.returncode == 0, check.stderr
    assert "SyncNode" in check.stdout


@pytest.mark.mdns
@pytest.mark.skipif(mdns_disabled(), reason="UP2P_SKIP_MDNS_TESTS is set")
async def test_secure_devices_discover_each_other_on_the_lan(make_secure_node) -> None:
    options = dict(enable_discovery=True, advertise_addresses=("127.0.0.1",),
                   discovery_connect_delay=0.5)
    a, ra = await make_secure_node("echo", "lan-a", **options)
    b, rb = await make_secure_node("echo", "lan-b", **options)
    await ra.wait_for("peer_discovered", timeout=20)
    await wait_until(lambda: len(a.peers()) == 1 and len(b.peers()) == 1, 20)
    assert a.peers()[0].secure and a.peers()[0].device_id == b.device_id
    await pair(a, b)
    started = time.monotonic()
    group = await a.create_group("LAN team")
    invite = await a.create_invite(group.id, "member", device_id=b.device_id)
    await rb.wait_for("group_invitation_received")
    await b.accept_invite(invite.id)
    await a.publish(group.id, "notes", "lan", {"ok": True})
    await rb.wait_for("record_received")
    assert time.monotonic() - started < 20
