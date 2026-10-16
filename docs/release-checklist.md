# Release checklist

Before tagging `vX.Y.Z`:

## Code and tests

- [ ] `pytest` passes locally with `UP2P_TEST_DATABASE_URL` set and mDNS enabled
      (`UP2P_SKIP_MDNS_TESTS` unset) on Linux.
- [ ] GitHub Actions is green on `ubuntu-latest` and `windows-latest` for
      Python 3.11, 3.12 and 3.13, including the `install-from-git` job.
- [ ] Two-laptop manual test of Scenario A (Echo) and Scenario B (To-Do)
      from [echo-integration.md](echo-integration.md) and
      [todo-integration.md](todo-integration.md) on real Wi-Fi, including one
      Windows laptop, with firewall rules applied (not disabled).
- [ ] Restart test: stop and start one laptop's app mid-scenario; pending
      changes arrive.

## Schema and protocol

- [ ] Any change to `storage/schema.py` has a new Alembic revision in
      `storage/migrations/versions/` (never edit a released revision).
- [ ] Upgrade test: start the previous release against a database, then start
      the new version on the same database (auto-migrate) and synchronize with
      a node still on the previous release.
- [ ] Wire-format changes are additive within protocol version 2, or bump the
      protocol version; `docs/protocol.md` updated.

## Packaging

- [ ] Version bumped in `src/universal_p2p_sync/_version.py`.
- [ ] `pip wheel --no-deps .` produces a wheel containing
      `storage/migrations/versions/*.py`, `env.py`, `script.py.mako` and `py.typed`.
- [ ] `pip install "universal-p2p-sync @ git+https://…@<tag>"` into a fresh
      virtual environment works; `python -m universal_p2p_sync identity --app-id x`
      runs.
- [ ] Dependency lower bounds in `pyproject.toml` still install and pass tests.

## Documentation

- [ ] README milestone table and limitations reflect reality.
- [ ] New/changed events documented in [integration.md](integration.md#events).
- [ ] Changelog entry (in the GitHub release notes) lists breaking changes and
      migration steps.

## Security

- [ ] `pip-audit` (or GitHub Dependabot) shows no known vulnerable dependency.
- [ ] No secrets, test databases or key files in the repository
      (`git status`, `.gitignore`).
- [ ] Review of any change touching `crypto.py`, `network/connection.py`,
      `pairing.py`, `groups.py` or authorization checks in `sync_engine.py`
      by a second person.
