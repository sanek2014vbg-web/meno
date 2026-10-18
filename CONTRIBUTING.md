# Contributing to MeNo Messenger

First off, thank you for considering contributing to MeNo — a privacy-first,
end-to-end encrypted messenger built with FastAPI (backend) and Flet (client).

Reading this guide takes about 10 minutes. Following these guidelines helps
keep the review process smooth and the codebase healthy for everyone.

## Table of contents

1. [Code of Conduct](#code-of-conduct)
2. [Golden rules](#golden-rules)
3. [Local development setup](#local-development-setup)
4. [Running the test suite](#running-the-test-suite)
5. [Linting and formatting](#linting-and-formatting)
6. [Pre-commit hooks](#pre-commit-hooks)
7. [Database migrations](#database-migrations)
8. [Pull request checklist](#pull-request-checklist)
9. [Reporting bugs & proposing features](#reporting-bugs--proposing-features)

## Code of Conduct

This project and everyone participating in it is governed by the
[MeNo Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are
expected to uphold this code. Please report unacceptable behavior to the
maintainers listed in `SECURITY.md`.

## Golden rules

These rules are **hard requirements**; CI will enforce most of them:

1. **No direct changes to `main`.** All work goes through feature branches
   and Pull Requests. A PR is mergeable only when all tests are green and
   at least one maintainer has approved it.
2. **Tests must stay dialect-safe.** Unit/integration tests run on SQLite;
   production runs on PostgreSQL 16. Never use database-specific SQL without
   routing it through the compatibility helpers in `server/utils.py`, and
   keep SQLAlchemy enums non-native (`native_enum=False`).
3. **Privacy is a feature.** Anything that touches message content must be
   E2EE-friendly: the server relays opaque ciphertext blobs and never learns
   plaintext, reaction emoji included.
4. **Clean Code standards apply.** Small functions, meaningful names, no
   dead code, no commented-out leftovers, and absolutely no lazy `# TODO`
   stubs merged into `main`.
5. **Never commit secrets.** The `gitleaks` pre-commit hook blocks commits
   containing credentials, keys, or tokens. Test fixtures with fake secrets
   belong under `*/tests/` paths, which are allowlisted.

## Local development setup

### Option A — Docker Compose (recommended)

The full stack (PostgreSQL 16, Redis, MinIO, backend API) starts with one
command:

```bash
git clone https://github.com/<org>/meno-messenger.git
cd meno-messenger
cp .env.example .env          # adjust POSTGRES_PASSWORD etc. if needed
docker compose up -d --build  # starts db, redis, minio, api
docker compose logs -f api    # watch the backend boot
```

The API is then available at `http://localhost:8000` (OpenAPI docs at
`/docs`). Database migrations run automatically on container start via
`server/entrypoint.sh` (`alembic upgrade head`).

### Option B — Bare-metal Python environment

If you prefer running services locally:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r server/requirements.txt
pip install -r client/requirements.txt

# Backend (expects PostgreSQL + Redis reachable, see docker-compose.yml)
export DATABASE_URL=postgresql+asyncpg://meno:meno@localhost:5432/meno
export REDIS_URL=redis://localhost:6379/0
uvicorn server.main:app --reload

# Client (Flet desktop app, points at http://127.0.0.1:8000 by default)
cd client && flet run main.py
```

## Running the test suite

All tests are async (`pytest-asyncio`, `asyncio_mode=auto`) and run against
a throwaway SQLite database created by the fixtures in `conftest.py` — no
PostgreSQL required for local testing.

```bash
# Everything (backend unit + integration + client tests)
python -m pytest -q

# Only backend unit tests
python -m pytest tests/unit -q

# Only backend integration tests (FastAPI TestClient over ASGI)
python -m pytest tests/integration -q

# Only client logic tests (no GUI runtime needed — safe for headless CI)
python -m pytest client/tests -q
```

A brand-new contribution should add at least one regression test proving
the fix/feature works. Tests for race conditions should use
`asyncio.gather()` to fire concurrent requests, mirroring real network
reordering.

## Linting and formatting

We use [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting
(configuration lives in `pyproject.toml`):

```bash
ruff check .            # lint (must exit 0 before pushing)
ruff check . --fix      # auto-fix what can be auto-fixed
ruff format .           # apply the canonical formatting style
```

CI fails on any Ruff error, including unused imports (`F401`) and
undefined names (`F821`).

## Pre-commit hooks

Install the hook chain once per clone:

```bash
pip install pre-commit
pre-commit install
```

Every `git commit` now runs, in order:

| Hook | Purpose |
|------|---------|
| `check-yaml`, `end-of-file-fixer`, `trailing-whitespace`, `check-added-large-files` | hygiene |
| `ruff` (+ `--fix`) | style and correctness; non-zero exit if it changed anything |
| `ruff-format` | formatting |
| `gitleaks` | secret scanning (config: `.gitleaks.toml`) |

If a hook fails, fix the issue and commit again — do not bypass with
`--no-verify` unless a maintainer explicitly approves it in the PR thread.

## Database migrations

Schema changes always ship with an Alembic migration:

```bash
# autogenerate from models, then REVIEW the diff manually
alembic revision --autogenerate -m "short_description"

alembic upgrade head      # apply
alembic downgrade -1      # roll back one step
```

Migration files must be **idempotent** (guard column/table creation with
the inspector, like existing revisions do) and **dialect-safe**: SQLite
cannot execute some `ALTER TABLE` forms, so follow the three-step nullable →
backfill → set-NOT-NULL pattern used in
`migrations/versions/c8d9e0f1a2b3_reactions_and_replies.py`.

## Pull request checklist

Before requesting review, confirm:

- [ ] Branch is fresh from `main` (`git rebase main` or merge latest `main`)
- [ ] No direct pushes to `main` happened (protected branch — CI enforces)
- [ ] `python -m pytest -q` is fully green
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] New schema fields have an idempotent Alembic migration
- [ ] New WS events are handled by the client router *and* tested logically
      (headless) in `client/tests/`
- [ ] Docs touched: `README.md` / this file updated when behavior changed
- [ ] PR description explains *why*, not just *what*; link related issues

Maintainers squash-merge green PRs. Keep your history tidy but don't fear
follow-up commits — review comments are a collaboration, not a judgment.

## Reporting bugs & proposing features

- **Security vulnerabilities:** never open a public issue. Follow
  `SECURITY.md` for private disclosure.
- **Bugs:** include the exact reproduction command, expected vs. actual
  behavior, Python version, and whether you run Docker or bare-metal.
- **Features:** open an issue first to align on scope; small, single-purpose
  PRs land fastest.

Happy hacking — and welcome aboard! 🚀
