#!/usr/bin/env python3
"""merge_heads.py — инструмент жёсткой сведения графа Alembic к одному head (P0/A6).

Назначение:
1. ``--check``  — диагностика CI: печатает все heads и выходит с кодом 1, если
   heads больше одного (блокирующий guard в pipeline).
2. ``--repair`` — автоматический ремонт: если обнаружено >= 2 heads, генерирует
   merge-revision (аналог ``alembic merge -m "merge heads" <heads...>``) в
   migrations/versions/, после чего граф снова становится линейно-сходящимся.

Использование (из корня репозитория):
    python server/merge_heads.py --check
    python server/merge_heads.py --repair

Инструмент идемпотентен: повторный запуск --repair при единственном head
ничего не делает и завершается успешно.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

# Корень репозитория = родитель серверного пакета (здесь лежит alembic.ini).
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from alembic.config import Config  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402

TEMPLATE = '''"""Merge heads: {msg}

Автоматически создан инструментом server/merge_heads.py (режим --repair).
Revision ID: {rev}
Revises: {revs}
Create Date: {date}

"""
from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = '{rev}'
down_revision: Union[str, Sequence[str], None] = ({revs_tuple})
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Чисто топологическое слияние веток: схема не меняется."""


def downgrade() -> None:
    """Обратное расщепление графа; схема не меняется."""
'''


def _load_script_dir() -> tuple[Config, ScriptDirectory]:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    return cfg, ScriptDirectory.from_config(cfg)


def get_heads() -> list[str]:
    _, sd = _load_script_dir()
    return list(sd.get_heads())


def cmd_check(verbose: bool = True) -> int:
    heads = get_heads()
    if verbose:
        print(f"Alembic heads: {len(heads)} -> {heads}")
    if len(heads) == 1:
        return 0
    print(
        "ERROR: граф миграций имеет {} heads (ожидается 1). Выполните:\n"
        "    python server/merge_heads.py --repair\n".format(len(heads)),
        file=sys.stderr,
    )
    return 1


def cmd_repair() -> int:
    heads = get_heads()
    if len(heads) == 1:
        print(f"OK: единственный head {heads[0]}, ремонт не требуется.")
        return 0
    if not heads:
        print(
            "ERROR: не найдено ни одной ревизии — проверьте migrations/.",
            file=sys.stderr,
        )
        return 2

    from datetime import datetime, timezone

    rev = uuid.uuid4().hex[:12]
    versions_dir = REPO_ROOT / "migrations" / "versions"
    filename = versions_dir / f"{rev}_merge_heads.py"
    body = TEMPLATE.format(
        msg=f"{' + '.join(heads)}",
        rev=rev,
        revs=", ".join(heads),
        revs_tuple=", ".join(f"'{h}'" for h in heads)
        + ("," if len(heads) == 1 else ""),
        date=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    filename.write_text(body, encoding="utf-8")
    new_heads = get_heads()
    if len(new_heads) != 1:
        print(
            f"ERROR: после ремонта heads всё ещё {new_heads}",
            file=sys.stderr,
        )
        return 3
    print(f"Created merge revision {rev} -> single head confirmed: {new_heads[0]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check",
        action="store_true",
        help="проверить количество heads (exit 1 если > 1)",
    )
    group.add_argument(
        "--repair",
        action="store_true",
        help="сгенерировать merge-revision при нескольких heads",
    )
    args = parser.parse_args(argv)
    return cmd_repair() if args.repair else cmd_check()


if __name__ == "__main__":
    raise SystemExit(main())
