from typing import Any


def fetchone_dict(cur) -> dict[str, Any] | None:
    row = cur.fetchone()
    if row is None:
        return None
    cols = [d.name for d in cur.description]
    return dict(zip(cols, row))


def fetchall_dict(cur) -> list[dict[str, Any]]:
    rows = cur.fetchall()
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]
