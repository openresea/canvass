from typing import Any, Optional


def fetchone_dict(cur) -> Optional[dict[str, Any]]:
    row = cur.fetchone()
    if row is None:
        return None
    cols = [d.name for d in cur.description]
    return dict(zip(cols, row))


def fetchall_dict(cur) -> list[dict[str, Any]]:
    rows = cur.fetchall()
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]
