"""An append-only record of every write rutern sends.

Each write is two lines in `~/.local/state/rutern/audit.jsonl` (mode 0600):
the intent, with the whole saved list as it was just before (the backup to
restore by hand), then the outcome. If the intent cannot be recorded, the
write does not happen.
"""

from __future__ import annotations

import contextlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

from rutern.config import state_dir, write_private
from rutern.errors import WriteRefused


def path() -> Path:
    return state_dir() / "audit.jsonl"


def _append(event: dict[str, Any]) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    write_private(path(), json.dumps({"ts": stamp, **event}, sort_keys=True) + "\n", append=True)


def intent(event: dict[str, Any]) -> str:
    """Record a write about to be sent; returns its id. Refuses the write when
    the record cannot be kept."""
    write_id = uuid.uuid4().hex[:12]
    try:
        _append({"event": "write", "write_id": write_id, **event})
    except OSError as e:
        raise WriteRefused(f"cannot record the write in {path()}; nothing was written") from e
    return write_id


def outcome(write_id: str, result: str) -> None:
    # The write already happened; if this line is lost, its intent is the record.
    with contextlib.suppress(OSError):
        _append({"event": "result", "write_id": write_id, "outcome": result})


def recent(n: int = 20) -> list[dict[str, Any]]:
    """The last n writes, newest last, each with its outcome merged in."""
    try:
        lines = path().read_text().splitlines()
    except OSError:
        return []
    writes: dict[str, dict[str, Any]] = {}
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or not isinstance(e.get("write_id"), str):
            continue
        if e.get("event") == "write":
            writes[e["write_id"]] = {**e, "outcome": "unknown (no result recorded)"}
        elif e.get("event") == "result" and e["write_id"] in writes:
            writes[e["write_id"]]["outcome"] = e.get("outcome")
    return list(writes.values())[-n:]
