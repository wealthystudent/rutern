from __future__ import annotations

import json
import os
import pwd
from pathlib import Path
from typing import Any

import pytest

from rutern.cli import AGENT_ENV

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture(autouse=True)
def _no_real_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests away from the real Keychain, keyring, state and router."""
    # rutern takes home from the password database (config.home), so the
    # database itself answers with a temp dir: no import style reaches the real one.
    real = pwd.getpwuid(os.getuid())
    fake = pwd.struct_passwd((*real[:5], str(tmp_path / "home"), real.pw_shell))
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: fake)
    monkeypatch.setenv("RUTERN_REFERENCE", "12345678")
    for var in ("RUTERN_HOST", *AGENT_ENV):
        monkeypatch.delenv(var, raising=False)

    def no_store(*_: Any, **__: Any) -> None:
        raise AssertionError("tests must not touch the Keychain or keyring")

    monkeypatch.setattr("rutern.credentials.store", no_store)
