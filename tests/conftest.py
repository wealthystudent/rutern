from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture(autouse=True)
def _no_real_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests away from the real Keychain, state, policy and router."""
    monkeypatch.setattr("rutern.config.home", lambda: tmp_path / "home")
    monkeypatch.setenv("RUTERN_REFERENCE", "12345678")
    for var in ("RUTERN_HOST", "RUTERN_READ_ONLY", "CLAUDECODE"):
        monkeypatch.delenv(var, raising=False)

    def no_keychain(*_: Any, **__: Any) -> None:
        raise AssertionError("tests must not touch the Keychain")

    monkeypatch.setattr("rutern.keychain._find", no_keychain)
    monkeypatch.setattr("rutern.keychain.store_session", no_keychain)
    monkeypatch.setattr("rutern.keychain.clear_session", no_keychain)
