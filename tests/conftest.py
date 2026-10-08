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
    """Keep tests away from the real Keychain, state dir and router."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("RUTERN_REFERENCE", "12345678")
    monkeypatch.setenv("RUTERN_UNVERIFIED_WRITES", "1")

    def no_keychain(*_: Any, **__: Any) -> None:
        raise AssertionError("tests must not touch the Keychain")

    monkeypatch.setattr("rutern.keychain._find", no_keychain)
    monkeypatch.setattr("rutern.keychain.store_session", no_keychain)
    monkeypatch.setattr("rutern.keychain.clear_session", no_keychain)
