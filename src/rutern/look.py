"""The shared tool look for plain (non interactive) CLI output.

Ported from fuzzyrepo/internal/look (Go): the palette roles on the
terminal's ANSI colours, and rounded frames with the title on the top
border. Colour is off when stdout is not a terminal or NO_COLOR is set.
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata

ERROR, OK, KEY, ACCENT, INFO, TEXT, DIM = "31", "32", "33", "34", "35", "37", "90"
BORDER = "38;2;55;59;64"  # #373b40, no ANSI slot

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def enabled(stream: object = None) -> bool:
    stream = stream or sys.stdout
    return "NO_COLOR" not in os.environ and bool(getattr(stream, "isatty", lambda: False)())


_color = enabled()


def set_color(on: bool) -> None:
    global _color
    _color = on


def fg(role: str, text: str, bold: bool = False) -> str:
    if not _color or not text:
        return text
    code = f"1;{role}" if bold else role
    return f"\x1b[{code}m{text}\x1b[0m"


def title(text: str) -> str:
    return fg(ACCENT, text, bold=True)


def width(text: str) -> int:
    plain = _ANSI.sub("", text)
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in plain)


def pad(text: str, n: int) -> str:
    return text + " " * max(0, n - width(text))


def fit(text: str, n: int) -> str:
    if width(text) <= n:
        return pad(text, n)
    plain = _ANSI.sub("", text)
    out = ""
    for c in plain:
        if width(out + c) > n - 1:
            break
        out += c
    return out + "…"


def frame(heading: str, lines: list[str], min_width: int = 0) -> str:
    """A rounded box with the heading centred on the top border."""
    inner = max([min_width, width(heading) + 6, *(width(line) + 2 for line in lines)])

    def b(s: str) -> str:
        return fg(BORDER, s)

    label = f" {heading} "
    left = (inner - width(label)) // 2
    right = inner - width(label) - left
    top = b("╭" + "─" * left) + title(label) + b("─" * right + "╮")
    body = [b("│") + " " + pad(line, inner - 2) + " " + b("│") for line in lines]
    return "\n".join([top, *body, b("╰" + "─" * inner + "╯")])


def table(headers: list[str], rows: list[list[str]], max_col: int = 40) -> list[str]:
    """Column aligned lines with a dim header row."""
    if not rows:
        return [fg(DIM, "nothing to show")]
    widths = [min(max_col, max(width(r[i]) for r in [headers, *rows])) for i in range(len(headers))]

    def line(cells: list[str]) -> str:
        return "  ".join(fit(c, w) for c, w in zip(cells, widths, strict=True)).rstrip()

    return [fg(DIM, line(headers)), *(line(r) for r in rows)]


def kv(pairs: list[tuple[str, str]]) -> list[str]:
    w = max(width(k) for k, _ in pairs)
    return [fg(DIM, pad(k, w)) + "  " + v for k, v in pairs]


def error(msg: str) -> str:
    return fg(ERROR, "error") + " " + msg


def hint(*pairs: tuple[str, str]) -> str:
    """A hint line: keys in yellow, descriptions dim."""
    return "  ".join(fg(KEY, k) + " " + fg(DIM, d) for k, d in pairs)
