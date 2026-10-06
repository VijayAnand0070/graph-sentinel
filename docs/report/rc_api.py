"""Content API for the project report: chapters are written as a list of blocks."""

from __future__ import annotations

C: list[tuple] = []


def CH(num: int, title: str) -> None:
    C.append(("chapter", num, title))


def SEC(num: str, title: str) -> None:
    C.append(("sec", num, title))


def SUB(num: str, title: str) -> None:
    C.append(("sub", num, title))


def P(text: str, indent: bool = True) -> None:
    C.append(("p", text, indent))


def BUL(items: list[str]) -> None:
    C.append(("bullets", items))


def NUM(items: list[str]) -> None:
    C.append(("numbered", items))


def FIG(label: str, file: str, width: float, caption: str) -> None:
    C.append(("fig", label, file, width, caption))


def TAB(label: str, caption: str, widths: list[int], rows: list[list[str]], aligns: list[str] | None = None,
        size: float = 11.0) -> None:
    C.append(("tab", label, caption, widths, rows, aligns, size))


def EQ(label: str) -> None:
    C.append(("eq", label))


def BREAK() -> None:
    C.append(("pagebreak",))
