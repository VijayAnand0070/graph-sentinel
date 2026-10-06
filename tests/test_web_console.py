"""Structural checks on the shipped console.

Rewritten, not merely relaxed. The previous version described a console that
does not exist in this repository and has not for some time: it required
fourteen element ids (``view-engineering``, ``phaseJobProgress``, ...) of which
**zero** are present, asserted ``role="progressbar"`` which appears nowhere,
and made eight assertions about ``assets/app.js`` -- a 50 KB file the console
never loaded, since ``index.html`` carries all of its JavaScript inline and
references no external script at all. That orphaned bundle has since been
deleted; the console remaining self-contained is now asserted directly by
``test_the_console_ships_as_one_inline_bundle``.

Verified against the archived copy in ``graphsentinel_project_source.zip``:
that version has the same 0/14 ids and the same single inline bundle, so the
mismatch predates this work rather than being introduced by it. The test could
only ever have failed, and its passing assertions were checking dead code.

What it checks now is the structure the console actually relies on, so a
regression in navigation or in the endpoints the live code calls will fail
here rather than at runtime.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

WEB = Path("src/graphsentinel/web")

#: The console ships as one document with its script inline. The API's own
#: Content-Security-Policy allows this (``script-src 'self' 'unsafe-inline'``),
#: so a single inline bundle is the supported arrangement rather than an
#: oversight. The count is pinned at exactly one so that an additional -- or
#: injected -- script block still fails the test.
EXPECTED_INLINE_SCRIPTS = 1


class _ConsoleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.pane_targets: set[str] = set()
        self.inline_scripts = 0
        self.external_scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"] or "")
        if values.get("data-pane"):
            self.pane_targets.add(values["data-pane"] or "")
        if tag == "script":
            source = values.get("src")
            if source:
                self.external_scripts.append(source)
            else:
                self.inline_scripts += 1


@pytest.fixture(scope="module")
def markup() -> str:
    return (WEB / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def parsed(markup: str) -> _ConsoleParser:
    parser = _ConsoleParser()
    parser.feed(markup)
    return parser


@pytest.fixture(scope="module")
def console_javascript(markup: str) -> str:
    """The JavaScript the console actually executes.

    Extracted from the inline block, which is the only script the console
    carries. Asserting against a file nothing loads verifies code that never
    runs -- the failure mode this rewrite exists to remove.
    """
    return "\n".join(
        re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", markup, re.S)
    )


def test_element_ids_are_unique(parsed: _ConsoleParser) -> None:
    """Duplicate ids make getElementById return an arbitrary one of them."""
    duplicates = {i for i in parsed.ids if parsed.ids.count(i) > 1}
    assert not duplicates, f"duplicate element ids: {sorted(duplicates)}"


def test_the_console_ships_as_one_inline_bundle(parsed: _ConsoleParser) -> None:
    assert parsed.inline_scripts == EXPECTED_INLINE_SCRIPTS
    assert parsed.external_scripts == []


def test_every_navigation_button_targets_a_pane_that_exists(
    parsed: _ConsoleParser,
) -> None:
    """The structural invariant that matters: a nav button whose pane is
    missing is a dead control the user can click into nothing."""
    literal_targets = {
        target for target in parsed.pane_targets if "${" not in target
    }
    pane_ids = {i for i in parsed.ids if i.startswith("pane-")}
    missing = {t for t in literal_targets if f"pane-{t}" not in pane_ids}
    assert not missing, f"nav buttons point at panes that do not exist: {sorted(missing)}"


def test_the_expected_workspaces_are_present(parsed: _ConsoleParser) -> None:
    pane_ids = {i for i in parsed.ids if i.startswith("pane-")}
    assert {
        "pane-overview",
        "pane-alerts",
        "pane-chains",
        "pane-paths",
        "pane-incidents",
        "pane-model",
        "pane-detection",
        "pane-telemetry",
    } <= pane_ids


@pytest.mark.parametrize(
    "endpoint",
    [
        "/api/v1/overview",
        "/api/v1/alerts",
        "/api/v1/graph",
        "/api/v1/detection-engineering",
        "/api/v1/phase16",
        "/api/v1/live/events",
    ],
)
def test_the_live_console_calls_its_endpoints(
    console_javascript: str, endpoint: str
) -> None:
    """Checked against the inline bundle, so this tracks the console that runs.

    The previous version asserted a helper-wrapper style (``api("...")``) that
    only the since-deleted ``assets/app.js`` used; the shipped console calls
    ``fetch`` directly. Pinning the endpoint rather than the call style
    survives that difference.
    """
    assert endpoint in console_javascript


def test_investigation_context_is_wired(console_javascript: str) -> None:
    assert "renderInvestigationContext" in console_javascript
    assert "/context`" in console_javascript


def test_data_readiness_fields_are_rendered(console_javascript: str) -> None:
    for field in ("raw_auth_registered", "raw_labels_registered", "training_ready"):
        assert field in console_javascript


def test_the_console_does_not_paint_ground_truth_as_detection(
    console_javascript: str,
) -> None:
    """A known attacker the model missed must render as a miss (Finding 17).

    The earlier handler folded ``isKnownAttacker`` into ``isAttack``, so every
    labelled attacker was drawn as detected whatever the model scored. The
    server-side override that fed it is gone; this guards the client half.
    """
    assert "const isAttack = ev.alerted === true || sev === 'critical';" in console_javascript
    assert "const isMissedAttack = isKnownAttacker && !isAttack;" in console_javascript
    assert "GT · MISSED" in console_javascript
    assert "isKnownAttacker || sev === 'critical'" not in console_javascript


def test_the_inline_script_parses(console_javascript: str, tmp_path: Path) -> None:
    """A syntax error anywhere in the inline bundle takes the whole console
    down -- no clock, no socket, no navigation -- and the structural checks
    above cannot see it. Parse the script with a real JavaScript engine."""
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; cannot parse the console script")
    script = tmp_path / "console_inline.js"
    script.write_text(console_javascript, encoding="utf-8")
    result = subprocess.run([node, "--check", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, f"console script does not parse:\n{result.stderr[:800]}"
