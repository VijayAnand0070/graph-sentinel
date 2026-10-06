"""Capture console screenshots of the running GraphSentinel service for the project report."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent / "shots"
OUT.mkdir(exist_ok=True)
URL = "http://127.0.0.1:8010/"
PANES = ["overview", "stream", "chains", "alerts", "paths", "incidents", "response", "model", "detection",
         "research", "telemetry"]


def main(stage: str) -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1.5)
        logs: list[str] = []
        page.on("console", lambda m: logs.append(f"{m.type}: {m.text}"))
        page.goto(URL, wait_until="domcontentloaded")
        time.sleep(35)  # background population streams the seed events
        page.screenshot(path=str(OUT / "01_overview_populating.png"))
        if stage in ("all", "chains"):
            page.click("#topTriggerAtkBtn")
            # wait for the attack demo to finish streaming
            for _ in range(120):
                time.sleep(2)
                if not page.evaluate("typeof isStreaming !== 'undefined' && isStreaming"):
                    break
            time.sleep(8)
        for n, pane in enumerate(PANES, 2):
            page.click(f".nav-btn[data-pane='{pane}']")
            time.sleep(4)
            page.screenshot(path=str(OUT / f"{n:02d}_{pane}.png"))
            page.screenshot(path=str(OUT / f"{n:02d}_{pane}_full.png"), full_page=True)
        (OUT / "console_log.txt").write_text("\n".join(logs), encoding="utf-8")
        browser.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "all")
