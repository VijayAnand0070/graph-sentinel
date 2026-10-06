"""Detail screenshots: alert drawer + triage, SOC incident report, path explanation."""

from __future__ import annotations

import time
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent / "shots"
URL = "http://127.0.0.1:8010/"


def wait_text(page, selector: str, bad: tuple[str, ...], timeout: float = 150) -> str:
    end = time.time() + timeout
    text = ""
    while time.time() < end:
        try:
            text = page.inner_text(selector)
        except Exception:
            text = ""
        if text.strip() and not any(b in text for b in bad):
            return text
        time.sleep(2)
    return text


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1.5)
    page.goto(URL, wait_until="domcontentloaded")
    time.sleep(12)

    # 1) alert drawer with evidence context and the AI triage report
    page.click(".nav-btn[data-pane='alerts']")
    time.sleep(4)
    page.locator("#pane-alerts .alert-card").first.click()
    time.sleep(5)
    page.screenshot(path=str(OUT / "20_alert_drawer.png"))
    page.click("#btnGenerateTriage")
    txt = wait_text(page, "#triageReportBlock", ("Generating", "Queued"))
    print("triage:", txt[:300].replace("\n", " | "))
    page.locator("#triageReportBlock").scroll_into_view_if_needed()
    time.sleep(1)
    page.screenshot(path=str(OUT / "21_alert_triage.png"))
    page.keyboard.press("Escape")
    time.sleep(2)

    # 2) SOC incident report for the account the loop escalated
    page.click(".nav-btn[data-pane='response']")
    time.sleep(5)
    page.locator("button:has-text('Write report')").first.click()
    txt = wait_text(page, "#socReportBlock", ("Writing the report", "Waiting for the model"))
    print("soc:", txt[:300].replace("\n", " | "))
    block = page.locator("#socReportBlock")
    block.scroll_into_view_if_needed()
    time.sleep(1)
    page.screenshot(path=str(OUT / "22_soc_report_view.png"))
    try:
        block.screenshot(path=str(OUT / "23_soc_report_block.png"))
    except Exception as err:  # noqa: BLE001
        print("element shot failed:", err)

    # 3) grounded explanation of the top suspicious path
    page.click(".nav-btn[data-pane='paths']")
    time.sleep(5)
    btn = page.locator("button:has-text('Explain this path')").first
    btn.click()
    txt = wait_text(page, "#path-explain-0", ("Explaining", "Generating", "Queued", "Waiting"))
    print("path:", txt[:300].replace("\n", " | "))
    page.locator("#path-explain-0").scroll_into_view_if_needed()
    time.sleep(1)
    page.screenshot(path=str(OUT / "24_path_explained.png"))
    browser.close()
