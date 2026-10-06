import time
from pathlib import Path
from playwright.sync_api import sync_playwright
OUT = Path(__file__).resolve().parent / "shots"
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    page = b.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=1.5)
    page.goto("http://127.0.0.1:8010/", wait_until="domcontentloaded")
    time.sleep(10)
    page.click(".nav-btn[data-pane='response']")
    time.sleep(5)
    buttons = page.locator("button:has-text('Write report')")
    print("incidents:", buttons.count())
    for idx in (1, 2, 3):
        if idx >= buttons.count():
            break
        buttons.nth(idx).click()
        end = time.time() + 180
        txt = ""
        while time.time() < end:
            txt = page.inner_text("#socReportBlock")
            if txt.strip() and "Writing the report" not in txt and "Waiting for the model" not in txt:
                break
            time.sleep(2)
        head = txt[:160].replace("\n", " | ")
        print(idx, head)
        page.locator("#socReportBlock").screenshot(path=str(OUT / f"25_soc_report_{idx}.png"))
        if "AI-generated" in txt:
            break
    b.close()
