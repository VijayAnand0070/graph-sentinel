"""Crop console screenshots for the report and save them as high-quality JPEG."""

from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
S = HERE / "shots"
OUT = HERE / "figs"
OUT.mkdir(exist_ok=True)

SIDEBAR = 360       # px at 1.5x device scale
FULL_H = 1500

crops = {
    "s_overview": ("02_overview.png", (0, 0, 2400, 1395)),
    "s_stream": ("03_stream.png", (SIDEBAR, 0, 2400, 1300)),
    "s_chains": ("04_chains.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_alerts": ("05_alerts.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_paths": ("24_path_explained.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_incidents": ("07_incidents.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_response": ("08_response.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_detection": ("10_detection.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_model": ("09_model.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_research": ("11_research.png", (SIDEBAR, 0, 2400, FULL_H)),
    "s_telemetry": ("12_telemetry.png", (SIDEBAR, 0, 2400, FULL_H)),
}
for name, (src, box) in crops.items():
    im = Image.open(S / src).convert("RGB").crop(box)
    im.save(OUT / f"{name}.jpg", quality=90, optimize=True)
    print(name, im.size)

# alert drawer: header, entities and risk (above the canned explainability box) + evidence and AI triage
a = Image.open(S / "20_alert_drawer.png").convert("RGB").crop((1680, 0, 2400, 770))
b = Image.open(S / "21_alert_triage.png").convert("RGB").crop((1680, 0, 2400, 1500))
gap = 24
bg = (13, 17, 28)
combo = Image.new("RGB", (a.width + b.width + gap, max(a.height, b.height)), bg)
combo.paste(a, (0, 0))
combo.paste(b, (a.width + gap, 0))
combo.save(OUT / "s_alert_drawer.jpg", quality=90, optimize=True)
print("s_alert_drawer", combo.size)

soc = Image.open(S / "25_soc_report_1.png").convert("RGB")
soc.save(OUT / "s_soc_report.jpg", quality=92, optimize=True)
print("s_soc_report", soc.size)
