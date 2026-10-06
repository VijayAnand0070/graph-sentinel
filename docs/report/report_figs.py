"""Diagrams and charts for the GraphSentinel project report (print, single column)."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch, Rectangle

ROOT = Path("D:/graph_sentinel")
OUT = Path(__file__).resolve().parent / "figs"
OUT.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "font.size": 9,
    "axes.titlesize": 9.5,
    "axes.labelsize": 9.5,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "legend.fontsize": 8.5,
    "axes.linewidth": 0.7,
    "savefig.dpi": 400,
})

INK = "#1f2d3d"
EDGE = "#44546a"
BLUE = "#dce8f5"
RED = "#fbe3e1"
GREEN = "#e3f1e0"
AMBER = "#fdf0d5"
GREY = "#f2f2f2"
VIOLET = "#ece5f6"


def box(ax, x, y, w, h, title, body="", fc=BLUE, ec=EDGE, ts=9.0, bs=7.8, lw=0.8, style="round"):
    shape = "round,pad=0.0,rounding_size=0.8" if style == "round" else "square,pad=0.0"
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=shape, fc=fc, ec=ec, lw=lw))
    if body:
        ax.text(x + w / 2, y + h * 0.70, title, ha="center", va="center", fontsize=ts, fontweight="bold",
                color=INK)
        ax.text(x + w / 2, y + h * 0.33, body, ha="center", va="center", fontsize=bs, color=INK,
                linespacing=1.2)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=ts, fontweight="bold",
                color=INK, linespacing=1.2)


def arrow(ax, p, q, style="-|>", color=EDGE, lw=0.9, ls="-", rad=0.0, ms=8, label=None, lpos=0.5,
          loff=(0, 0), lsize=7.2, lcolor="#333333", lha="center"):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=ms, color=color, lw=lw, linestyle=ls,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0))
    if label:
        x = p[0] + (q[0] - p[0]) * lpos + loff[0]
        y = p[1] + (q[1] - p[1]) * lpos + loff[1]
        ax.text(x, y, label, fontsize=lsize, color=lcolor, ha=lha, va="center", style="italic",
                bbox=dict(fc="white", ec="none", pad=0.6))


def canvas(w_in, h_in, xmax, ymax):
    fig = plt.figure(figsize=(w_in, h_in))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, xmax)
    ax.set_ylim(0, ymax)
    ax.axis("off")
    return fig, ax


# --------------------------------------------------------------------------- architecture
def fig_architecture() -> None:
    fig, ax = canvas(6.3, 7.6, 100, 122)

    def band(y, h, label, fc="#fafafa"):
        ax.add_patch(FancyBboxPatch((1, y), 98, h, boxstyle="round,pad=0,rounding_size=1.2", fc=fc,
                                    ec="#c4c4c4", lw=0.6))
        ax.text(2.6, y + h - 2.3, label, fontsize=8.2, fontweight="bold", color="#555555", ha="left")

    # sources
    ax.add_patch(FancyBboxPatch((1, 111), 98, 10, boxstyle="round,pad=0,rounding_size=1.2", fc="white",
                                ec=EDGE, lw=0.7, ls=(0, (3, 2))))
    ax.text(50, 118.4, "AUTHENTICATION LOG SOURCES", fontsize=8.2, fontweight="bold", color="#555555", ha="center")
    ax.text(50, 113.9, "LANL auth  \u00b7  Windows Security (4624, 4625, 4768, 4769, 4776)  \u00b7  SSH  \u00b7  Zeek\n"
            "Microsoft Entra ID  \u00b7  Okta  \u00b7  generic CSV / JSONL", fontsize=8.0, color=INK, ha="center",
            va="center", linespacing=1.25)

    band(88, 20, "INGESTION LAYER")
    box(ax, 4, 90, 44, 13, "Format detection + adapters",
        "column scoring picks the adapter;\ncanonical event: time, account,\nsource, destination, outcome")
    box(ax, 52, 90, 44, 13, "Entity dictionary",
        "frozen with the checkpoint;\nunseen names hashed into\n4,096 user / 16,384 host buckets")

    band(64, 21, "MODEL LAYER")
    box(ax, 4, 66, 28, 14, "Causal features", "27 features per event,\ncomputed from strictly\nearlier events")
    box(ax, 36, 66, 30, 14, "Temporal graph network",
        "64-d memory per user/host;\nscore first, then update;\n107,585 parameters")
    box(ax, 70, 66, 26, 14, "Warm state store", "feature counters and\nnode memories saved\nand restored", fc="white")

    band(40, 21, "DECISION LAYER")
    box(ax, 4, 42, 21, 14, "Evidence\nchannels", "novelty, burst,\npivot, corroboration", ts=8.6, bs=7.4)
    box(ax, 27.5, 42, 21, 14, "Chain rule", "4 novel hops by\none account in\n1,800 s", fc=RED, ts=8.6, bs=7.4)
    box(ax, 51, 42, 21, 14, "Noisy-OR\nfusion", "risk \u03c1 in [0, 1];\nrule raises floor", ts=8.6, bs=7.4)
    box(ax, 74.5, 42, 21.5, 14, "Thresholds", "alert  \u03c4\u2090 = 0.329\ngate  \u03c4\u2093 = 0.846\n(Wilson bound)",
        fc=AMBER, ts=8.6, bs=7.4)

    band(16, 21, "RESPONSE LAYER")
    box(ax, 4, 18, 28, 14, "Response coordinator", "budgets 20/h and\n1 per account/h;\ndry-run by default", fc=RED)
    box(ax, 36, 18, 30, 14, "Prevention loop", "contain \u2192 verify (30 min)\n\u2192 escalate (lock)\n\u2192 revert (2 h)", fc=RED)
    box(ax, 70, 18, 26, 14, "Executor + connectors", "directory, EDR, firewall;\ncommand + undo\nrecorded", fc="white")

    # analyst services strip
    ax.add_patch(FancyBboxPatch((1, 1), 98, 13, boxstyle="round,pad=0,rounding_size=1.2", fc="#f4f9f3",
                                ec="#c4c4c4", lw=0.6))
    ax.text(2.6, 11.6, "ANALYST SERVICES", fontsize=8.2, fontweight="bold", color="#555555", ha="left")
    box(ax, 4, 2.5, 22, 8, "LLM report agent", "grounded, cited", fc=GREEN, ts=8.4, bs=7.4)
    box(ax, 28.5, 2.5, 20, 8, "Path ranker", "multi-hop paths", fc="white", ts=8.4, bs=7.4)
    box(ax, 51, 2.5, 22, 8, "Console \u00b7 API \u00b7 store", "alerts, cases, audit", fc="white", ts=8.4, bs=7.4)
    box(ax, 75.5, 2.5, 20.5, 8, "SOC analyst", "approve \u00b7 keep \u00b7 lift", fc=VIOLET, ts=8.4, bs=7.4)

    # vertical flow
    arrow(ax, (26, 111), (26, 103))
    arrow(ax, (48, 96.5), (52, 96.5), style="<|-|>")
    arrow(ax, (18, 90), (18, 80))
    arrow(ax, (32, 73), (36, 73))
    arrow(ax, (66, 73), (70, 73), style="<|-|>")
    arrow(ax, (14.5, 66), (14.5, 56))
    arrow(ax, (51, 66), (61.5, 56))
    arrow(ax, (25, 49), (27.5, 49))
    arrow(ax, (48.5, 49), (51, 49))
    arrow(ax, (72, 49), (74.5, 49))
    arrow(ax, (85, 42), (85, 37.5), style="-")
    ax.plot([85, 18], [37.5, 37.5], color=EDGE, lw=0.9)
    arrow(ax, (18, 37.5), (18, 32))
    arrow(ax, (32, 25), (36, 25), style="<|-|>")
    arrow(ax, (66, 25), (70, 25))
    arrow(ax, (51, 18), (51, 10.5))
    arrow(ax, (73, 6.5), (75.5, 6.5), style="<|-|>")
    arrow(ax, (26, 6.5), (28.5, 6.5), style="<|-|>")
    arrow(ax, (48.5, 6.5), (51, 6.5), style="<|-|>")
    fig.savefig(OUT / "r_architecture.png", facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------- DFD
def fig_dfd() -> None:
    fig, ax = canvas(6.3, 5.3, 100, 90)

    def proc(x, y, w, h, num, text, fc=BLUE):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=2.4", fc=fc, ec=EDGE,
                                    lw=0.9))
        ax.plot([x + 1.0, x + w - 1.0], [y + h - 3.6, y + h - 3.6], color=EDGE, lw=0.6)
        ax.text(x + w / 2, y + h - 1.8, num, ha="center", va="center", fontsize=8.0, fontweight="bold", color=INK)
        ax.text(x + w / 2, y + (h - 3.6) / 2, text, ha="center", va="center", fontsize=7.8, color=INK,
                linespacing=1.15)

    def entity(x, y, w, h, text):
        ax.add_patch(Rectangle((x, y), w, h, fc="white", ec=INK, lw=1.3))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=8.0, fontweight="bold",
                color=INK, linespacing=1.15)

    def store(x, y, w, h, sid, text):
        ax.add_patch(Rectangle((x, y), w, h, fc=GREY, ec="none"))
        for yy in (y, y + h):
            ax.plot([x, x + w], [yy, yy], color=INK, lw=1.0)
        ax.plot([x, x], [y, y + h], color=INK, lw=1.0)
        ax.plot([x + 5.5, x + 5.5], [y, y + h], color=INK, lw=0.8)
        ax.text(x + 2.75, y + h / 2, sid, ha="center", va="center", fontsize=7.6, fontweight="bold", color=INK)
        ax.text(x + 5.5 + (w - 5.5) / 2, y + h / 2, text, ha="center", va="center", fontsize=7.4, color=INK,
                linespacing=1.1)

    def note(x, y, text, ha="center"):
        ax.text(x, y, text, fontsize=6.9, style="italic", ha=ha, va="center", color="#333333", linespacing=1.1)

    # row 1
    entity(1, 70, 15, 13, "Authentication\nlog sources")
    proc(21, 69, 16, 15, "1.0", "Ingest and\nnormalise")
    proc(42, 69, 16, 15, "2.0", "Compute\ncausal features")
    proc(63, 69, 16, 15, "3.0", "Score event\nwith the TGN")
    proc(84, 69, 15, 15, "4.0", "Fuse evidence,\nchain rule")
    # row 2
    store(18, 45, 22, 7, "D1", "Entity dictionary")
    store(44, 45, 25, 7, "D2", "Feature and\nmemory state")
    proc(84, 41, 15, 15, "5.0", "Decide: alert,\ngate, budget")
    # row 3
    entity(1, 10, 15, 13, "SOC analyst")
    proc(21, 9, 16, 15, "7.0", "Explain and\nreport (LLM)", fc=GREEN)
    store(40, 13, 21, 8, "D3", "Alert, case and\naudit store")
    proc(64, 9, 16, 15, "6.0", "Contain, verify,\nescalate, revert", fc=RED)
    entity(84, 10, 15, 13, "Directory,\nEDR, firewall")

    for x0, x1, text in ((16, 21, "raw auth\nrecords"), (37, 42, "canonical\nevents"),
                         (58, 63, "feature\nvector x\u2096"), (79, 84, "prob.\np\u2096")):
        arrow(ax, (x0, 76.5), (x1, 76.5))
        note((x0 + x1) / 2, 87.2, text)
    arrow(ax, (91.5, 69), (91.5, 56))
    note(90.5, 62.5, "fused\nrisk \u03c1\u2096", ha="right")
    arrow(ax, (29, 69), (29, 52), style="<|-|>")
    note(30.5, 60.5, "entity ids", ha="left")
    arrow(ax, (50, 69), (52, 52), style="<|-|>")
    note(52.5, 60.5, "counters", ha="left")
    arrow(ax, (71, 69), (64, 52), style="<|-|>")
    note(69.5, 58.5, "memory", ha="left")
    arrow(ax, (84, 49), (52, 21))
    note(63.5, 37.5, "alerts", ha="center")
    arrow(ax, (88, 41), (76, 24))
    note(85.5, 31.5, "action\nplan", ha="left")
    arrow(ax, (80, 16.5), (84, 16.5))
    note(82, 5.8, "commands\n+ undo")
    arrow(ax, (64, 17), (61, 17))
    note(62.5, 6.4, "action\nrecords")
    arrow(ax, (40, 16.5), (37, 16.5))
    note(38.5, 27.5, "incident\nfacts")
    arrow(ax, (21, 16.5), (16, 16.5))
    note(18.5, 27.5, "grounded\nreport")
    ax.plot([8.5, 8.5, 69, 69], [10, 2.2, 2.2, 5.5], color=EDGE, lw=0.9)
    arrow(ax, (69, 5.5), (69, 9))
    ax.text(40, 2.2, "approve / keep / lift decisions", fontsize=6.9, style="italic", ha="center", va="center",
            color="#333333", bbox=dict(fc="white", ec="none", pad=0.4))
    fig.savefig(OUT / "r_dfd.png", facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------- use case
def stick(ax, x, y, name, s=1.0):
    ax.add_patch(plt.Circle((x, y + 9 * s), 2.0 * s, fc="white", ec=INK, lw=1.1))
    ax.plot([x, x], [y + 7 * s, y + 1.5 * s], color=INK, lw=1.1)
    ax.plot([x - 3.2 * s, x + 3.2 * s], [y + 5.2 * s, y + 5.2 * s], color=INK, lw=1.1)
    ax.plot([x, x - 2.8 * s], [y + 1.5 * s, y - 3 * s], color=INK, lw=1.1)
    ax.plot([x, x + 2.8 * s], [y + 1.5 * s, y - 3 * s], color=INK, lw=1.1)
    ax.text(x, y - 5.6 * s, name, ha="center", va="top", fontsize=8.4, fontweight="bold", color=INK,
            linespacing=1.1)


def fig_usecase() -> None:
    fig, ax = canvas(6.3, 6.4, 100, 102)
    ax.add_patch(Rectangle((22, 1), 56, 99.5, fc="#fbfbfb", ec=INK, lw=1.1))
    ax.text(50, 97, "GraphSentinel", ha="center", va="center", fontsize=10, fontweight="bold", color=INK)
    cases = [
        ("Stream and score\nauthentication events", 88),
        ("Monitor live detection\ndashboard", 79),
        ("Investigate alert\nand evidence", 70),
        ("Explore suspicious paths\nand attack chains", 61),
        ("Generate triage /\nSOC incident report", 52),
        ("Approve, keep or lift\nresponse action", 43),
        ("Contain account\nautomatically", 34),
        ("Onboard log source\n(auto-detect format)", 25),
        ("Configure response mode\n(off / dry-run / armed)", 16),
        ("Train and evaluate\nthe model", 7),
    ]
    pos = {}
    for text, y in cases:
        ax.add_patch(Ellipse((50, y), 46, 7.8, fc=BLUE if "Contain" not in text else RED, ec=EDGE, lw=0.9))
        ax.text(50, y, text, ha="center", va="center", fontsize=7.9, color=INK, linespacing=1.1)
        pos[text.split("\n")[0]] = y
    stick(ax, 9, 66, "SOC analyst")
    stick(ax, 9, 20, "Security\nadministrator")
    stick(ax, 91, 80, "Log source\n(DC / SIEM)")
    stick(ax, 91, 24, "Directory /\nEDR connector")
    stick(ax, 91, 52, "Local LLM\n(Ollama)")

    def link(ax_x, ax_y, y, side):
        x = 27 if side == "L" else 73
        ax.plot([ax_x, x], [ax_y, y], color=EDGE, lw=0.8)

    for key in ("Monitor live detection", "Investigate alert", "Explore suspicious paths", "Generate triage /",
                "Approve, keep or lift"):
        link(12.5, 71, pos[key], "L")
    for key in ("Onboard log source", "Configure response mode", "Train and evaluate"):
        link(12.5, 25, pos[key], "L")
    link(87.5, 85, pos["Stream and score"], "R")
    link(87.5, 57, pos["Generate triage /"], "R")
    for key in ("Contain account", "Approve, keep or lift"):
        link(87.5, 29, pos[key], "R")
    fig.savefig(OUT / "r_usecase.png", facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------- sequence
def fig_sequence() -> None:
    fig, ax = canvas(6.3, 6.6, 100, 104)
    lanes = ["Log source", "API gateway", "Feature\nengine", "TGN scorer", "Fusion and\nrules", "Response\ncoordinator",
             "Executor", "Audit / store"]
    xs = [6 + i * 12.5 for i in range(len(lanes))]
    for x, name in zip(xs, lanes):
        ax.add_patch(FancyBboxPatch((x - 5.6, 94), 11.2, 8, boxstyle="round,pad=0,rounding_size=0.8", fc=BLUE,
                                    ec=EDGE, lw=0.8))
        ax.text(x, 98, name, ha="center", va="center", fontsize=7.6, fontweight="bold", color=INK, linespacing=1.05)
        ax.plot([x, x], [2, 94], color="#8a8a8a", lw=0.7, ls=(0, (4, 3)))
    msgs = [
        (0, 1, "POST /api/v1/live/events", 89),
        (1, 1, "order check (strictly increasing time)", 84),
        (1, 2, "event e\u2096", 79),
        (2, 3, "features x\u2096 (past only)", 74),
        (3, 3, "score with memory before e\u2096", 69),
        (3, 4, "probability p\u2096", 64),
        (3, 3, "then update memory (GRU)", 59),
        (4, 4, "noisy-OR, chain-rule floor \u2192 \u03c1\u2096", 54),
        (4, 7, "alert if \u03c1\u2096 \u2265 \u03c4\u2090", 49),
        (4, 5, "plan if \u03c1\u2096 \u2265 \u03c4\u2093", 44),
        (5, 5, "budget and 30-min verify check", 39),
        (5, 6, "force_reauth / lock_account", 34),
        (6, 6, "dry-run or armed connector", 29),
        (6, 7, "command, undo, outcome", 24),
        (5, 7, "escalation and revert timer (2 h)", 19),
        (1, 0, "200 OK: risks and alert ids", 13),
        (7, 1, "WebSocket push to console", 7),
    ]
    for a, b, text, y in msgs:
        if a == b:
            x = xs[a]
            ax.plot([x, x + 3.5, x + 3.5], [y + 1.6, y + 1.6, y - 1.6], color=INK, lw=0.8)
            arrow(ax, (x + 3.5, y - 1.6), (x + 0.3, y - 1.6), lw=0.8, ms=6)
            right = x > 70
            ax.text(x - 1.2 if right else x + 4.3, y, text, fontsize=7.0, color=INK, va="center",
                    ha="right" if right else "left", bbox=dict(fc="white", ec="none", pad=0.3))
        else:
            ls = (0, (4, 2)) if b < a else "-"
            arrow(ax, (xs[a], y), (xs[b], y), lw=0.8, ms=6, ls=ls)
            xm = (xs[a] + xs[b]) / 2
            ax.text(xm, y + 1.8, text, fontsize=7.0, color=INK, va="center", ha="center",
                    bbox=dict(fc="white", ec="none", pad=0.3))
    fig.savefig(OUT / "r_sequence.png", facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------- methodology
def fig_methodology() -> None:
    fig, ax = canvas(6.3, 6.2, 100, 98)
    steps = [
        ("1. Data acquisition", "LANL: 1.05 billion auth events, 749 red-team events\nOTRF: 29 Windows lateral-movement recordings", GREY),
        ("2. Pre-processing", "drop local logons \u00b7 stride-sample benign events\nentity dictionary \u00b7 chronological train/val/test split", BLUE),
        ("3. Causal feature engineering", "27 features per event from strictly earlier events\n(recency, novelty, windows, graph structure)", BLUE),
        ("4. TGN training", "weighted BCE, AdamW, 16 epochs, 60-s buckets\nscore-before-update, 107,585 parameters", AMBER),
        ("5. Fusion and rule calibration", "noisy-OR reliabilities fitted on validation\nchain rule priced on an unsampled day", AMBER),
        ("6. Threshold derivation", "alert threshold at 25 false positives / 10k\nexecution gate from Wilson lower bound \u2265 0.75", AMBER),
        ("7. Evaluation", "baselines, bootstrap intervals, entity hold-out,\nablation, prevention replay, OTRF external test", GREEN),
        ("8. Deployment", "FastAPI service, console, bounded response loop,\nlocal LLM reports, audit trail", GREEN),
    ]
    y = 88
    for i, (title, body, fc) in enumerate(steps):
        col = i % 2
        row = i // 2
        x = 3 if col == 0 else 52
        yy = 76 - row * 24
        ax.add_patch(FancyBboxPatch((x, yy), 45, 18, boxstyle="round,pad=0,rounding_size=1.2", fc=fc, ec=EDGE,
                                    lw=0.8))
        ax.text(x + 22.5, yy + 13.6, title, ha="center", va="center", fontsize=9.2, fontweight="bold", color=INK)
        ax.text(x + 22.5, yy + 6.6, body, ha="center", va="center", fontsize=7.8, color=INK, linespacing=1.25)
    # arrows: 1->2 (right), 2->3 (down-left), 3->4 (right), ...
    for row in range(4):
        yy = 76 - row * 24
        arrow(ax, (48, yy + 9), (52, yy + 9))
        if row < 3:
            arrow(ax, (74.5, yy), (25.5, yy - 6), rad=0.0)
    ax.text(50, 96, "GraphSentinel methodology", ha="center", va="center", fontsize=10, fontweight="bold", color=INK)
    fig.savefig(OUT / "r_methodology.png", facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------- agent workflow
def fig_agent() -> None:
    fig, ax = canvas(6.3, 3.6, 100, 58)
    box(ax, 2, 36, 18, 14, "prepare", "evidence bundle\nE-nnn / F-nnn ids", fc=GREY, bs=7.6)
    box(ax, 26, 36, 18, 14, "draft", "local LLM\n(qwen3.5:4b) \u2192 JSON", fc=BLUE, bs=7.6)
    box(ax, 50, 36, 20, 14, "validate", "citations exist, ids real,\nactions and severity\nunchanged", fc=AMBER, bs=7.4)
    box(ax, 76, 36, 22, 14, "accepted report", "badge: AI-generated,\ncitation-checked", fc=GREEN, bs=7.6)
    box(ax, 50, 8, 20, 14, "repair", "prompt names the\nexact violation", fc=RED, bs=7.6)
    box(ax, 76, 8, 22, 14, "deterministic writer", "same facts, template\nbadge: fallback used", fc="white", bs=7.4)
    arrow(ax, (20, 43), (26, 43))
    arrow(ax, (44, 43), (50, 43))
    arrow(ax, (70, 43), (76, 43), label="pass", loff=(0, 2.4))
    arrow(ax, (60, 36), (60, 22), label="fail", loff=(3.4, 0))
    arrow(ax, (50, 15), (35, 36), rad=-0.25, label="retry (\u2264 3 attempts)", lpos=0.5, loff=(-7, -3))
    arrow(ax, (70, 15), (76, 15))
    ax.text(73, 4.2, "after 3 failed attempts, or when the model is unreachable", fontsize=7.2,
            style="italic", ha="center", va="center", color="#333333")
    ax.text(50, 54, "LangGraph workflow of the grounded report agent", ha="center", fontsize=9.5,
            fontweight="bold", color=INK)
    fig.savefig(OUT / "r_agent.png", facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------- charts
def fig_training() -> None:
    t = json.loads((ROOT / "artifacts/metrics/tgn_lanl_545k_split_v3_training-candidate-c6912ac36724.json").read_text())
    ep = [e["epoch"] for e in t["epoch_history"]]
    pr = [e["validation_pr_auc"] for e in t["epoch_history"]]
    loss = [e["train_loss"] for e in t["epoch_history"]]
    fig, ax = plt.subplots(figsize=(5.6, 2.9))
    ax.plot(ep, pr, marker="o", ms=3.5, color="#2e5e8c", label="validation PR-AUC")
    ax.set_xlabel("epoch")
    ax.set_ylabel("validation PR-AUC", color="#2e5e8c")
    ax.set_ylim(0.6, 1.0)
    ax.set_xticks(ep)
    ax2 = ax.twinx()
    ax2.plot(ep, loss, marker="s", ms=3.2, color="#b03a2e", ls="--", label="training loss")
    ax2.set_ylabel("weighted BCE training loss", color="#b03a2e")
    ax2.set_ylim(0, 0.16)
    lines = ax.get_lines() + ax2.get_lines()
    ax.legend(lines, [l.get_label() for l in lines], loc="upper center", frameon=False, ncol=2)
    ax.grid(axis="y", lw=0.3, color="#dddddd")
    for a in (ax, ax2):
        a.spines["top"].set_visible(False)
    fig.subplots_adjust(left=0.11, right=0.88, top=0.96, bottom=0.16)
    fig.savefig(OUT / "r_training.png", facecolor="white")
    plt.close(fig)


def fig_detectors() -> None:
    names = ["Rule", "Rarity", "Isolation\nforest", "Logistic\nregression", "Linear\nfusion", "Noisy-OR\n(shipped)", "TGN"]
    c1 = [0.071, 0.007, 0.041, 0.246, 0.577, 0.805, 0.821]
    c2 = [0.548, 0.288, 0.244, 0.956, 0.676, 0.604, 0.566]
    fig, ax = plt.subplots(figsize=(5.8, 2.9))
    import numpy as np
    x = np.arange(len(names))
    w = 0.38
    b1 = ax.bar(x - w / 2, c1, w, color="#2e5e8c", label="C1 (shipped corpus, 126 test attacks)")
    b2 = ax.bar(x + w / 2, c2, w, color="#d98c2b", label="C2 (corrected corpus, 101 test attacks)")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.015, f"{b.get_height():.3f}", ha="center",
                    fontsize=6.8, rotation=90, va="bottom")
    ax.set_xticks(x, names)
    ax.set_ylabel("test PR-AUC")
    ax.set_ylim(0, 1.18)
    ax.legend(loc="upper left", frameon=False, ncol=1)
    ax.grid(axis="y", lw=0.3, color="#dddddd")
    ax.spines[["top", "right"]].set_visible(False)
    fig.subplots_adjust(left=0.1, right=0.99, top=0.97, bottom=0.2)
    fig.savefig(OUT / "r_detectors.png", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    fig_architecture()
    fig_dfd()
    fig_usecase()
    fig_sequence()
    fig_methodology()
    fig_agent()
    fig_training()
    fig_detectors()
    print(sorted(p.name for p in OUT.glob("r_*.png")))
