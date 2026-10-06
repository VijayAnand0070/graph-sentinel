"""Figures for the GraphSentinel conference paper, drawn from project artifacts."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path("D:/graph_sentinel")
OUT = Path(__file__).resolve().parent / "figs"
OUT.mkdir(exist_ok=True)

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 7.5,
        "axes.titlesize": 7.5,
        "axes.labelsize": 7.5,
        "xtick.labelsize": 6.8,
        "ytick.labelsize": 6.8,
        "legend.fontsize": 6.6,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.5,
        "ytick.major.width": 0.5,
        "lines.linewidth": 1.1,
        "savefig.dpi": 600,
    }
)

INK = "#1f2d3d"
EDGE = "#44546a"
BLUE = "#dce8f5"
RED = "#fbe3e1"
GREEN = "#e3f1e0"
GREY = "#f2f2f2"
AMBER = "#fdf0d5"


def box(ax, x, y, w, h, title, body="", fc=BLUE, ec=EDGE, tsize=7.2, bsize=6.3, lw=0.7):
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.0,rounding_size=0.6", fc=fc, ec=ec, lw=lw
        )
    )
    if body:
        ax.text(x + w / 2, y + h * 0.70, title, ha="center", va="center", fontsize=tsize,
                fontweight="bold", color=INK)
        ax.text(x + w / 2, y + h * 0.32, body, ha="center", va="center", fontsize=bsize,
                color=INK, linespacing=1.15)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=tsize,
                fontweight="bold", color=INK, linespacing=1.15)


def arrow(ax, p, q, style="-|>", color=EDGE, lw=0.8, ls="-", rad=0.0, ms=6):
    ax.add_patch(
        FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=ms, color=color, lw=lw,
                        linestyle=ls, connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0)
    )


def lane(ax, y, h, label):
    ax.add_patch(FancyBboxPatch((6.2, y), 74.6, h, boxstyle="round,pad=0,rounding_size=0.8",
                                fc="#fafafa", ec="#c9c9c9", lw=0.5))
    ax.text(3.1, y + h / 2, label, ha="center", va="center", fontsize=6.6, color="#555555",
            rotation=90, fontweight="bold")


def fig_architecture() -> None:
    fig = plt.figure(figsize=(7.05, 3.25))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 46)
    ax.axis("off")

    # sources
    ax.add_patch(FancyBboxPatch((6.2, 41.6), 74.6, 3.6, boxstyle="round,pad=0,rounding_size=0.8",
                                fc="white", ec=EDGE, lw=0.6, ls=(0, (3, 2))))
    ax.text(43.5, 43.4, "Authentication logs:  LANL auth  \u00b7  Windows Security 4624/4625/4768/4769/4776  \u00b7  "
            "SSH  \u00b7  Zeek  \u00b7  Entra ID / Okta  \u00b7  CSV / JSONL",
            ha="center", va="center", fontsize=6.7, color=INK)

    lane(ax, 31.4, 9.0, "INGEST")
    lane(ax, 21.0, 9.4, "MODEL")
    lane(ax, 10.6, 9.4, "DECIDE")
    lane(ax, 0.4, 9.2, "RESPOND")

    box(ax, 8.0, 32.4, 34.0, 7.0, "Format detection + source adapters",
        "token-scored column inference; one canonical event\n(time, account, source host, destination host, outcome)")
    box(ax, 45.0, 32.4, 34.0, 7.0, "Entity dictionary",
        "stable integer id per account and host, frozen with\nthe checkpoint; unseen names hashed to OOV buckets")
    box(ax, 8.0, 22.2, 22.0, 7.0, "Causal feature engine",
        "27 features per event from\nstrictly earlier events only")
    box(ax, 33.0, 22.2, 24.0, 7.0, "Temporal graph network",
        "64-d memory per user and host;\nscore first, then update memory")
    box(ax, 60.0, 22.2, 19.0, 7.0, "Warm state",
        "memories and counters\nsaved and restored", fc="white")
    box(ax, 8.0, 11.8, 15.0, 7.0, "Evidence channels", "novelty \u00b7 burst \u00b7\npivot \u00b7 corroboration")
    box(ax, 25.0, 11.8, 16.0, 7.0, "Chain rule", "4 novel successful hops,\nsame account, 1,800 s", fc=RED)
    box(ax, 43.0, 11.8, 17.0, 7.0, "Noisy-OR fusion", "learned + explicit evidence;\nrule raises risk to floor")
    box(ax, 62.0, 11.8, 17.0, 7.0, "Two thresholds", "alert  \u03c4\u2090 = 0.329\ngate  \u03c4\u2093 = 0.846 (Wilson)", fc=AMBER)
    box(ax, 8.0, 1.4, 22.0, 7.0, "Response coordinator",
        "budgets: 20 actions/h, 1 per\naccount/h; dry-run by default", fc=RED)
    box(ax, 33.0, 1.4, 24.0, 7.0, "Prevention loop",
        "contain \u2192 verify (30 min) \u2192\nescalate (lock) \u2192 revert (2 h)", fc=RED)
    box(ax, 60.0, 1.4, 19.0, 7.0, "Executor + connectors",
        "directory, EDR, firewall;\nexact command and undo", fc="white")

    # right column
    ax.add_patch(FancyBboxPatch((82.6, 0.4), 16.8, 44.8, boxstyle="round,pad=0,rounding_size=0.8",
                                fc="#fafafa", ec="#c9c9c9", lw=0.5))
    ax.text(91.0, 43.6, "ANALYST SERVICES", ha="center", va="center", fontsize=6.6, color="#555555",
            fontweight="bold")
    box(ax, 83.6, 30.2, 14.8, 11.4, "LLM report agent",
        "LangGraph + Ollama\nprepare \u2192 draft \u2192\nvalidate \u2192 repair\ncitations checked;\ndeterministic fallback",
        fc=GREEN, bsize=6.0)
    box(ax, 83.6, 20.6, 14.8, 7.8, "Path ranker", "suspicious multi-hop\npaths for triage", bsize=6.0)
    box(ax, 83.6, 10.6, 14.8, 8.2, "Console \u00b7 API \u00b7 store",
        "alerts, cases, SOC\nreports, audit log", fc="white", bsize=6.0)
    ax.text(91.0, 5.6, "SOC analyst", ha="center", va="center", fontsize=7.0, fontweight="bold", color=INK)
    ax.text(91.0, 3.1, "approve \u00b7 keep \u00b7 lift", ha="center", va="center", fontsize=6.2, color=INK)

    # flow arrows
    arrow(ax, (25.0, 41.6), (25.0, 39.4))
    arrow(ax, (42.0, 35.9), (45.0, 35.9), style="<|-|>")
    arrow(ax, (19.0, 32.4), (19.0, 29.2))
    arrow(ax, (30.0, 25.7), (33.0, 25.7))
    arrow(ax, (57.0, 25.7), (60.0, 25.7), style="<|-|>")
    arrow(ax, (15.5, 22.2), (15.5, 18.8))
    arrow(ax, (45.0, 22.2), (51.5, 18.8))
    arrow(ax, (23.0, 15.3), (25.0, 15.3))
    arrow(ax, (41.0, 15.3), (43.0, 15.3))
    arrow(ax, (60.0, 15.3), (62.0, 15.3))
    arrow(ax, (70.5, 11.8), (70.5, 10.0), style="-")
    ax.plot([70.5, 19.0], [10.0, 10.0], color=EDGE, lw=0.8)
    arrow(ax, (19.0, 10.0), (19.0, 8.4))
    arrow(ax, (30.0, 4.9), (33.0, 4.9), style="<|-|>")
    arrow(ax, (57.0, 4.9), (60.0, 4.9))
    # to right column
    arrow(ax, (79.0, 15.3), (83.6, 15.3))
    arrow(ax, (79.0, 4.9), (83.6, 12.0))
    arrow(ax, (91.0, 18.8), (91.0, 20.6), style="<|-|>")
    arrow(ax, (91.0, 28.4), (91.0, 30.2), style="<|-|>")
    arrow(ax, (91.0, 10.6), (91.0, 7.0), style="<|-|>")
    fig.savefig(OUT / "fig1_architecture.png", facecolor="white")
    plt.close(fig)


def fig_tgn() -> None:
    fig = plt.figure(figsize=(3.45, 2.5))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 74)
    ax.axis("off")
    L0, L1, R0, R1 = 1.5, 44.5, 55.5, 98.5
    box(ax, L0, 62, R1 - L0, 9.5,
        r"Event  $e_k = (u_k, s_k, d_k, t_k, \mathbf{x}_k)$,  $\mathbf{x}_k \in \mathbb{R}^{27}$",
        fc="white", tsize=7.2)
    box(ax, L0, 45.5, L1 - L0, 12.5, "Memory read",
        r"$\mathbf{m}_u, \mathbf{m}_s, \mathbf{m}_d \in \mathbb{R}^{64}$ (before $e_k$)", bsize=6.6)
    box(ax, R0, 45.5, R1 - R0, 12.5, "Time encoding",
        r"$\psi(\Delta t_u), \psi(\Delta t_d) \in \mathbb{R}^{16}$", bsize=6.6)
    box(ax, L0, 25.5, L1 - L0, 15.5, "1. Score",
        "concat $\\to$ MLP(96) + residual\n$\\to p_k = P(\\mathrm{malicious})$", fc=AMBER, bsize=6.4)
    box(ax, R0, 25.5, R1 - R0, 15.5, "2. Messages",
        "$h(\\cdot)$ per endpoint, then\nattention over each node", bsize=6.4)
    box(ax, L0, 3, L1 - L0, 17.5, "Output",
        "$p_k$ goes to fusion; no event\nsees its own update", fc="white", bsize=6.4)
    box(ax, R0, 3, R1 - R0, 17.5, "3. Memory write",
        "LayerNorm $\\to$ GRUCell\n$\\mathbf{m}_i \\leftarrow \\mathrm{GRU}(\\cdot, \\mathbf{m}_i)$", fc=GREEN, bsize=6.4)
    arrow(ax, (23.0, 62), (23.0, 58.0))
    arrow(ax, (77.0, 62), (77.0, 58.0))
    arrow(ax, (23.0, 45.5), (23.0, 41.0))
    arrow(ax, (66.0, 45.5), (38.0, 41.0))
    arrow(ax, (77.0, 45.5), (77.0, 41.0))
    arrow(ax, (77.0, 25.5), (77.0, 20.5))
    arrow(ax, (23.0, 25.5), (23.0, 20.5))
    # the written memory is what the next event reads
    ax.plot([R0, 50.0, 50.0], [8.0, 8.0, 51.7], color="#6f6f6f", lw=0.7, ls=(0, (2, 1.4)))
    arrow(ax, (50.0, 51.7), (L1, 51.7), color="#6f6f6f", lw=0.7)
    ax.text(49.3, 16.5, "read by the next event", rotation=90, fontsize=5.4, color="#555555",
            ha="right", va="center")
    fig.savefig(OUT / "fig2_tgn.png", facecolor="white")
    plt.close(fig)


def fig_loop() -> None:
    fig = plt.figure(figsize=(3.45, 2.3))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 66)
    ax.axis("off")
    A, B, C = (1.5, 30.5), (35.5, 64.5), (69.5, 98.5)
    w = 29.0
    r1, r2, r3, h = 51.0, 28.0, 5.0, 12.0
    box(ax, A[0], r1, w, h, "Alert", r"$\rho_k \geq \tau_a$", fc="white", bsize=6.8)
    box(ax, B[0], r1, w, h, "Gate + budgets", "$\\rho_k \\geq \\tau_x$ and budget left\n(20/h, 1 per account/h)",
        fc=AMBER, bsize=5.9)
    box(ax, C[0], r1, w, h, "Contain", "force re-authentication:\nend sessions and tokens", fc=RED, bsize=5.9)
    box(ax, A[0], r2, w, h, "Analyst queue", "below gate or over\nbudget: human approval", fc="white", bsize=5.9)
    box(ax, B[0], r2, w, h, "Close", "contained; case and\naudit record kept", fc="white", bsize=5.9)
    box(ax, C[0], r2, w, h, "Verify", "account moves again\nwithin 30 min?", fc=BLUE, bsize=5.9)
    box(ax, B[0], r3, w, h, "Revert", "unlock after 2 h unless\nan analyst keeps it", fc=GREEN, bsize=5.9)
    box(ax, C[0], r3, w, h, "Escalate", "lock the account\n(reversible action)", fc=RED, bsize=5.9)
    grey = "#555555"
    arrow(ax, (A[1], r1 + h / 2), (B[0], r1 + h / 2))
    arrow(ax, (B[1], r1 + h / 2), (C[0], r1 + h / 2))
    ax.text((B[1] + C[0]) / 2, r1 + h / 2 + 1.3, "yes", fontsize=5.8, color=grey, ha="center")
    arrow(ax, (B[0] + 4, r1), (A[1] - 4, r2 + h))
    ax.text(31.0, 45.2, "no", fontsize=5.8, color=grey, ha="center")
    arrow(ax, (84.0, r1), (84.0, r2 + h))
    arrow(ax, (C[0], r2 + h / 2), (B[1], r2 + h / 2))
    ax.text((B[1] + C[0]) / 2, r2 + h / 2 + 1.3, "no", fontsize=5.8, color=grey, ha="center")
    arrow(ax, (84.0, r2), (84.0, r3 + h))
    ax.text(85.5, (r2 + r3 + h) / 2 - 0.8, "yes", fontsize=5.8, color=grey)
    arrow(ax, (C[0], r3 + h / 2), (B[1], r3 + h / 2))
    arrow(ax, (50.0, r3 + h), (50.0, r2))
    fig.savefig(OUT / "fig3_loop.png", facecolor="white")
    plt.close(fig)


def fig_prevention() -> None:
    report = json.loads((ROOT / "artifacts/prevention/production/prevention_report.json").read_text())
    op = report["operating_points"]["noisy_or"]
    detected = defaultdict(int)
    total = defaultdict(int)
    for c in op["campaigns"]:
        total[(c["family"], c["interval_seconds"])] += 1
        detected[(c["family"], c["interval_seconds"])] += int(c["detected"])
    intervals = sorted({k[1] for k in total})
    labels = [f"{i}s" if i < 60 else (f"{i // 60}m" if i < 3600 else "1h") for i in intervals]
    fig, (a, b) = plt.subplots(2, 1, figsize=(3.45, 2.8), gridspec_kw={"height_ratios": [1, 1], "hspace": 0.62})
    x = range(len(intervals))
    chain = [detected[("chain", i)] / total[("chain", i)] for i in intervals]
    fan = [detected[("fanout", i)] / total[("fanout", i)] for i in intervals]
    a.plot(x, chain, marker="o", ms=3.2, color="#b03a2e", label="chain (one account)")
    a.plot(x, fan, marker="s", ms=3.0, color="#2e5e8c", label="fan-out (rotating accounts)")
    a.axvspan(6.5, 9.4, color="#eeeeee", zorder=0)
    a.text(8.0, 0.62, "hops spaced beyond\nthe 1,800 s window", ha="center", fontsize=6.0, color="#444444")
    a.set_xticks(list(x), labels)
    a.set_ylim(-0.05, 1.08)
    a.set_ylabel("detection rate")
    a.set_xlabel("interval between attacker hops")
    a.set_title("(a) Detection by inter-hop interval (5 campaigns per point)", loc="left")
    a.legend(loc="center left", frameon=False, bbox_to_anchor=(0.0, 0.66))
    a.grid(axis="y", lw=0.3, color="#dddddd")

    loop = op["loop"]
    k = [row["kill_effectiveness"] for row in loop]
    without = [100 * row["prevented_without_escalation"] for row in loop]
    with_ = [100 * row["prevented_with_escalation"] for row in loop]
    b.plot(k, with_, marker="o", ms=3.2, color="#1e7b45", label="contain + verify + escalate")
    b.plot(k, without, marker="s", ms=3.0, color="#7f7f7f", ls="--", label="contain only")
    for kk, w, n in zip(k, with_, [row["campaigns_escalated"] for row in loop]):
        if n:
            b.annotate(f"{n}", (kk, w), textcoords="offset points", xytext=(0, 4), ha="center",
                       fontsize=5.8, color="#1e7b45")
    b.set_xlim(1.04, -0.04)
    b.set_ylim(-1, 17.5)
    b.set_xlabel("probability that a session reset actually stops the attacker")
    b.set_ylabel("attack hops prevented (%)")
    b.set_title("(b) Prevention when containment fails (labels: campaigns escalated)", loc="left")
    b.legend(loc="lower left", frameon=False)
    b.grid(axis="y", lw=0.3, color="#dddddd")
    for axis in (a, b):
        axis.spines[["top", "right"]].set_visible(False)
    fig.subplots_adjust(left=0.13, right=0.98, top=0.925, bottom=0.135)
    fig.savefig(OUT / "fig4_prevention.png", facecolor="white")
    plt.close(fig)


def fig_fullrate() -> None:
    data = json.loads((ROOT / "artifacts/prevention/chain_hop_strictness.json").read_text())
    # hour 24 holds 88 events (the day's tail) and carries no information
    hours = [row for row in data["hours"] if row["benign"] >= 1000]
    h = [row["hour"] for row in hours]
    loose = [1e4 * row["A"] / row["benign"] for row in hours]
    strict = [1e4 * row["C"] / row["benign"] for row in hours]
    fig, ax = plt.subplots(figsize=(3.45, 1.75))
    ax.semilogy(h, loose, marker="o", ms=2.6, color="#7f7f7f", label="any 4-hop chain within 1,800 s")
    shown = [(x, v) for x, v in zip(h, strict) if v > 0]
    ax.semilogy([x for x, _ in shown], [v for _, v in shown], marker="s", ms=2.6, color="#b03a2e",
                label="shipped rule: 4 novel successful hops")
    for x, v in zip(h, strict):
        if v == 0:
            ax.plot([x], [0.025], marker="v", ms=3.2, color="#b03a2e", mfc="white", mew=0.8)
            ax.text(x, 0.034, "0", fontsize=5.6, color="#b03a2e", ha="center", va="bottom")
    ax.axhline(25, color="#2e5e8c", lw=0.7, ls=":")
    ax.text(23.4, 30, "budget 25 / 10k", fontsize=6.0, color="#2e5e8c", ha="right", va="bottom")
    ax.set_xlabel("hour of the unsampled day (7.26 M benign events, cold start)")
    ax.set_ylabel("benign flags / 10k")
    ax.set_xlim(-0.5, 23.5)
    ax.set_ylim(0.02, 3000)
    ax.legend(loc="upper right", frameon=False, bbox_to_anchor=(1.0, 1.02))
    ax.grid(axis="y", lw=0.3, color="#dddddd", which="major")
    ax.spines[["top", "right"]].set_visible(False)
    fig.subplots_adjust(left=0.14, right=0.98, top=0.97, bottom=0.22)
    fig.savefig(OUT / "fig5_fullrate.png", facecolor="white")
    plt.close(fig)


def fig_otrf() -> None:
    events = json.loads((ROOT / "artifacts/otrf/otrf_events.json").read_text())
    by = defaultdict(list)
    for e in events:
        if e["label"] != "excluded":
            by[e["dataset"]].append(e)
    scored = {k: v for k, v in by.items() if any(e["attack"] for e in v)}
    order = sorted(scored, key=lambda k: -max(e["risk"] for e in scored[k] if e["attack"]))
    fig, ax = plt.subplots(figsize=(3.45, 1.95))
    for i, name in enumerate(order):
        benign = [e["risk"] for e in scored[name] if not e["attack"]]
        attack = [e["risk"] for e in scored[name] if e["attack"]]
        ax.scatter([i] * len(benign), benign, s=5, color="#9a9a9a", marker="o", lw=0, zorder=2,
                   label="benign event" if i == 0 else None)
        ax.scatter([i] * len(attack), attack, s=11, color="#b03a2e", marker="^", lw=0, zorder=3,
                   label="attack event" if i == 0 else None)
    ax.axhline(0.3292, color="#2e5e8c", lw=0.8, ls="--")
    ax.text(len(order) - 0.6, 0.36, "shipped alert threshold 0.329", fontsize=6.0, color="#2e5e8c",
            ha="right", va="bottom")
    ax.set_yscale("log")
    ax.set_ylim(0.004, 1.3)
    ax.set_xticks(range(len(order)), [str(i + 1) for i in range(len(order))], fontsize=5.8)
    ax.set_xlabel("OTRF recording (sorted by highest attack risk)")
    ax.set_ylabel("fused risk")
    ax.legend(loc="lower left", frameon=False, ncol=2, handletextpad=0.2, columnspacing=0.8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.subplots_adjust(left=0.14, right=0.98, top=0.97, bottom=0.22)
    fig.savefig(OUT / "fig6_otrf.png", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    fig_architecture()
    fig_tgn()
    fig_loop()
    fig_prevention()
    fig_fullrate()
    fig_otrf()
    print(sorted(p.name for p in OUT.glob("*.png")))
