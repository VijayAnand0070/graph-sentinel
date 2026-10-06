from pathlib import Path

p = Path(__file__).resolve().parent / "report_figs.py"
s = p.read_text(encoding="utf-8")

# ---------------------------------------------------------------- new DFD
start = s.index("# --------------------------------------------------------------------------- DFD")
end = s.index("# --------------------------------------------------------------------------- use case")
new_dfd = '''# --------------------------------------------------------------------------- DFD
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
    entity(1, 70, 15, 13, "Authentication\\nlog sources")
    proc(21, 69, 16, 15, "1.0", "Ingest and\\nnormalise")
    proc(42, 69, 16, 15, "2.0", "Compute\\ncausal features")
    proc(63, 69, 16, 15, "3.0", "Score event\\nwith the TGN")
    proc(84, 69, 15, 15, "4.0", "Fuse evidence,\\nchain rule")
    # row 2
    store(18, 45, 22, 7, "D1", "Entity dictionary")
    store(44, 45, 25, 7, "D2", "Feature and\\nmemory state")
    proc(84, 41, 15, 15, "5.0", "Decide: alert,\\ngate, budget")
    # row 3
    entity(1, 10, 15, 13, "SOC analyst")
    proc(21, 9, 16, 15, "7.0", "Explain and\\nreport (LLM)", fc=GREEN)
    store(40, 13, 21, 7, "D3", "Alert and\\nincident store")
    proc(64, 9, 16, 15, "6.0", "Contain, verify,\\nescalate, revert", fc=RED)
    entity(84, 10, 15, 13, "Directory,\\nEDR, firewall")
    store(63, 29, 18, 7, "D4", "Audit log")

    for x0, x1, text in ((16, 21, "raw auth\\nrecords"), (37, 42, "canonical\\nevents"),
                         (58, 63, "feature\\nvector x\\u2096"), (79, 84, "prob.\\np\\u2096")):
        arrow(ax, (x0, 76.5), (x1, 76.5))
        note((x0 + x1) / 2, 87.2, text)
    arrow(ax, (91.5, 69), (91.5, 56))
    note(90.5, 62.5, "fused\\nrisk \\u03c1\\u2096", ha="right")
    arrow(ax, (29, 69), (29, 52), style="<|-|>")
    note(30.5, 60.5, "entity ids", ha="left")
    arrow(ax, (50, 69), (52, 52), style="<|-|>")
    note(52.5, 60.5, "counters", ha="left")
    arrow(ax, (71, 69), (64, 52), style="<|-|>")
    note(69.5, 58.5, "memory", ha="left")
    arrow(ax, (86, 41), (57, 20))
    note(66, 33.5, "alerts", ha="center")
    arrow(ax, (95, 41), (78, 24))
    note(88.5, 28.5, "action\\nplan", ha="left")
    arrow(ax, (80, 16.5), (84, 16.5))
    note(82, 5.8, "commands\\n+ undo")
    arrow(ax, (72, 24), (72, 29))
    note(73.2, 39.2, "action records", ha="left")
    arrow(ax, (40, 16.5), (37, 16.5))
    note(38.5, 27.5, "incident\\nfacts")
    arrow(ax, (21, 16.5), (16, 16.5))
    note(18.5, 27.5, "grounded\\nreport")
    ax.plot([8.5, 8.5, 69, 69], [10, 2.2, 2.2, 5.5], color=EDGE, lw=0.9)
    arrow(ax, (69, 5.5), (69, 9))
    ax.text(40, 2.2, "approve / keep / lift decisions", fontsize=6.9, style="italic", ha="center", va="center",
            color="#333333", bbox=dict(fc="white", ec="none", pad=0.4))
    fig.savefig(OUT / "r_dfd.png", facecolor="white")
    plt.close(fig)


'''
s = s[:start] + new_dfd + s[end:]

# ---------------------------------------------------------------- use case
s = s.replace('ax.add_patch(Rectangle((22, 2), 56, 98, fc="#fbfbfb", ec=INK, lw=1.1))',
              'ax.add_patch(Rectangle((22, 1), 56, 99.5, fc="#fbfbfb", ec=INK, lw=1.1))')
a = s.index('        ("Stream and score\\nauthentication events", 88),')
b = s.index('    pos = {}')
s = s[:a] + '''        ("Stream and score\\nauthentication events", 88),
        ("Monitor live detection\\ndashboard", 79),
        ("Investigate alert\\nand evidence", 70),
        ("Explore suspicious paths\\nand attack chains", 61),
        ("Generate triage /\\nSOC incident report", 52),
        ("Approve, keep or lift\\nresponse action", 43),
        ("Contain account\\nautomatically", 34),
        ("Onboard log source\\n(auto-detect format)", 25),
        ("Configure response mode\\n(off / dry-run / armed)", 16),
        ("Train and evaluate\\nthe model", 7),
    ]
''' + s[b:]
s = s.replace("ax.add_patch(Ellipse((50, y), 46, 8.2,", "ax.add_patch(Ellipse((50, y), 46, 7.8,")
s = s.replace('stick(ax, 91, 38, "Directory /\\nEDR connector")', 'stick(ax, 91, 24, "Directory /\\nEDR connector")')
s = s.replace('stick(ax, 91, 58, "Local LLM\\n(Ollama)")', 'stick(ax, 91, 52, "Local LLM\\n(Ollama)")')
s = s.replace('link(87.5, 63, pos["Generate triage /"], "R")', 'link(87.5, 57, pos["Generate triage /"], "R")')
s = s.replace('        link(87.5, 43, pos[key], "R")', '        link(87.5, 29, pos[key], "R")')
x0 = s.index("    # <<extend>> from containment to scoring")
x1 = s.index('    fig.savefig(OUT / "r_usecase.png"')
s = s[:x0] + s[x1:]

# ---------------------------------------------------------------- sequence: right-lane self-call labels
old = '''            ax.text(x + 4.3, y, text, fontsize=7.0, color=INK, va="center", ha="left",
                    bbox=dict(fc="white", ec="none", pad=0.3))'''
new = '''            right = x > 70
            ax.text(x - 1.2 if right else x + 4.3, y, text, fontsize=7.0, color=INK, va="center",
                    ha="right" if right else "left", bbox=dict(fc="white", ec="none", pad=0.3))'''
assert s.count(old) == 1
s = s.replace(old, new)
p.write_text(s, encoding="utf-8")
print("patched")
