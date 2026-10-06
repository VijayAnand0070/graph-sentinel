from pathlib import Path

p = Path(__file__).resolve().parent / "report_figs.py"
s = p.read_text(encoding="utf-8")


def rep(old, new):
    global s
    assert s.count(old) == 1, old[:80]
    s = s.replace(old, new)


# DFD: one store holds alerts, cases and the audit log (it is one SQLite store in the product)
rep('''    store(40, 13, 21, 7, "D3", "Alert and\\nincident store")''',
    '''    store(40, 13, 21, 8, "D3", "Alert, case and\\naudit store")''')
rep('''    store(63, 29, 18, 7, "D4", "Audit log")\n''', "")
rep('''    arrow(ax, (86, 41), (57, 20))
    note(66, 33.5, "alerts", ha="center")
    arrow(ax, (95, 41), (78, 24))
    note(88.5, 28.5, "action\\nplan", ha="left")''',
    '''    arrow(ax, (84, 49), (52, 21))
    note(63.5, 37.5, "alerts", ha="center")
    arrow(ax, (88, 41), (76, 24))
    note(85.5, 31.5, "action\\nplan", ha="left")''')
rep('''    arrow(ax, (72, 24), (72, 29))
    note(73.2, 39.2, "action records", ha="left")''',
    '''    arrow(ax, (64, 17), (61, 17))
    note(62.5, 6.4, "action\\nrecords")''')

# agent: move the fallback label under the boxes
rep('''    arrow(ax, (70, 15), (76, 15), label="budget spent\\nor model down", loff=(0, 5.2), lsize=6.8)''',
    '''    arrow(ax, (70, 15), (76, 15))
    ax.text(73, 4.2, "after 3 failed attempts, or when the model is unreachable", fontsize=7.2,
            style="italic", ha="center", va="center", color="#333333")''')

# training chart legend
rep('''    ax.legend(lines, [l.get_label() for l in lines], loc="center right", frameon=False)''',
    '''    ax.legend(lines, [l.get_label() for l in lines], loc="upper center", frameon=False, ncol=2)''')
p.write_text(s, encoding="utf-8")
print("patched 2")
