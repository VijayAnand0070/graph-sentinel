"""Patch report_build.py for the AIML department front matter (line-anchored edits)."""

from pathlib import Path

p = Path(__file__).resolve().parent / "report_build.py"
lines = p.read_text(encoding="utf-8").split("\n")


def find(prefix: str, start: int = 0) -> int:
    for i in range(start, len(lines)):
        if lines[i].strip().startswith(prefix):
            return i
    raise SystemExit(f"not found: {prefix}")


def replace_line(prefix: str, new: str | list[str]) -> None:
    i = find(prefix)
    lines[i:i + 1] = new if isinstance(new, list) else [new]


def replace_block(first_prefix: str, last_prefix: str, new: list[str]) -> None:
    i = find(first_prefix)
    j = find(last_prefix, i)
    lines[i:j + 1] = new


BUL = "•"
TAB = "\\t"

replace_line('"""Build the GraphSentinel project report',
             '"""Build the GraphSentinel project report (.docx) in the REC project report format (Department of AIML)."""')
replace_line('c("IT19811 PROJECT PHASE-II REPORT"', '    c(F.COURSE_LINE, 14, after=600)')
replace_line('c("INFORMATION TECHNOLOGY", 18', '    c(F.DEGREE, 18, after=640)')
replace_line('c("DEPARTMENT OF INFORMATION TECHNOLOGY"', '    c(F.DEPARTMENT, 16, after=160)')

# certificate: no SDG line and no viva line; centred signature blocks with bold names; examiners in capitals
replace_block('d.p(ppr(jc="both", first=720, line=480, after=240), rich(F.BONAFIDE',
              'borders=False, keep=False, aligns=["center", "center"]))', [
    '    d.p(ppr(jc="both", first=720, line=480, after=960), rich(F.BONAFIDE, refs, sz=13))',
    '    sig = [[f"**{F.HOD[0]}**", f"**{F.SUPERVISOR[0]}**"]] + [[F.HOD[k], F.SUPERVISOR[k]] for k in range(1, 5)]',
    '    d.raw(table_xml([4153, 4153], sig, refs, sz=12, header=False, borders=False, keep=False, cell_before=40,',
    '                    cell_after=40, aligns=["center", "center"], valign="top"))',
    '    d.p(ppr(jc="left", before=1400, after=0), "")',
    '    d.raw(table_xml([4153, 4153], [["**INTERNAL EXAMINER**", "**EXTERNAL EXAMINER**"]], refs, sz=12, header=False,',
    '                    borders=False, keep=False, aligns=["center", "center"]))',
])

# department pages from the PO list to the course outcomes
replace_block("for k, (name, t) in enumerate(F.POS, 1):", f'run("{BUL}{TAB}" + t, sz=12.5))', [
    "    for k, (name, t) in enumerate(F.POS, 1):",
    '        d.p(ppr(jc="both", left=480, hanging=480, line=LINE_15, after=60),',
    '            run(f"PO{k}: ", b=True, sz=12.5) + run(name + ": ", b=True, sz=12.5) + run(t, sz=12.5))',
    '    H("PROGRAM SPECIFIC OUTCOMES (PSOs)", sz=14, before=240, after=120)',
    '    d.p(ppr(jc="left", line=LINE_15, after=60), run(F.PSO_INTRO, sz=12.5))',
    "    for k, (name, t) in enumerate(F.PSOS, 1):",
    '        d.p(ppr(jc="both", left=480, hanging=480, line=LINE_15, after=60),',
    '            run(f"PSO{k}: ", b=True, sz=12.5) + run(name + ": ", b=True, sz=12.5) + run(t, sz=12.5))',
    '    H("COURSE OBJECTIVE", sz=14, before=240, after=120)',
    '    d.p(ppr(jc="both", left=360, hanging=360, line=LINE_15, after=60, tabs=[("left", 360)]),',
    f'        run("{BUL}{TAB}", sz=12.5) + rich(F.COURSE_OBJECTIVE, refs, sz=12.5))',
    '    H("COURSE OUTCOMES", sz=14, before=240, after=120)',
    "    for t in F.COURSE_OUTCOMES:",
    '        d.p(ppr(jc="both", left=360, hanging=360, line=LINE_15, after=60, tabs=[("left", 360)]),',
    f'            run("{BUL}{TAB}", sz=12.5) + rich(t, refs, sz=12.5))',
])

# appendices V and VI
i = find('d.p(ppr(jc="center", page_break=True, after=0), run("IT19811')
lines[i] = '    d.p(ppr(jc="center", page_break=True, after=0), rich(F.COURSE_HEADER, refs, b=True, sz=16))'
i = find('d.p(ppr(jc="center", page_break=True, after=0), run("IT19811')
lines[i] = '    d.p(ppr(jc="center", page_break=True, after=0), rich(F.COURSE_HEADER, refs, b=True, sz=16))'
replace_line('heads = ["PO / PSO',
             '    heads = ["PO / PSO\\nCO"] + [f"PO {k}" for k in range(1, 13)] + [f"PSO {k}" for k in range(1, 4)]')
replace_line('d.raw(table_xml([1026] + [455] * 16',
             '    d.raw(table_xml([1031] + [485] * 15, rows, refs, sz=10, aligns=["center"] * 16, keep=False,')
replace_line('["Batch Members", ":",', '            ["Batch Members", ":", F.BATCH],')
replace_line('["Supervisor", ":",', '            ["Supervisor", ":", F.SUPERVISOR_LINE]]')
i = find('f"<dc:title>{x(F.TITLE_SENTENCE)}</dc:title><dc:subject>IT19811')
lines[i] = lines[i].replace("<dc:subject>IT19811 Project Phase-II Report</dc:subject>",
                            "<dc:subject>{x(F.COURSE_SUBJECT)}</dc:subject>")

text = "\n".join(lines)
for bad in ("IT19811", "INFORMATION TECHNOLOGY", "SDG_LINE", "Viva-Voce"):
    assert bad not in text, bad
p.write_text(text, encoding="utf-8")
print("report_build.py patched for AIML")
