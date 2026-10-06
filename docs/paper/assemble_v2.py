from pathlib import Path
src = Path("build_paper_v1.py").read_text(encoding="utf-8").splitlines(keepends=True)
head_end = next(i for i, l in enumerate(src) if l.startswith("# ----------------------------------------------------------------- references"))
render_start = next(i for i, l in enumerate(src) if l.startswith("# ------------------------------------------------------------------ renderer"))
header = "".join(src[:head_end]).replace('"GraphSentinel_Conference_Paper.docx"', '"GraphSentinel_Conference_Paper_v2.docx"')
Path("build_v2.py").write_text(header + Path("content_v2.py").read_text(encoding="utf-8") + "\n\n" + "".join(src[render_start:]), encoding="utf-8")
