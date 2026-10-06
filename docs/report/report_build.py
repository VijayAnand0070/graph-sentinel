"""Build the GraphSentinel project report (.docx) in the REC project report format (Department of AIML)."""

from __future__ import annotations

import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image

import rc_api
import rc_ch1  # noqa: F401  (chapters register their blocks in order)
import rc_ch2  # noqa: F401
import rc_ch3  # noqa: F401
import rc_ch4  # noqa: F401
import rc_ch5  # noqa: F401
import rc_ch6  # noqa: F401
import rc_front as F
from paper_ooxml import md, mr, smart_quotes, x
from rc_eqs import EQUATIONS
from rc_refs import REFERENCES

HERE = Path(__file__).resolve().parent
FIGS = HERE / "figs"
PAPER_FIGS = HERE.parent / "paper" / "figs"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "GraphSentinel_Project_Report.docx"

TNR = "Times New Roman"
TEXT_W = 8306          # twips (A4 11906 - 2160 left - 1440 right)
BODY_SZ = 12
LINE_15 = 360          # 1.5 line spacing (auto rule)
IN = 914400            # EMU per inch


# ============================================================== text runs
def run(text: str, *, b=False, i=False, sz=BODY_SZ, va=None, font=None, hl=None, caps=False, u=False) -> str:
    text = smart_quotes(text)
    props = []
    if font:
        props.append(f'<w:rFonts w:ascii="{font}" w:hAnsi="{font}" w:cs="{font}"/>')
    if b:
        props.append("<w:b/><w:bCs/>")
    if i:
        props.append("<w:i/><w:iCs/>")
    if caps:
        props.append("<w:caps/>")
    if u:
        props.append('<w:u w:val="single"/>')
    if hl:
        props.append(f'<w:highlight w:val="{hl}"/>')
    props.append(f'<w:sz w:val="{int(round(sz * 2))}"/><w:szCs w:val="{int(round(sz * 2))}"/>')
    if va:
        props.append(f'<w:vertAlign w:val="{va}"/>')
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>"
    out = []
    for n, part in enumerate(text.split("\t")):
        if n:
            out.append(f"<w:r>{rpr}<w:tab/></w:r>")
        if part:
            out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{x(part)}</w:t></w:r>')
    return "".join(out)


@dataclass
class Refs:
    order: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)

    def cite(self, keys: list[str]) -> str:
        nums = []
        for key in keys:
            if key not in REFERENCES:
                raise SystemExit(f"unknown reference key: {key}")
            if key not in self.order:
                self.order.append(key)
            nums.append(self.order.index(key) + 1)
        nums = sorted(set(nums))
        groups: list[list[int]] = []
        for n in nums:
            if groups and n == groups[-1][-1] + 1:
                groups[-1].append(n)
            else:
                groups.append([n])
        parts = []
        for g in groups:
            if len(g) >= 3:
                parts.append(f"[{g[0]}]–[{g[-1]}]")
            else:
                parts.extend(f"[{n}]" for n in g)
        return ", ".join(parts)


TOKEN = re.compile(r"(\{\{.*?\}\}|\*\*|\*|_\{|\^\{|\}|\[@[^\]]+\]|\{(?:fig|tab|eq):[^}]+\})")


def rich(text: str, refs: Refs, *, sz=BODY_SZ, b=False, i=False, font=None) -> str:
    bold, ital = b, i
    stack: list[str] = []
    out = []
    for token in TOKEN.split(text):
        if not token:
            continue
        if token.startswith("{{") and token.endswith("}}"):
            out.append(run(token[2:-2], b=bold, i=ital, sz=sz, font=font, hl="yellow"))
        elif token == "**":
            bold = not bold
        elif token == "*":
            ital = not ital
        elif token == "_{":
            stack.append("subscript")
        elif token == "^{":
            stack.append("superscript")
        elif token == "}" and stack:
            stack.pop()
        elif token.startswith("[@"):
            keys = [k.strip() for k in token[2:-1].split(",")]
            out.append(run(refs.cite(keys), b=bold, sz=sz, font=font))
        elif token.startswith("{") and token.endswith("}") and ":" in token:
            key = token[1:-1]
            if key not in refs.labels:
                raise SystemExit(f"unknown label: {key}")
            out.append(run(refs.labels[key], b=bold, i=ital, sz=sz, font=font))
        else:
            out.append(run(token, b=bold, i=ital, sz=sz, va=stack[-1] if stack else None, font=font))
    return "".join(out)


# ============================================================== paragraphs
def ppr(*, jc="both", first=0, left=0, hanging=0, before=0, after=0, line=None, exact=False, keep_next=False,
        keep_lines=False, page_break=False, tabs=None, no_hyphen=False) -> str:
    p = []
    if keep_next:
        p.append("<w:keepNext/>")
    if keep_lines:
        p.append("<w:keepLines/>")
    if page_break:
        p.append("<w:pageBreakBefore/>")
    if tabs:
        p.append("<w:tabs>" + "".join(f'<w:tab w:val="{k}" w:pos="{v}"/>' for k, v in tabs) + "</w:tabs>")
    if no_hyphen:
        p.append("<w:suppressAutoHyphens/>")
    sp = f'<w:spacing w:before="{before}" w:after="{after}"'
    if line:
        sp += f' w:line="{line}" w:lineRule="{"exact" if exact else "auto"}"'
    p.append(sp + "/>")
    ind = f'<w:ind w:left="{left}"'
    ind += f' w:hanging="{hanging}"' if hanging else f' w:firstLine="{first}"'
    p.append(ind + "/>")
    p.append(f'<w:jc w:val="{jc}"/>')
    return "".join(p)


class Doc:
    def __init__(self) -> None:
        self.parts: list[str] = []
        self.bm_id = 0
        self.media: list[tuple[str, Path, str]] = []
        self.pic_id = 0

    def p(self, pp: str, body: str, *, bookmark: str | None = None, sect: str = "") -> None:
        if bookmark:
            self.bm_id += 1
            body = (f'<w:bookmarkStart w:id="{self.bm_id}" w:name="{bookmark}"/>' + body
                    + f'<w:bookmarkEnd w:id="{self.bm_id}"/>')
        self.parts.append(f"<w:p><w:pPr>{pp}{sect}</w:pPr>{body}</w:p>")

    def raw(self, xml: str) -> None:
        self.parts.append(xml)

    def image(self, path: Path, width_in: float, *, outline=False) -> str:
        with Image.open(path) as im:
            w, h = im.size
        cx = int(width_in * IN)
        cy = int(cx * h / w)
        self.pic_id += 1
        ext = path.suffix.lower().lstrip(".")
        ext = "jpeg" if ext in ("jpg", "jpeg") else ext
        rid = f"rIdImg{self.pic_id}"
        target = f"media/img{self.pic_id:03d}.{'jpg' if ext == 'jpeg' else ext}"
        self.media.append((rid, path, target))
        line = ('<a:ln w="6350"><a:solidFill><a:srgbClr val="808080"/></a:solidFill></a:ln>' if outline else "")
        return (
            "<w:r><w:drawing>"
            f'<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
            '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
            f'<wp:docPr id="{self.pic_id}" name="Picture {self.pic_id}"/>'
            '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
            '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
            f'<pic:pic><pic:nvPicPr><pic:cNvPr id="{self.pic_id}" name="img{self.pic_id}"/><pic:cNvPicPr/></pic:nvPicPr>'
            f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
            f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
            f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>{line}</pic:spPr></pic:pic>'
            "</a:graphicData></a:graphic></wp:inline></w:drawing></w:r>"
        )


def fld(instr: str, placeholder: str = "0", *, sz=BODY_SZ, b=False) -> str:
    rpr = f'<w:rPr>{"<w:b/>" if b else ""}<w:sz w:val="{sz * 2:.0f}"/><w:szCs w:val="{sz * 2:.0f}"/></w:rPr>'
    return (f'<w:r>{rpr}<w:fldChar w:fldCharType="begin"/></w:r>'
            f'<w:r>{rpr}<w:instrText xml:space="preserve"> {instr} </w:instrText></w:r>'
            f'<w:r>{rpr}<w:fldChar w:fldCharType="separate"/></w:r>'
            f'<w:r>{rpr}<w:t>{placeholder}</w:t></w:r>'
            f'<w:r>{rpr}<w:fldChar w:fldCharType="end"/></w:r>')


def table_xml(widths, rows, refs: Refs, *, sz=11.0, aligns=None, header=True, borders=True, keep=True,
              valign="center", cell_before=20, cell_after=20, bold_first_col=False, vertical_header=False,
              header_height=0) -> str:
    aligns = aligns or ["left"] * len(widths)
    total = sum(widths)
    bd = ""
    if borders:
        bd = ("<w:tblBorders>" + "".join(
            f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
            for s in ("top", "left", "bottom", "right", "insideH", "insideV")) + "</w:tblBorders>")
    out = [f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/><w:jc w:val="center"/>{bd}'
           '<w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="30" w:type="dxa"/><w:left w:w="80" w:type="dxa"/>'
           '<w:bottom w:w="30" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar>'
           '<w:tblLook w:val="0000"/></w:tblPr><w:tblGrid>'
           + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>"]
    for r, row in enumerate(rows):
        head = header and r == 0
        height = f'<w:trHeight w:val="{header_height}" w:hRule="atLeast"/>' if head and header_height else ""
        trpr = "<w:trPr><w:cantSplit/>" + height + ("<w:tblHeader/>" if head else "") + "</w:trPr>"
        cells = []
        skip = 0
        for c, cell in enumerate(row):
            if skip:
                skip -= 1
                continue
            span = 1
            text = cell
            m = re.match(r"^<span=(\d+)>", cell)
            if m:
                span = int(m.group(1))
                text = cell[m.end():]
                skip = span - 1
            w = sum(widths[c:c + span])
            tcpr = f'<w:tcW w:w="{w}" w:type="dxa"/>' + (f'<w:gridSpan w:val="{span}"/>' if span > 1 else "")
            if head and vertical_header and c > 0:
                tcpr += '<w:textDirection w:val="btLr"/>'
            tcpr += f'<w:vAlign w:val="{valign}"/>'
            jc = "center" if head else ("center" if span > 1 else aligns[c])
            paras = []
            for line in text.split("\n"):
                pp = ppr(jc=jc, before=cell_before, after=cell_after, keep_next=keep, no_hyphen=True)
                paras.append(f"<w:p><w:pPr>{pp}</w:pPr>"
                             f"{rich(line, refs, sz=sz, b=head or (bold_first_col and c == 0))}</w:p>")
            cells.append(f"<w:tc><w:tcPr>{tcpr}</w:tcPr>{''.join(paras)}</w:tc>")
        out.append(f"<w:tr>{trpr}{''.join(cells)}</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


def sect_pr(*, header_rid: str, fmt: str | None, start: int | None) -> str:
    pg = ""
    if fmt:
        pg = f'<w:pgNumType w:fmt="{fmt}"' + (f' w:start="{start}"' if start is not None else "") + "/>"
    return (f'<w:sectPr><w:headerReference w:type="default" r:id="{header_rid}"/>'
            '<w:pgSz w:w="11906" w:h="16838"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="2160" w:header="720" w:footer="720" '
            f'w:gutter="0"/>{pg}<w:cols w:space="720"/><w:docGrid w:linePitch="360"/></w:sectPr>')


# ============================================================== numbering pass
def number_labels(refs: Refs) -> tuple[list, list]:
    ch = 0
    nf = nt = ne = 0
    figs, tabs = [], []
    for item in rc_api.C:
        kind = item[0]
        if kind == "chapter":
            ch = item[1]
            nf = nt = ne = 0
        elif kind == "fig":
            nf += 1
            refs.labels[f"fig:{item[1]}"] = f"Figure {ch}.{nf}"
            figs.append((f"{ch}.{nf}", item[4], f"bm_fig{ch}_{nf}"))
        elif kind == "tab":
            nt += 1
            refs.labels[f"tab:{item[1]}"] = f"Table {ch}.{nt}"
            tabs.append((f"{ch}.{nt}", item[2], f"bm_tab{ch}_{nt}"))
        elif kind == "eq":
            ne += 1
            refs.labels[f"eq:{item[1]}"] = f"({ch}.{ne})"
    return figs, tabs


def outline() -> list[tuple]:
    """Chapters and sections for the table of contents."""
    rows = []
    for item in rc_api.C:
        if item[0] == "chapter":
            rows.append(("chapter", str(item[1]), item[2], f"bm_ch{item[1]}"))
        elif item[0] == "sec":
            rows.append(("sec", item[1], item[2], "bm_s" + item[1].replace(".", "_")))
    return rows


# ============================================================== build
def build() -> dict:
    refs = Refs()
    figs, tabs = number_labels(refs)
    d = Doc()
    H = lambda text, sz=16, before=0, after=240, bm=None, pb=False, jc="center": d.p(  # noqa: E731
        ppr(jc=jc, before=before, after=after, page_break=pb, keep_next=True), run(text, b=True, sz=sz), bookmark=bm)

    # ---------------------------------------------------------------- cover (section 1)
    c = lambda text, sz, before=0, after=0, font=None, i=False: d.p(  # noqa: E731
        ppr(jc="center", before=before, after=after), rich(text, refs, sz=sz, b=True, i=i, font=font))
    c("GRAPHSENTINEL: A TRUSTWORTHY TEMPORAL GRAPH NEURAL NETWORK MODEL FOR AUTONOMOUS LATERAL MOVEMENT "
      "DETECTION AND PREVENTION", 16, before=240, after=360)
    c(F.COURSE_LINE, 14, after=600)
    c("Submitted by", 14, after=260, font="Calibri", i=True)
    for s in F.STUDENTS:
        c(s, 14, after=100)
    c("in partial fulfilment for the award of the degree of", 14, before=480, after=260, font="Calibri", i=True)
    c("BACHELOR OF TECHNOLOGY", 18, after=220)
    c("in", 18, after=220)
    c(F.DEGREE, 18, after=640)
    logos = (d.image(HERE / "assets" / "rec_logo.png", 2.25) + run("    ", sz=14)
             + d.image(HERE / "assets" / "college_emblem.png", 0.95))
    d.p(ppr(jc="center", after=760), logos)
    c(F.DEPARTMENT, 16, after=160)
    c("RAJALAKSHMI ENGINEERING COLLEGE", 16, after=160)
    c("(AUTONOMOUS), CHENNAI-602 105", 16, after=600)
    d.p(ppr(jc="center"), rich(F.MONTH_YEAR, refs, sz=14, b=True),
        sect=sect_pr(header_rid="rIdHdrBlank", fmt="lowerRoman", start=1))

    # ---------------------------------------------------------------- bonafide (section 2 starts at ii)
    d.p(ppr(jc="center", after=40), run("RAJALAKSHMI ENGINEERING COLLEGE", b=True, sz=16))
    d.p(ppr(jc="center", after=360), run("(An Autonomous Institution Affiliated to Anna University Chennai)", sz=12))
    d.p(ppr(jc="center", after=360), run("BONAFIDE CERTIFICATE", b=True, sz=18))
    d.p(ppr(jc="both", first=720, line=480, after=960), rich(F.BONAFIDE, refs, sz=13))
    sig = [[f"**{F.HOD[0]}**", f"**{F.SUPERVISOR[0]}**"]] + [[F.HOD[k], F.SUPERVISOR[k]] for k in range(1, 5)]
    d.raw(table_xml([4153, 4153], sig, refs, sz=12, header=False, borders=False, keep=False, cell_before=40,
                    cell_after=40, aligns=["center", "center"], valign="top"))
    d.p(ppr(jc="left", before=1400, after=0), "")
    d.raw(table_xml([4153, 4153], [["**INTERNAL EXAMINER**", "**EXTERNAL EXAMINER**"]], refs, sz=12, header=False,
                    borders=False, keep=False, aligns=["center", "center"]))

    # ---------------------------------------------------------------- acknowledgement
    H("ACKNOWLEDGEMENT", pb=True, after=360)
    for t in F.ACK:
        d.p(ppr(jc="both", first=720, line=LINE_15, after=160), rich(t, refs, sz=13))
    for s in F.STUDENT_SIGN:
        d.p(ppr(jc="right", before=120 if s == F.STUDENT_SIGN[0] else 0, after=0, line=LINE_15), rich(s, refs, sz=13))

    # ---------------------------------------------------------------- abstract
    H("ABSTRACT", pb=True, after=360, bm="bm_abstract")
    for t in F.ABSTRACT:
        d.p(ppr(jc="both", first=720, line=LINE_15, after=160), rich(t, refs, sz=12.5))

    # ---------------------------------------------------------------- table of contents
    H("TABLE OF CONTENTS", pb=True, after=360)
    toc_rows = [["CHAPTER NO", "TITLE", "PAGE NO"]]
    toc_bm = []
    for label, bm in (("ABSTRACT", "bm_abstract"), ("LIST OF FIGURES", "bm_lof"), ("LIST OF TABLES", "bm_lot"),
                      ("LIST OF ABBREVIATIONS", "bm_abbr")):
        toc_rows.append(["", f"**{label}**", f"@@{bm}"])
    for kind, num, title, bm in outline():
        if kind == "chapter":
            toc_rows.append([f"**{num}**", f"**{title}**", f"@@{bm}"])
        else:
            toc_rows.append(["", f"{num}  {title}", f"@@{bm}"])
    toc_rows.append(["", "**REFERENCES**", "@@bm_refs"])
    toc_rows.append(["", "**APPENDICES**", "@@bm_app"])
    for num, title, bm in APPENDIX_TITLES:
        toc_rows.append(["", f"**{num}  {title}**", f"@@{bm}"])
    d.raw(ref_table([1300, 5606, 1400], toc_rows, refs, sz=11.5, aligns=["center", "left", "center"]))

    # ---------------------------------------------------------------- lists of figures and tables
    H("LIST OF FIGURES", pb=True, after=360, bm="bm_lof")
    rows = [["Figure Number", "Figure Caption", "Page Number"]] + [[n, cap, f"@@{bm}"] for n, cap, bm in figs]
    d.raw(ref_table([1500, 5306, 1500], rows, refs, sz=11.5, aligns=["center", "left", "center"]))
    H("LIST OF TABLES", pb=True, after=360, bm="bm_lot")
    rows = [["Table Number", "Table Caption", "Page Number"]] + [[n, cap, f"@@{bm}"] for n, cap, bm in tabs]
    d.raw(ref_table([1500, 5306, 1500], rows, refs, sz=11.5, aligns=["center", "left", "center"]))

    # ---------------------------------------------------------------- abbreviations
    H("LIST OF ABBREVIATIONS", pb=True, after=360, bm="bm_abbr")
    rows = [["S.No", "Abbreviation", "Word Expansion"]] + [
        [str(k), a, e] for k, (a, e) in enumerate(F.ABBREVIATIONS, 1)]
    d.raw(table_xml([1000, 2000, 5306], rows, refs, sz=11.5, borders=False, keep=False,
                    aligns=["center", "left", "left"], cell_before=10, cell_after=10))

    # ---------------------------------------------------------------- department pages
    H("DEPARTMENT VISION", sz=14, pb=True, after=120)
    d.p(ppr(jc="both", line=LINE_15, after=240), run(F.VISION, sz=12.5))
    H("DEPARTMENT MISSION", sz=14, after=120)
    for m in F.MISSION:
        d.p(ppr(jc="both", line=LINE_15, after=60), run(m, sz=12.5))
    H("PROGRAMME EDUCATIONAL OBJECTIVES", sz=14, before=240, after=120)
    for k, t in F.PEOS:
        d.p(ppr(jc="left", after=0, keep_next=True, line=LINE_15), run(k, b=True, sz=12.5))
        d.p(ppr(jc="both", line=LINE_15, after=120), run(t, sz=12.5))
    H("PROGRAM OUTCOMES (POs)", sz=14, pb=True, after=120)
    d.p(ppr(jc="left", line=LINE_15, after=60), run("Engineering Graduates will be able to:", sz=12.5))
    for k, (name, t) in enumerate(F.POS, 1):
        d.p(ppr(jc="both", left=480, hanging=480, line=LINE_15, after=60),
            run(f"PO{k}: ", b=True, sz=12.5) + run(name + ": ", b=True, sz=12.5) + run(t, sz=12.5))
    H("PROGRAM SPECIFIC OUTCOMES (PSOs)", sz=14, before=240, after=120)
    d.p(ppr(jc="left", line=LINE_15, after=60), run(F.PSO_INTRO, sz=12.5))
    for k, (name, t) in enumerate(F.PSOS, 1):
        d.p(ppr(jc="both", left=480, hanging=480, line=LINE_15, after=60),
            run(f"PSO{k}: ", b=True, sz=12.5) + run(name + ": ", b=True, sz=12.5) + run(t, sz=12.5))
    H("COURSE OBJECTIVE", sz=14, before=240, after=120)
    d.p(ppr(jc="both", left=360, hanging=360, line=LINE_15, after=60, tabs=[("left", 360)]),
        run("•\t", sz=12.5) + rich(F.COURSE_OBJECTIVE, refs, sz=12.5))
    H("COURSE OUTCOMES", sz=14, before=240, after=120)
    for t in F.COURSE_OUTCOMES:
        d.p(ppr(jc="both", left=360, hanging=360, line=LINE_15, after=60, tabs=[("left", 360)]),
            run("•\t", sz=12.5) + rich(t, refs, sz=12.5))
    # end of front matter: section 2 (lower roman, starting at ii)
    d.p(ppr(jc="left", line=20, exact=True), "", sect=sect_pr(header_rid="rIdHdrFront", fmt="lowerRoman", start=2))

    # ---------------------------------------------------------------- chapters (section 3, arabic from 1)
    eq_count = 0
    first_chapter = True
    for item in rc_api.C:
        kind = item[0]
        if kind == "chapter":
            _, num, title = item
            d.p(ppr(jc="center", after=120, page_break=not first_chapter, keep_next=True),
                run(f"CHAPTER {num}", b=True, sz=16))
            first_chapter = False
            d.p(ppr(jc="center", after=480, keep_next=True), run(title, b=True, sz=16), bookmark=f"bm_ch{num}")
        elif kind == "sec":
            _, num, title = item
            d.p(ppr(jc="left", before=240, after=160, keep_next=True), run(f"{num} {title}", b=True, sz=14),
                bookmark="bm_s" + num.replace(".", "_"))
        elif kind == "sub":
            _, num, title = item
            d.p(ppr(jc="left", before=200, after=100, keep_next=True), run(f"{num} {title}", b=True, sz=12.5))
        elif kind == "p":
            _, text, indent = item
            d.p(ppr(jc="both", first=720 if indent else 0, line=LINE_15, after=120), rich(text, refs))
        elif kind in ("bullets", "numbered"):
            for k, text in enumerate(item[1], 1):
                mark = "•" if kind == "bullets" else f"{k}."
                d.p(ppr(jc="both", left=720, hanging=360, line=LINE_15, after=80, tabs=[("left", 720)]),
                    run(f"{mark}\t") + rich(text, refs))
        elif kind == "eq":
            label = item[1]
            number = refs.labels[f"eq:{label}"].strip("()")
            omml = EQUATIONS[label].replace('<w:sz w:val="20"/><w:szCs w:val="20"/>',
                                            '<w:sz w:val="24"/><w:szCs w:val="24"/>')
            body = ('<m:oMathPara><m:oMath><m:eqArr><m:eqArrPr><m:maxDist m:val="1"/></m:eqArrPr><m:e>'
                    + omml + mr("#", "p").replace('w:val="20"', 'w:val="24"')
                    + md(mr(number, "p").replace('w:val="20"', 'w:val="24"'))
                    + "</m:e></m:eqArr></m:oMath></m:oMathPara>")
            d.p(ppr(jc="center", before=60, after=60), body)
            eq_count += 1
        elif kind == "fig":
            _, label, file, width, caption = item
            path = FIGS / file if (FIGS / file).exists() else PAPER_FIGS / file
            d.p(ppr(jc="center", before=120, after=80, keep_next=True), d.image(path, width))
            num = refs.labels[f"fig:{label}"].split()[1]
            d.p(ppr(jc="center", after=240, keep_lines=True), run(f"Figure {num}: {caption}", b=True, i=True),
                bookmark=f"bm_fig{num.replace('.', '_')}")
        elif kind == "tab":
            _, label, caption, widths, rows_, aligns, size = item
            d.p(ppr(jc="left", line=120, exact=True, keep_next=True), "")
            d.raw(table_xml(widths, rows_, refs, sz=size, aligns=aligns))
            num = refs.labels[f"tab:{label}"].split()[1]
            d.p(ppr(jc="center", before=100, after=240, keep_lines=True), run(f"Table {num}: {caption}", b=True, i=True),
                bookmark=f"bm_tab{num.replace('.', '_')}")
        elif kind == "pagebreak":
            d.p(ppr(page_break=True), "")

    # ---------------------------------------------------------------- references
    H("REFERENCES", pb=True, after=240, bm="bm_refs")
    missing = [k for k in REFERENCES if k not in refs.order]
    if missing:
        raise SystemExit(f"references never cited: {missing}")
    for n, key in enumerate(refs.order, 1):
        text = re.sub(r"https?://\S+", lambda m: m.group(0).replace("/", "/​"), REFERENCES[key])
        d.p(ppr(jc="both", left=600, hanging=600, line=300, after=100, tabs=[("left", 600)]),
            run(f"[{n}]\t", sz=12) + rich(text, refs, sz=12))

    # ---------------------------------------------------------------- appendices
    H("APPENDICES", pb=True, after=240, bm="bm_app")
    appendix_heading(d, "I.", "PROJECT PLAGIARISM REPORT", "bm_app1", page_break=False)
    placeholder_box(d, refs, "Attach the Turnitin / plagiarism similarity report of this project report here.")
    appendix_heading(d, "II.", "PAPER PLAGIARISM REPORT", "bm_app2")
    placeholder_box(d, refs, "Attach the plagiarism similarity report of the research paper here.")
    appendix_heading(d, "III.", "FINAL PUBLISHED PAPER", "bm_app3")
    d.p(ppr(jc="center", after=120),
        rich("{{[Manuscript prepared for IEEE conference submission. Replace these pages with the published "
             "version and its IEEE DOI after publication.]}}", refs, sz=11))
    pages = sorted((HERE / "paper_pages").glob("page*.jpg"))
    for k, pg in enumerate(pages):
        width = 5.55 if k == 0 else 5.77
        d.p(ppr(jc="center", page_break=k > 0, after=0), d.image(pg, width, outline=True))
    appendix_heading(d, "IV.", "PROOF OF THE PUBLICATION", "bm_app4")
    placeholder_box(d, refs, "Attach the proof of publication here (acceptance e-mail, IEEE Xplore page with the "
                             "DOI, and the certificate of presentation).")

    # V. CO-PO-PSO mapping
    d.p(ppr(jc="center", page_break=True, after=0), rich(F.COURSE_HEADER, refs, b=True, sz=16))
    d.p(ppr(jc="center", after=300), run("V. CO-PO-PSO Mapping", b=True, sz=13), bookmark="bm_app5")
    project_block(d, refs)
    heads = ["PO / PSO\nCO"] + [f"PO {k}" for k in range(1, 13)] + [f"PSO {k}" for k in range(1, 4)]
    rows = [heads] + [[co] + vals for co, vals in F.COPO]
    d.raw(table_xml([1031] + [485] * 15, rows, refs, sz=10, aligns=["center"] * 16, keep=False,
                    vertical_header=True, header_height=820, cell_before=60, cell_after=60))
    d.p(ppr(jc="left", before=200, after=200),
        run("1: Slight (Low), 2: Moderate (Medium), 3: Substantial (High), ‘-’: no correlation.", sz=11))
    d.p(ppr(jc="right", before=900), run("Signature of the Supervisor", sz=12))

    # VI. CO-SDG relevance record
    d.p(ppr(jc="center", page_break=True, after=0), rich(F.COURSE_HEADER, refs, b=True, sz=16))
    d.p(ppr(jc="center", after=300), run("VI. CO-SDG Relevance Record", b=True, sz=13), bookmark="bm_app6")
    project_block(d, refs)
    rows = [["SDG (No. & Theme)", "Addressed COs", "Topic / Activity addressing SDG Theme"]] + [
        [s, cos, t] for s, cos, t in F.COSDG]
    d.raw(table_xml([2300, 1300, 4706], rows, refs, sz=11, aligns=["left", "center", "left"], keep=False,
                    valign="top"))
    d.p(ppr(jc="right", before=1200), run("Signature of the Supervisor", sz=12))

    body = "".join(d.parts) + sect_pr(header_rid="rIdHdrMain", fmt="decimal", start=1)
    write_package(OUT, body, d.media)
    return {"figures": len(figs), "tables": len(tabs), "equations": eq_count, "references": len(refs.order),
            "images": len(d.media)}


APPENDIX_TITLES = [
    ("I.", "PROJECT PLAGIARISM REPORT", "bm_app1"),
    ("II.", "PAPER PLAGIARISM REPORT", "bm_app2"),
    ("III.", "FINAL PUBLISHED PAPER", "bm_app3"),
    ("IV.", "PROOF OF THE PUBLICATION", "bm_app4"),
    ("V.", "CO-PO-PSO MAPPING", "bm_app5"),
    ("VI.", "CO-SDG RELEVANCE RECORD", "bm_app6"),
]


def ref_table(widths, rows, refs, *, sz, aligns):
    """Borderless list table whose last column holds PAGEREF fields (cells written as @@bookmark)."""
    xml = table_xml(widths, rows, refs, sz=sz, borders=False, keep=False, aligns=aligns, cell_before=40,
                    cell_after=40)

    def repl(m):
        bm = m.group(1)
        return "</w:t></w:r>" + fld(f"PAGEREF {bm} \\h", "0", sz=sz) + '<w:r><w:t xml:space="preserve">'

    return re.sub(r"@@(bm_[A-Za-z0-9_]+)", repl, xml)


def appendix_heading(d: Doc, num: str, title: str, bm: str, page_break=True) -> None:
    d.p(ppr(jc="left", before=120, after=240, page_break=page_break, keep_next=True),
        run(f"{num} {title}", b=True, sz=14), bookmark=bm)


def placeholder_box(d: Doc, refs: Refs, text: str) -> None:
    d.raw(table_xml([8306], [["{{[" + text + "]}}"]], refs, sz=12, header=False, keep=False,
                    aligns=["center"], cell_before=1800, cell_after=1800))


def project_block(d: Doc, refs: Refs) -> None:
    rows = [["Project Title", ":", F.TITLE_SENTENCE + "."],
            ["Batch Members", ":", F.BATCH],
            ["Supervisor", ":", F.SUPERVISOR_LINE]]
    d.raw(table_xml([1700, 300, 6306], rows, refs, sz=12, header=False, borders=False, keep=False,
                    aligns=["left", "center", "left"], valign="top", cell_before=60, cell_after=160))
    d.p(ppr(jc="left", after=120), "")


# ============================================================== package
NS = ('xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
      'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
      'xmlns:o="urn:schemas-microsoft-com:office:office" '
      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
      'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" '
      'xmlns:v="urn:schemas-microsoft-com:vml" '
      'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
      'xmlns:w10="urn:schemas-microsoft-com:office:word" '
      'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
      'xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml" '
      'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
      'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"')

STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="{TNR}" w:eastAsia="{TNR}" w:hAnsi="{TNR}" w:cs="{TNR}"/>
<w:sz w:val="24"/><w:szCs w:val="24"/><w:lang w:val="en-IN" w:eastAsia="en-US" w:bidi="ar-SA"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:uiPriority w:val="99"/>
<w:semiHidden/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/>
<w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>"""

SETTINGS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math">
<w:defaultTabStop w:val="720"/><w:characterSpacingControl w:val="doNotCompress"/>
<m:mathPr><m:mathFont m:val="Cambria Math"/><m:brkBin m:val="before"/><m:brkBinSub m:val="--"/>
<m:smallFrac m:val="0"/><m:dispDef/><m:lMargin m:val="0"/><m:rMargin m:val="0"/><m:defJc m:val="centerGroup"/>
<m:wrapIndent m:val="1440"/><m:intLim m:val="subSup"/><m:naryLim m:val="undOvr"/></m:mathPr>
<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>
</w:settings>"""


def header_xml(with_page: bool) -> str:
    body = ""
    if with_page:
        body = ('<w:p><w:pPr><w:jc w:val="right"/></w:pPr>' + fld("PAGE", "1", sz=11) + "</w:p>")
    else:
        body = "<w:p/>"
    return (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:hdr {NS}>{body}</w:hdr>')


def write_package(path: Path, body_xml: str, media: list[tuple[str, Path, str]]) -> None:
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document {NS}><w:body>{body_xml}</w:body></w:document>'
    rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '<Relationship Id="rIdSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>']
    for rid, target in (("rIdHdrBlank", "header1.xml"), ("rIdHdrFront", "header2.xml"), ("rIdHdrMain", "header3.xml")):
        rels.append(f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="{target}"/>')
    for rid, _p, target in media:
        rels.append(f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{target}"/>')
    rels.append("</Relationships>")
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Default Extension="png" ContentType="image/png"/>'
          '<Default Extension="jpg" ContentType="image/jpeg"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
          '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
          + "".join(f'<Override PartName="/word/header{k}.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
                    for k in (1, 2, 3))
          + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
          "</Types>")
    root = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
            "</Relationships>")
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f"<dc:title>{x(F.TITLE_SENTENCE)}</dc:title><dc:subject>{x(F.COURSE_SUBJECT)}</dc:subject>"
            "<dc:creator>Project team</dc:creator></cp:coreProperties>")
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           "<Application>Microsoft Office Word</Application></Properties>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", root)
        z.writestr("word/document.xml", doc)
        z.writestr("word/styles.xml", STYLES)
        z.writestr("word/settings.xml", SETTINGS)
        z.writestr("word/header1.xml", header_xml(False))
        z.writestr("word/header2.xml", header_xml(True))
        z.writestr("word/header3.xml", header_xml(True))
        z.writestr("word/_rels/document.xml.rels", "".join(rels))
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        for _rid, p, target in media:
            z.write(p, f"word/{target}")


if __name__ == "__main__":
    info = build()
    print(OUT, info)
