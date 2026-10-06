"""A small WordprocessingML writer for an IEEE-style two-column conference paper.

Everything is emitted as raw OOXML so that the layout (sections, columns,
tables, native equations, inline figures) is exactly what we specify.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image

NS = (
    'xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas" '
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
    'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture" '
    'xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"'
)

TNR = "Times New Roman"
TWIP_PER_IN = 1440
EMU_PER_IN = 914400


def x(text: str) -> str:
    return escape(text, {'"': "&quot;"})


# --------------------------------------------------------------------- runs
def smart_quotes(text: str) -> str:
    """Typographic quotes: an opening quote follows a space or bracket, anything else closes."""
    out = []
    for n, ch in enumerate(text):
        if ch == '"':
            prev = text[n - 1] if n else " "
            out.append("“" if prev.isspace() or prev in "([{—" else "”")
        elif ch == "'":
            out.append("’")
        else:
            out.append(ch)
    return "".join(out)


def run(text: str, *, b=False, i=False, sz=None, smallcaps=False, caps=False, va=None,
        font=None, color=None) -> str:
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
    if smallcaps:
        props.append("<w:smallCaps/>")
    if color:
        props.append(f'<w:color w:val="{color}"/>')
    if sz:
        props.append(f'<w:sz w:val="{int(round(sz * 2))}"/><w:szCs w:val="{int(round(sz * 2))}"/>')
    if va:
        props.append(f'<w:vertAlign w:val="{va}"/>')
    rpr = f"<w:rPr>{''.join(props)}</w:rPr>" if props else ""
    parts = text.split("\t")
    out = []
    for n, part in enumerate(parts):
        if n:
            out.append(f"<w:r>{rpr}<w:tab/></w:r>")
        if part:
            out.append(f'<w:r>{rpr}<w:t xml:space="preserve">{x(part)}</w:t></w:r>')
    return "".join(out)


TOKEN = re.compile(r"(\*\*|\*|_\{|\^\{|\}|\[@[^\]]+\]|\{(?:fig|tab|eq):[^}]+\})")


@dataclass
class Refs:
    order: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)

    def cite(self, keys: list[str]) -> str:
        nums = []
        for key in keys:
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


def rich(text: str, refs: Refs, *, sz=None, b=False, i=False, smallcaps=False, font=None) -> str:
    """Render light markup: **bold**, *italic*, _{sub}, ^{sup}, [@key,key], {fig:label}."""
    bold, ital = b, i
    stack: list[str] = []
    out = []
    for token in TOKEN.split(text):
        if not token:
            continue
        if token == "**":
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
            out.append(run(refs.cite(keys), b=bold, i=False, sz=sz, font=font))
        elif token.startswith("{") and ":" in token and token.endswith("}"):
            out.append(run(refs.labels[token[1:-1]], b=bold, i=ital, sz=sz, font=font))
        else:
            va = stack[-1] if stack else None
            out.append(run(token, b=bold, i=ital, sz=sz, va=va, smallcaps=smallcaps, font=font))
    return "".join(out)


# --------------------------------------------------------------- paragraphs
def ppr(*, jc="both", first=0, left=0, hanging=0, before=0, after=0, line=None, keep_next=False,
        tabs=None, widow=True, extra="", keep_lines=False, no_hyphen=False) -> str:
    p = []
    if keep_next:
        p.append("<w:keepNext/>")
    if keep_lines:
        p.append("<w:keepLines/>")
    if no_hyphen:
        p.append("<w:suppressAutoHyphens/>")
    if not widow:
        p.append('<w:widowControl w:val="0"/>')
    if tabs:
        p.append("<w:tabs>" + "".join(f'<w:tab w:val="{k}" w:pos="{v}"/>' for k, v in tabs) + "</w:tabs>")
    spacing = f'<w:spacing w:before="{before}" w:after="{after}"'
    if line:
        spacing += f' w:line="{line}" w:lineRule="exact"'
    spacing += "/>"
    p.append(spacing)
    ind = f'<w:ind w:left="{left}"'
    if hanging:
        ind += f' w:hanging="{hanging}"'
    else:
        ind += f' w:firstLine="{first}"'
    ind += "/>"
    p.append(ind)
    p.append(f'<w:jc w:val="{jc}"/>')
    return "".join(p) + extra


@dataclass
class Para:
    ppr: str
    body: str
    sect: str = ""

    def xml(self) -> str:
        return f"<w:p><w:pPr>{self.ppr}{self.sect}</w:pPr>{self.body}</w:p>"


@dataclass
class Raw:
    body: str

    def xml(self) -> str:
        return self.body


# ------------------------------------------------------------------ math
def mr(text: str, sty: str | None = None) -> str:
    rpr = f'<m:rPr><m:sty m:val="{sty}"/></m:rPr>' if sty else ""
    return (f'<m:r>{rpr}<w:rPr><w:rFonts w:ascii="Cambria Math" w:hAnsi="Cambria Math"/>'
            f'<w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr>'
            f'<m:t xml:space="preserve">{x(text)}</m:t></m:r>')


def msub(base: str, s: str) -> str:
    return f"<m:sSub><m:e>{base}</m:e><m:sub>{s}</m:sub></m:sSub>"


def msup(base: str, s: str) -> str:
    return f"<m:sSup><m:e>{base}</m:e><m:sup>{s}</m:sup></m:sSup>"


def msubsup(base: str, s: str, p: str) -> str:
    return f"<m:sSubSup><m:e>{base}</m:e><m:sub>{s}</m:sub><m:sup>{p}</m:sup></m:sSubSup>"


def mfrac(n: str, d: str, small=False) -> str:
    typ = '<m:fPr><m:type m:val="lin"/></m:fPr>' if small else ""
    return f"<m:f>{typ}<m:num>{n}</m:num><m:den>{d}</m:den></m:f>"


def md(content: str, beg="(", end=")") -> str:
    return (f'<m:d><m:dPr><m:begChr m:val="{x(beg)}"/><m:endChr m:val="{x(end)}"/></m:dPr>'
            f"<m:e>{content}</m:e></m:d>")


def mnary(ch: str, lo: str, body: str, hi: str = "") -> str:
    hide = "" if hi else '<m:supHide m:val="1"/>'
    return (f'<m:nary><m:naryPr><m:chr m:val="{ch}"/><m:limLoc m:val="undOvr"/>{hide}</m:naryPr>'
            f"<m:sub>{lo}</m:sub><m:sup>{hi}</m:sup><m:e>{body}</m:e></m:nary>")


def mrad(content: str) -> str:
    return f'<m:rad><m:radPr><m:degHide m:val="1"/></m:radPr><m:deg/><m:e>{content}</m:e></m:rad>'


def mfunc(name: str, arg: str) -> str:
    return f"<m:func><m:fName>{mr(name, 'p')}</m:fName><m:e>{arg}</m:e></m:func>"


def macc(content: str, ch: str) -> str:
    return f'<m:acc><m:accPr><m:chr m:val="{ch}"/></m:accPr><m:e>{content}</m:e></m:acc>'


# ------------------------------------------------------------------ images
@dataclass
class Media:
    items: list[tuple[str, Path]] = field(default_factory=list)

    def add(self, path: Path) -> str:
        rid = f"rIdImg{len(self.items) + 1}"
        self.items.append((rid, path))
        return rid


def picture(path: Path, width_in: float, media: Media, pic_id: int) -> str:
    with Image.open(path) as im:
        w, h = im.size
    cx = int(width_in * EMU_PER_IN)
    cy = int(cx * h / w)
    rid = media.add(path)
    name = x(path.name)
    return (
        "<w:r><w:drawing>"
        f'<wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="{cx}" cy="{cy}"/>'
        '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
        f'<wp:docPr id="{pic_id}" name="Figure {pic_id}"/>'
        '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
        '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:pic><pic:nvPicPr><pic:cNvPr id="{pic_id}" name="{name}"/><pic:cNvPicPr/></pic:nvPicPr>'
        f'<pic:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
        "</a:graphicData></a:graphic></wp:inline></w:drawing></w:r>"
    )


# ------------------------------------------------------------------ tables
def table(widths: list[int], rows: list[list[str]], refs: Refs, *, header_rows=1, sz=8.0,
          aligns: list[str] | None = None, shade="FBE4D5", borders="grid") -> str:
    aligns = aligns or ["left"] * len(widths)
    total = sum(widths)
    if borders == "grid":
        b = ('<w:tblBorders>'
             '<w:top w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
             '<w:left w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
             '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
             '<w:right w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
             '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
             '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
             '</w:tblBorders>')
    else:
        b = ""
    out = [
        f'<w:tbl><w:tblPr><w:tblW w:w="{total}" w:type="dxa"/><w:jc w:val="center"/>{b}'
        '<w:tblLayout w:type="fixed"/>'
        '<w:tblCellMar><w:top w:w="10" w:type="dxa"/><w:left w:w="50" w:type="dxa"/>'
        '<w:bottom w:w="10" w:type="dxa"/><w:right w:w="50" w:type="dxa"/></w:tblCellMar>'
        '<w:tblLook w:val="0000"/></w:tblPr><w:tblGrid>'
        + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths)
        + "</w:tblGrid>"
    ]
    for r, row in enumerate(rows):
        head = r < header_rows
        trpr = "<w:trPr><w:cantSplit/>" + ("<w:tblHeader/>" if head else "") + "</w:trPr>"
        cells = []
        span_skip = 0
        for c, cell in enumerate(row):
            if span_skip:
                span_skip -= 1
                continue
            span = 1
            text = cell
            m = re.match(r"^<span=(\d+)>", cell)
            if m:
                span = int(m.group(1))
                text = cell[m.end():]
                span_skip = span - 1
            w = sum(widths[c:c + span])
            tcpr = f'<w:tcW w:w="{w}" w:type="dxa"/>'
            if span > 1:
                tcpr += f'<w:gridSpan w:val="{span}"/>'
            if head and shade:
                tcpr += f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>'
            tcpr += '<w:vAlign w:val="center"/>'
            jc = "center" if head else aligns[c]
            paras = []
            keep = r < len(rows) - 1  # keep every row with the next, so a table never splits
            for line in text.split("\n"):
                paras.append(
                    f"<w:p><w:pPr>{ppr(jc=jc, first=0, before=0, after=0, keep_next=keep, no_hyphen=True)}</w:pPr>"
                    f"{rich(line, refs, sz=sz, b=head)}</w:p>"
                )
            cells.append(f"<w:tc><w:tcPr>{tcpr}</w:tcPr>{''.join(paras)}</w:tc>")
        out.append(f"<w:tr>{trpr}{''.join(cells)}</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


# ------------------------------------------------------------------ package
def sect_pr(*, cols: int, continuous: bool, page=(11906, 16838), margins=(1077, 900, 1440, 900),
            space=288) -> str:
    top, right, bottom, left = margins
    typ = '<w:type w:val="continuous"/>' if continuous else ""
    return (
        f"<w:sectPr>{typ}<w:pgSz w:w=\"{page[0]}\" w:h=\"{page[1]}\"/>"
        f'<w:pgMar w:top="{top}" w:right="{right}" w:bottom="{bottom}" w:left="{left}" '
        'w:header="720" w:footer="720" w:gutter="0"/>'
        f'<w:cols w:num="{cols}" w:space="{space}"/><w:docGrid w:linePitch="360"/></w:sectPr>'
    )


STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="{TNR}" w:eastAsia="{TNR}" w:hAnsi="{TNR}" w:cs="{TNR}"/>
<w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="en-US" w:eastAsia="en-US" w:bidi="ar-SA"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:uiPriority w:val="99"/>
<w:semiHidden/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/>
<w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>"""

SETTINGS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math">
<w:autoHyphenation/><w:consecutiveHyphenLimit w:val="2"/><w:hyphenationZone w:val="357"/>
<w:defaultTabStop w:val="720"/><w:characterSpacingControl w:val="doNotCompress"/>
<m:mathPr><m:mathFont m:val="Cambria Math"/><m:brkBin m:val="before"/><m:brkBinSub m:val="--"/>
<m:smallFrac m:val="0"/><m:dispDef/><m:lMargin m:val="0"/><m:rMargin m:val="0"/><m:defJc m:val="centerGroup"/>
<m:wrapIndent m:val="1440"/><m:intLim m:val="subSup"/><m:naryLim m:val="undOvr"/></m:mathPr>
<w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>
</w:settings>"""


def write_docx(path: Path, body_xml: str, media: Media, *, title: str, subject: str) -> None:
    doc = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document {NS}>'
           f"<w:body>{body_xml}</w:body></w:document>")
    rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '<Relationship Id="rIdSettings" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>']
    for rid, p in media.items:
        rels.append(f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{p.name}"/>')
    rels.append("</Relationships>")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        "</Relationships>"
    )
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{x(title)}</dc:title><dc:subject>{x(subject)}</dc:subject><dc:creator>Authors</dc:creator>"
        "</cp:coreProperties>"
    )
    app = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
           "<Application>Microsoft Office Word</Application></Properties>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("word/document.xml", doc)
        z.writestr("word/styles.xml", STYLES)
        z.writestr("word/settings.xml", SETTINGS)
        z.writestr("word/_rels/document.xml.rels", "".join(rels))
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        for _, p in media.items:
            z.write(p, f"word/media/{p.name}")


def floating_box(inner_xml: str, width_in: float, height_in: float, box_id: int, *, gap_in: float = 0.14) -> str:
    """A borderless text box pinned to the top of the page, spanning the text width.

    Text in both columns wraps above and below it (IEEE-style full-width figure).
    """
    cx = int(width_in * EMU_PER_IN)
    cy = int(height_in * EMU_PER_IN)
    gap = int(gap_in * EMU_PER_IN)
    return (
        "<w:r><w:drawing>"
        f'<wp:anchor distT="0" distB="{gap}" distL="0" distR="0" simplePos="0" relativeHeight="{251660000 + box_id}" '
        'behindDoc="0" locked="0" layoutInCell="1" allowOverlap="0">'
        '<wp:simplePos x="0" y="0"/>'
        '<wp:positionH relativeFrom="margin"><wp:align>center</wp:align></wp:positionH>'
        '<wp:positionV relativeFrom="margin"><wp:align>top</wp:align></wp:positionV>'
        f'<wp:extent cx="{cx}" cy="{cy}"/><wp:effectExtent l="0" t="0" r="0" b="0"/>'
        "<wp:wrapTopAndBottom/>"
        f'<wp:docPr id="{box_id}" name="Figure box {box_id}"/><wp:cNvGraphicFramePr/>'
        '<a:graphic><a:graphicData uri="http://schemas.microsoft.com/office/word/2010/wordprocessingShape">'
        '<wps:wsp><wps:cNvSpPr txBox="1"/>'
        f'<wps:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></wps:spPr>'
        f"<wps:txbx><w:txbxContent>{inner_xml}</w:txbxContent></wps:txbx>"
        '<wps:bodyPr rot="0" vert="horz" wrap="square" lIns="0" tIns="0" rIns="0" bIns="0" anchor="t" anchorCtr="0">'
        "<a:spAutoFit/></wps:bodyPr></wps:wsp></a:graphicData></a:graphic></wp:anchor></w:drawing></w:r>"
    )
