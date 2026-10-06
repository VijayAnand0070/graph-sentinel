"""Open the built report in Word, update page references, save a native .docx and a PDF, render previews."""

import sys
from pathlib import Path

import pypdfium2 as pdfium
import win32com.client

HERE = Path(__file__).resolve().parent
src = (HERE / "GraphSentinel_Project_Report.docx").resolve()
out_docx = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "final" / "GraphSentinel_Project_Report.docx"
out_pdf = out_docx.with_suffix(".pdf")
out_docx.parent.mkdir(parents=True, exist_ok=True)

word = win32com.client.DispatchEx("Word.Application")
word.Visible = False
word.DisplayAlerts = 0
try:
    doc = word.Documents.Open(str(src), ReadOnly=True, AddToRecentFiles=False)
    doc.SaveAs2(str(out_docx), FileFormat=16)
    doc.Close(False)
    doc = word.Documents.Open(str(out_docx), AddToRecentFiles=False)
    for _ in range(3):
        doc.Repaginate()
        doc.Fields.Update()
    doc.Save()
    pages = doc.ComputeStatistics(2)
    words = doc.ComputeStatistics(0)
    doc.ExportAsFixedFormat(str(out_pdf), ExportFormat=17, OptimizeFor=0, BitmapMissingFonts=True,
                            DocStructureTags=True, CreateBookmarks=1)
    doc.Close(False)
finally:
    word.Quit()

pdf = pdfium.PdfDocument(str(out_pdf))
print("word pages:", pages, "| words:", words, "| pdf pages:", len(pdf))
prev = HERE / "pages"
prev.mkdir(exist_ok=True)
for f in prev.glob("*.png"):
    f.unlink()
for i in range(len(pdf)):
    pdf[i].render(scale=1.0).to_pil().save(prev / f"p{i + 1:03d}.png")
