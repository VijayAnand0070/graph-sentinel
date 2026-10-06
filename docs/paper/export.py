"""Export the .docx to PDF with Word, report the page count, render page previews."""
import sys
from pathlib import Path

import pypdfium2 as pdfium
import win32com.client

docx = Path(sys.argv[1]).resolve()
pdf = docx.with_suffix(".pdf")
word = win32com.client.DispatchEx("Word.Application")
word.Visible = False
word.DisplayAlerts = 0
try:
    doc = word.Documents.Open(str(docx), ReadOnly=False, AddToRecentFiles=False)
    doc.Repaginate()
    pages = doc.ComputeStatistics(2)
    doc.SaveAs2(str(pdf), FileFormat=17)
    doc.Close(False)
finally:
    word.Quit()
print("word pages:", pages)
out = docx.parent / "pages"
out.mkdir(exist_ok=True)
for f in out.glob("*.png"):
    f.unlink()
d = pdfium.PdfDocument(str(pdf))
print("pdf pages:", len(d))
for i in range(len(d)):
    d[i].render(scale=1.6).to_pil().save(out / f"p{i + 1}.png")
