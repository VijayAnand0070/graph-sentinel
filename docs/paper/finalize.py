"""Round-trip the built .docx through Word (native save), export PDF, report pages."""
from pathlib import Path

import pypdfium2 as pdfium
import win32com.client

src = Path("GraphSentinel_Conference_Paper_v2.docx").resolve()
out_docx = Path(r"D:\GraphSentinel_Conference_Paper.docx")
out_pdf = Path(r"D:\GraphSentinel_Conference_Paper.pdf")
word = win32com.client.DispatchEx("Word.Application")
word.Visible = False
word.DisplayAlerts = 0
try:
    doc = word.Documents.Open(str(src), ReadOnly=True, AddToRecentFiles=False)
    doc.SaveAs2(str(out_docx), FileFormat=16)          # wdFormatDocumentDefault
    doc.Close(False)
    doc = word.Documents.Open(str(out_docx), AddToRecentFiles=False)
    doc.Repaginate()
    pages = doc.ComputeStatistics(2)
    words = doc.ComputeStatistics(0)
    doc.ExportAsFixedFormat(str(out_pdf), ExportFormat=17, OptimizeFor=0, BitmapMissingFonts=True,
                            DocStructureTags=True, CreateBookmarks=0)
    doc.Close(False)
finally:
    word.Quit()
pdf = pdfium.PdfDocument(str(out_pdf))
print("word pages:", pages, "| words:", words, "| pdf pages:", len(pdf))
print(out_docx.stat().st_size, out_pdf.stat().st_size)
