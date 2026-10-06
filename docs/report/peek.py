import sys
import pypdfium2 as pdfium
from PIL import Image
pdf = pdfium.PdfDocument("final/GraphSentinel_Project_Report.pdf")
pages = [int(a) for a in sys.argv[1].split(",")]
scale = float(sys.argv[2]) if len(sys.argv) > 2 else 1.25
ims = [pdf[p - 1].render(scale=scale).to_pil().convert("RGB") for p in pages]
W = sum(i.width for i in ims) + 10 * (len(ims) - 1)
H = max(i.height for i in ims)
s = Image.new("RGB", (W, H), (110, 110, 110))
x = 0
for im in ims:
    s.paste(im, (x, 0)); x += im.width + 10
s.save(sys.argv[3] if len(sys.argv) > 3 else "peek.png")
print(s.size)
