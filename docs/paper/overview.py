import os
from PIL import Image
ims = [Image.open(f"pages/p{i}.png") for i in range(1, 20) if os.path.exists(f"pages/p{i}.png")]
w, h = ims[0].size; s = 0.5; tw, th = int(w * s), int(h * s)
rows = (len(ims) + 3) // 4
sheet = Image.new("RGB", (tw * 4 + 30, th * rows + 10 * (rows - 1)), (120, 120, 120))
for i, im in enumerate(ims):
    sheet.paste(im.resize((tw, th)), ((i % 4) * (tw + 10), (i // 4) * (th + 10)))
sheet.save("overview.png")
print(len(ims), "pages")
