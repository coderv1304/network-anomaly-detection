import os
try:
    from PIL import Image, ImageDraw
except ImportError:
    os.system("pip install pillow")
    from PIL import Image, ImageDraw

def create_shield_icon(size):
    # Create canvas with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    padding = max(2, size // 10)
    w = size - 2 * padding
    h = size - 2 * padding
    
    # Shield points
    points = [
        (size / 2, padding),
        (size - padding, padding + h * 0.25),
        (size - padding, padding + h * 0.55),
        (size / 2, size - padding),
        (padding, padding + h * 0.55),
        (padding, padding + h * 0.25)
    ]
    
    # Draw gradient shield (Cyan #06b6d4 to Blue #3b82f6)
    draw.polygon(points, fill=(6, 182, 212, 255), outline=(59, 130, 246, 255))
    
    # Inner accent check / shield core
    inner_margin = max(3, size // 4)
    inner_points = [
        (size / 2, padding + inner_margin / 2),
        (size - padding - inner_margin / 2, padding + h * 0.28),
        (size / 2, size - padding - inner_margin / 2),
        (padding + inner_margin / 2, padding + h * 0.28)
    ]
    draw.polygon(inner_points, fill=(255, 255, 255, 220))
    
    return img

icons_dir = r"c:\Users\varun\OneDrive\Desktop\network-anomaly-detection\extension\icons"
os.makedirs(icons_dir, exist_ok=True)

for sz in [16, 48, 128]:
    icon = create_shield_icon(sz)
    icon.save(os.path.join(icons_dir, f"icon{sz}.png"))
    print(f"Generated icon{sz}.png")
