#!/usr/bin/env python3
"""Generate the Shinobi logo PNG."""

import os
import sys


def generate_logo():
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("Pillow not installed. Install with: pip install Pillow")
        sys.exit(1)

    WIDTH, HEIGHT = 512, 512
    BG_COLOR = (0, 0, 0)
    RED = (220, 38, 38)       # #DC2626
    WHITE = (255, 255, 255)
    GRAY = (156, 163, 175)    # #9CA3AF

    img = Image.new('RGB', (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # --- Draw ninja mask ---
    # Horizontal mask band
    mask_y_top = 160
    mask_y_bottom = 260
    mask_left = 80
    mask_right = 432

    # Main mask band (rounded rectangle approximation)
    draw.rectangle([mask_left, mask_y_top, mask_right, mask_y_bottom], fill=RED)

    # Angled left eye (parallelogram)
    left_eye = [
        (130, 190),   # top-left
        (180, 180),   # top-right
        (200, 230),   # bottom-right
        (150, 240),   # bottom-left
    ]
    draw.polygon(left_eye, fill=BG_COLOR)

    # Angled right eye (parallelogram, mirrored)
    right_eye = [
        (312, 180),   # top-left
        (382, 190),   # top-right
        (362, 240),   # bottom-right
        (312, 230),   # bottom-left
    ]
    draw.polygon(right_eye, fill=BG_COLOR)

    # Mask top edge (angular shape for forehead)
    forehead = [
        (mask_left, mask_y_top),
        (256, mask_y_top - 40),  # peak
        (mask_right, mask_y_top),
    ]
    draw.polygon(forehead, fill=RED)

    # Mask bottom edge (angular chin wrap)
    chin_wrap = [
        (mask_left + 30, mask_y_bottom),
        (256, mask_y_bottom + 25),
        (mask_right - 30, mask_y_bottom),
    ]
    draw.polygon(chin_wrap, fill=RED)

    # Mask ties (trailing ribbons on the right side)
    draw.line([(mask_right, 200), (mask_right + 40, 180), (mask_right + 60, 195)], fill=RED, width=8)
    draw.line([(mask_right, 220), (mask_right + 50, 210), (mask_right + 65, 230)], fill=RED, width=6)

    # Eye shine/glow effect (small white dots)
    draw.ellipse([160, 200, 170, 210], fill=WHITE)
    draw.ellipse([340, 200, 350, 210], fill=WHITE)

    # --- Draw text ---
    # Try to load a nice font, fall back to default
    title_font = None
    subtitle_font = None
    font_paths = [
        '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/TTF/DejaVuSans-Bold.ttf',
        '/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf',
    ]

    for fp in font_paths:
        if os.path.exists(fp):
            try:
                title_font = ImageFont.truetype(fp, 56)
                subtitle_font = ImageFont.truetype(fp.replace('-Bold', ''), 22)
            except (OSError, IOError):
                pass
            break

    if title_font is None:
        try:
            title_font = ImageFont.truetype("DejaVuSans-Bold.ttf", 56)
            subtitle_font = ImageFont.truetype("DejaVuSans.ttf", 22)
        except (OSError, IOError):
            title_font = ImageFont.load_default()
            subtitle_font = ImageFont.load_default()

    # "SHINOBI" text
    title_text = "SHINOBI"
    title_bbox = draw.textbbox((0, 0), title_text, font=title_font)
    title_w = title_bbox[2] - title_bbox[0]
    title_x = (WIDTH - title_w) // 2
    title_y = 320

    # Text shadow
    draw.text((title_x + 2, title_y + 2), title_text, fill=(40, 40, 40), font=title_font)
    draw.text((title_x, title_y), title_text, fill=WHITE, font=title_font)

    # "security scanner" subtitle
    sub_text = "security scanner"
    sub_bbox = draw.textbbox((0, 0), sub_text, font=subtitle_font)
    sub_w = sub_bbox[2] - sub_bbox[0]
    sub_x = (WIDTH - sub_w) // 2
    sub_y = 390

    draw.text((sub_x, sub_y), sub_text, fill=GRAY, font=subtitle_font)

    # --- Decorative elements ---
    # Thin red lines at top and bottom
    draw.rectangle([0, 0, WIDTH, 4], fill=RED)
    draw.rectangle([0, HEIGHT - 4, WIDTH, HEIGHT], fill=RED)

    # Save
    output_dir = os.path.join(os.path.dirname(__file__), 'shinobi', 'assets')
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'logo.png')
    img.save(output_path, 'PNG')
    print(f"Logo generated: {output_path}")
    return output_path


if __name__ == '__main__':
    generate_logo()
