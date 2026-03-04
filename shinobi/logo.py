"""ASCII art logo for Shinobi."""

from pathlib import Path


FALLBACK_LOGO = r"""
   __ _     _             _     _
  / _\ |__ (_)_ __   ___ | |__ (_)
  \ \| '_ \| | '_ \ / _ \| '_ \| |
  _\ \ | | | | | | | (_) | |_) | |
  \__/_| |_|_|_| |_|\___/|_.__/|_|

  v1.0 — shadow guard for your code
"""


def _get_logo_path() -> Path:
    """Get path to the logo PNG file."""
    return Path(__file__).parent / 'assets' / 'logo.png'


def _image_to_ascii(image, width=60) -> str:
    """Convert a PIL Image to colored ASCII art."""
    # ASCII chars from dark to light
    chars = " .:-=+*#%@"

    # Resize maintaining aspect ratio (terminal chars are ~2:1)
    aspect_ratio = image.height / image.width
    new_height = int(width * aspect_ratio * 0.5)
    image = image.resize((width, new_height))

    # Convert to RGB if not already
    if image.mode != 'RGB':
        image = image.convert('RGB')

    pixels = image.load()
    lines = []

    for y in range(new_height):
        line = ""
        for x in range(width):
            r, g, b = pixels[x, y]
            brightness = (r + g + b) / 3
            char_index = int(brightness / 255 * (len(chars) - 1))
            char = chars[char_index]

            # Add ANSI color
            if brightness > 10:  # Skip near-black
                line += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
            else:
                line += " "
        lines.append(line)

    return "\n".join(lines)


def print_logo(use_color: bool = True):
    """Print the Shinobi logo. Tries PNG->ASCII first, falls back to text."""
    try:
        from PIL import Image
        logo_path = _get_logo_path()
        if logo_path.exists():
            img = Image.open(logo_path)
            ascii_art = _image_to_ascii(img)
            print(ascii_art)
            subtitle = "shinobi v1.0 — shadow guard for your code"
            print(f"\n{subtitle:^60}")
            return
    except ImportError:
        pass
    except Exception:
        pass

    # Fallback to text logo
    if use_color:
        print(f"\033[31m{FALLBACK_LOGO}\033[0m")
    else:
        print(FALLBACK_LOGO)
