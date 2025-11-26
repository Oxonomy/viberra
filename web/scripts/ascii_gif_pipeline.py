import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Tuple, Optional

from PIL import Image, ImageDraw, ImageFont

# -------------------------- ANSI / chafa format -------------------------- #

ESC = "\x1b"
CSI_SAVE = ESC + "[s"  # save cursor (start of useful stream)
CSI_RESTORE = ESC + "[u"  # restore cursor (frame boundaries)

ANSI_RE = re.compile(
    r"""
    \x1B
    (?:[ @-Z\\-_]|\[[0-?]*[ -/]*[@-~])
    """,
    re.VERBOSE,
)


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def cut_after_first_save(txt: str) -> str:
    idx = txt.find(CSI_SAVE)
    if idx == -1:
        return txt
    return txt[idx + len(CSI_SAVE):]


def split_frames(payload: str, cols: int, rows: int,) -> List[str]:
    frames = []
    frame = []
    for row in payload.split('\n'):
        if len(row) > cols:
            frame.append(row[:cols])
            frames.append("\n".join(frame))
            frame = [row[cols:]]
        else:
            frame.append(row)
    frames.append("\n".join(frame))
    return frames


def compute_dims(frames: List[str]) -> Tuple[int, int]:
    max_cols = 0
    max_rows = 0
    for fr in frames:
        lines = fr.split("\n")
        rows = len(lines)
        cols = max((len(line) for line in lines), default=0)
        max_cols = max(max_cols, cols)
        max_rows = max(max_rows, rows)
    return max_cols, max_rows


def normalize_frames(frames_raw: List[str], cols: int, rows: int) -> List[List[str]]:
    out: List[List[str]] = []
    for fr in frames_raw:
        lines = fr.split("\n")
        if len(lines) < rows:
            lines += [""] * (rows - len(lines))
        elif len(lines) > rows:
            lines = lines[:rows]
        norm = [ln + (" " * max(0, cols - len(ln))) if len(ln) < cols else ln[:cols] for ln in lines]
        out.append(norm)
    return out


# ------------------------------ Rendering ------------------------------ #

COMMON_MONO_CANDIDATES = [
    # Linux
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
    # macOS (paths may vary)
    "/System/Library/Fonts/SFNSMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/Library/Fonts/Menlo.ttc",
    "/Library/Fonts/Andale Mono.ttf",
    # Windows
    "C:/Windows/Fonts/consola.ttf",  # Consolas
    "C:/Windows/Fonts/cour.ttf",  # Courier New
    "C:/Windows/Fonts/lucon.ttf",  # Lucida Console
]


def load_font(font_path: Optional[str], font_size: int) -> ImageFont.FreeTypeFont:
    if font_path:
        try:
            return ImageFont.truetype(font_path, font_size)
        except Exception as e:
            print(f"[warn] Failed to load font '{font_path}': {e}", file=sys.stderr)
    for cand in COMMON_MONO_CANDIDATES:
        try:
            return ImageFont.truetype(cand, font_size)
        except Exception:
            continue
    print("[warn] Using built-in PIL font (may not be monospaced). Specify --font.", file=sys.stderr)
    return ImageFont.load_default()


def measure_cell(font: ImageFont.FreeTypeFont) -> Tuple[int, int]:
    ascent, descent = font.getmetrics()
    cell_h = max(6, int(round(ascent + descent + 1)))
    try:
        bbox = font.getbbox("M")
        cell_w = bbox[2] - bbox[0]
    except Exception:
        cell_w = int(font.getlength("M"))
    cell_w = max(4, int(round(cell_w)))
    return cell_w, cell_h


def hex_to_rgb(x: str) -> Tuple[int, int, int]:
    s = x.strip()
    if s.startswith("#"): s = s[1:]
    if len(s) == 3: s = "".join(ch * 2 for ch in s)
    if len(s) != 6: raise ValueError(f"Invalid color: {x}")
    return int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16)


def render_frame(
        lines: List[str],
        cols: int,
        rows: int,
        font: ImageFont.FreeTypeFont,
        cell_w: int,
        cell_h: int,
        fg: Tuple[int, int, int],
        bg: Tuple[int, int, int],
        padding: int = 0,
) -> Image.Image:
    width = (cols-2) * cell_w + 2 * padding
    height = (rows-1) * cell_h + 2 * padding
    img = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(img)
    y = padding
    for r in range(rows):
        s = lines[r] if r < len(lines) else ""
        if s:
            draw.text((padding, y), s, font=font, fill=fg)
        y += cell_h
    return img


# ------------------------------ CLI utils ------------------------------ #

def check_bin(name: str):
    if shutil.which(name) is None:
        print(f"[error] Executable '{name}' not found. Install it and ensure it's in PATH.", file=sys.stderr)
        sys.exit(1)


def run(cmd: list, stdout_path: Optional[Path] = None):
    try:
        if stdout_path is None:
            subprocess.run(cmd, check=True)
        else:
            with open(stdout_path, "wb") as out:
                subprocess.run(cmd, check=True, stdout=out)
    except subprocess.CalledProcessError as e:
        print(f"[error] Command failed: {' '.join(cmd)}", file=sys.stderr)
        sys.exit(e.returncode)


# ------------------------------ Conversion ------------------------------ #

def mp4_to_gif(ffmpeg_bin: str, inp: Path, out_gif: Path, fps: int, scale_w: int, scale_h: int, scaler: str):
    vf = f"fps={fps},scale={scale_w}:{scale_h}:flags={scaler}"
    cmd = [ffmpeg_bin, "-y", "-i", str(inp), "-vf", vf, str(out_gif)]
    print(f"[ffmpeg] {' '.join(cmd)}", file=sys.stderr)
    run(cmd)


def gif_to_txt(chafa_bin: str, inp_gif: Path, out_txt: Path, cols: int, rows: int, symbols: str, colors: str):
    size = f"{cols}x{rows}"
    cmd = [chafa_bin, "--symbols", symbols, "-c", colors, "-s", size, str(inp_gif)]
    subprocess.run(f"{chafa_bin} --symbols block -c {colors} -s {size} {str(inp_gif)} > {out_txt}", shell=True, check=True)
    print(f"[chafa] {' '.join(cmd)} > {out_txt}", file=sys.stderr)
    run(cmd, stdout_path=out_txt)


def text_to_ascii_gif(
        txt_path: Path,
        out_path: Path,
        fps: int,
        font_path: Optional[str],
        font_size: int,
        cell_w: Optional[int],
        cell_h: Optional[int],
        cols: int,
        rows: int,
        fg_hex: str,
        bg_hex: str,
        padding: int,
        quantize: bool,
        dither: bool,
        drop_empty: bool,
):
    with open(txt_path, "r", encoding="utf-8") as f:
        txt = f.read().replace("\r\n", "\n").replace("\r", "\n")

    txt = txt.strip('D')
    chunks = split_frames(txt, cols, rows)

    frames_raw: List[str] = []
    for ch in chunks:
        cleaned = strip_ansi(ch)
        if drop_empty and cleaned.strip() == "":
            continue
        frames_raw.append(cleaned)

    if not frames_raw:
        print("[error] No frames found in text dump.", file=sys.stderr)
        sys.exit(2)

    cols, rows = compute_dims(frames_raw)
    frames_grid = normalize_frames(frames_raw, cols, rows)

    font = load_font(font_path, font_size)
    auto_cw, auto_ch = measure_cell(font)
    cw = int(cell_w) if cell_w else auto_cw
    ch = int(cell_h) if cell_h else auto_ch

    fg = hex_to_rgb(fg_hex)
    bg = hex_to_rgb(bg_hex)

    images: List[Image.Image] = []
    for lines in frames_grid:
        img = render_frame(lines, cols, rows, font, cw, ch, fg, bg, padding)
        images.append(img)

    duration_ms = max(1, int(round(1000.0 / max(1, fps))))
    first, rest = images[0], images[1:] if len(images) > 1 else []
    save_kwargs = dict(
        save_all=True,
        append_images=rest,
        duration=duration_ms,
        loop=0,
        optimize=True,
        disposal=2,
        dither=Image.FLOYDSTEINBERG if dither else Image.NONE,
    )
    # If hard palette quantization needed before saving:
    if quantize:
        images_q = []
        for im in images:
            images_q.append(im.convert("P", palette=Image.ADAPTIVE, colors=256,
                                       dither=Image.FLOYDSTEINBERG if dither else Image.NONE))
        first, rest = images_q[0], images_q[1:] if len(images_q) > 1 else []

    first.save(str(out_path), format="GIF", **save_kwargs)

    w, h = first.size
    print(f"[ok] {len(images)} frames; grid={cols}x{rows} chars; cell={cw}x{ch}px; image={w}x{h}px; fps={fps} -> {out_path}",
          file=sys.stderr)


# ------------------------------ main / args ------------------------------ #

def process_single_file(
        inp: Path,
        out_ascii: Path,
        args,
        counter: str = ""
) -> bool:
    """
    Process a single MP4 file.

    Args:
        inp: Path to input MP4 file
        out_ascii: Path to output ASCII GIF
        args: Command line arguments
        counter: Progress string (e.g., "[2/5]")

    Returns:
        True if successful, False on error
    """
    import time
    start_time = time.time()

    prefix = f"{counter} " if counter else ""
    print(f"{prefix}Processing {inp.name}...", file=sys.stderr)

    # Temporary directory
    tmp_ctx = tempfile.TemporaryDirectory(prefix="ascii_pipe_")
    mid_gif = Path(tmp_ctx.name) / "source.gif"
    mid_txt = Path(tmp_ctx.name) / "dump.txt"

    try:
        # 1) ffmpeg: video -> GIF
        mp4_to_gif(args.ffmpeg, inp, mid_gif, args.fps, args.scale_w, args.scale_h, args.scaler)

        # 2) chafa: GIF -> text dump
        gif_to_txt(args.chafa, mid_gif, mid_txt, args.cols, args.rows, args.chafa_symbols, args.chafa_colors)

        # 3) Render text -> ASCII-GIF
        text_to_ascii_gif(
            txt_path=mid_txt,
            out_path=out_ascii,
            fps=args.fps,
            font_path=args.font,
            font_size=args.font_size,
            cell_w=args.cell_w,
            cell_h=args.cell_h,
            cols=args.cols,
            rows=args.rows,
            fg_hex=args.fg,
            bg_hex=args.bg,
            padding=args.padding,
            quantize=args.quantize,
            dither=not args.no_dither,
            drop_empty=args.drop_empty_frames,
        )

        elapsed = time.time() - start_time
        print(f"{prefix}[OK] {inp.name} -> {out_ascii.name} ({elapsed:.1f}s)", file=sys.stderr)
        return True

    except Exception as e:
        elapsed = time.time() - start_time
        print(f"{prefix}[FAIL] {inp.name}: {e} ({elapsed:.1f}s)", file=sys.stderr)
        return False

    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


def process_batch(input_dir: Path, args) -> None:
    """
    Process all MP4 files in directory.

    Args:
        input_dir: Directory with MP4 files
        args: Command line arguments
    """
    # Find all .mp4 files (non-recursive)
    mp4_files = sorted(input_dir.glob("*.mp4"))

    if not mp4_files:
        print(f"[warn] No MP4 files found in {input_dir}", file=sys.stderr)
        return

    total = len(mp4_files)
    print(f"[batch] Found {total} MP4 file(s) in {input_dir}", file=sys.stderr)

    successful = 0
    failed = 0
    failed_files = []

    for idx, mp4_path in enumerate(mp4_files, start=1):
        # Output file next to input
        out_path = mp4_path.with_suffix('.gif')

        counter = f"[{idx}/{total}]"

        if process_single_file(mp4_path, out_path, args, counter):
            successful += 1
        else:
            failed += 1
            failed_files.append(mp4_path.name)

    # Final statistics
    print(f"\n[batch] Completed: {successful}/{total} successful", file=sys.stderr)
    if failed > 0:
        print(f"[batch] Failed: {failed} file(s)", file=sys.stderr)
        for fname in failed_files:
            print(f"  - {fname}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Unified pipeline: MP4 -> GIF (ffmpeg) -> TXT (chafa) -> ASCII-GIF (Pillow). "
                    "Supports processing single file or all .mp4 files in directory."
    )
    ap.add_argument("input", help="Path to MP4 file or directory with MP4 files")
    ap.add_argument("-o", "--out", default="ascii.gif", help="Output ASCII-GIF (single file mode only; ignored in batch mode)")

    # ffmpeg
    ap.add_argument("--ffmpeg", default="ffmpeg", help="Path to ffmpeg binary (default: ffmpeg from PATH)")
    ap.add_argument("--fps", type=int, default=10, help="FPS for intermediate GIF and final ASCII-GIF (default: 10)")
    ap.add_argument("--scale-w", type=int, default=320, help="Scaling width for ffmpeg (default: 320)")
    ap.add_argument("--scale-h", type=int, default=-1, help="Scaling height (-1 = preserve aspect ratio)")
    ap.add_argument("--scaler", default="lanczos", help="ffmpeg scaling algorithm (default: lanczos)")

    # chafa
    ap.add_argument("--chafa", default="chafa", help="Path to chafa binary (default: chafa from PATH)")
    ap.add_argument("--cols", type=int, default=90, help="Number of character columns for chafa (default: 90)")
    ap.add_argument("--rows", type=int, default=45, help="Number of character rows for chafa (default: 45)")
    ap.add_argument("--chafa_symbols", default="block",
                    help="symbol classes:"
                         " all, none, space, solid, stipple, block, border, diagonal, dot, quad, half, hhalf, vhalf,"
                         " inverted, braille, technical, geometric, ascii, legacy, sextant, wedge, wide, narrow."
                         " Can be combined with +/-")
    ap.add_argument("--chafa-colors", default="none", help="chafa color mode (default: none)")

    # ASCII->GIF rendering
    ap.add_argument("--font", help="Path to monospace font (TTF/TTC)")
    ap.add_argument("--font-size", type=int, default=11, help="Font size (px)")
    ap.add_argument("--cell-w", type=int, help="Character cell width (px); default determined by font")
    ap.add_argument("--cell-h", type=int, help="Character cell height (px); default determined by font")
    ap.add_argument("--fg", default="#ffffff", help="Text color (HEX, e.g. #00FF00)")
    ap.add_argument("--bg", default="#000000", help="Background color (HEX, e.g. #000000)")
    ap.add_argument("--padding", type=int, default=0, help="Internal padding (px)")
    ap.add_argument("--quantize", action="store_true", help="Pre-quantize frames (adaptive palette)")
    ap.add_argument("--no-dither", action="store_true", help="Disable dithering")
    ap.add_argument("--drop-empty-frames", action="store_true", help="Drop empty frames from text dump")

    args = ap.parse_args()

    # Check binaries
    check_bin(args.ffmpeg)
    check_bin(args.chafa)

    inp = Path(args.input).expanduser().resolve()
    if not inp.exists():
        print(f"[error] Path not found: {inp}", file=sys.stderr)
        sys.exit(1)

    # Auto-detect mode: file vs directory
    if inp.is_file():
        # Single file mode
        out_ascii = Path(args.out).expanduser().resolve()
        success = process_single_file(inp, out_ascii, args)
        if success:
            print(f"[done] Output: {out_ascii}", file=sys.stderr)
        sys.exit(0 if success else 1)

    elif inp.is_dir():
        # Batch mode
        if args.out != "ascii.gif":
            print(f"[warn] Option -o/--out ignored in batch mode (directory processing)", file=sys.stderr)
        process_batch(inp, args)
        sys.exit(0)

    else:
        print(f"[error] Unknown path type: {inp}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
