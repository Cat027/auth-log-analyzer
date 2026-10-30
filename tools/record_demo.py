"""Render a terminal replay from real program executions (optional tooling).

Requires Pillow and ffmpeg. The analyzer itself has no external dependencies.
Run from the repository root: python3 tools/record_demo.py
"""

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "docs" / "media"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"


def main():
    if shutil.which("ffmpeg") is None:
        raise SystemExit("Install ffmpeg to generate the demonstration.")
    if not Path(FONT).exists():
        raise SystemExit("This renderer requires the DejaVu Sans Mono font on Linux.")
    DESTINATION.mkdir(parents=True, exist_ok=True)
    runs = [
        ("01 / Default rule: 5 failures in 60 seconds", "default", [], 6),
        ("02 / Higher threshold: no IP reaches 6 failures", "strict", ["--threshold", "6"], 6),
        ("03 / Wider window: two IPs reach the rule", "wide", ["--threshold", "3", "--window-seconds", "300"], 8),
        ("04 / Automated tests", "tests", None, 6),
    ]
    scenes = []
    # Use an isolated working directory so generated reports never clash with a user's.
    with tempfile.TemporaryDirectory(prefix="logwatch-demo-") as temporary:
        workspace = Path(temporary)
        shutil.copy(ROOT / "logwatch.py", workspace)
        shutil.copytree(ROOT / "data", workspace / "data")
        shutil.copytree(ROOT / "tests", workspace / "tests")
        for title, name, options, seconds in runs:
            args = (["logwatch.py", "data/sample_logins.csv", "--output", f"reports/{name}", *options]
                    if options is not None else ["-m", "unittest", "discover", "-s", "tests", "-q"])
            result = subprocess.run([sys.executable, *args], cwd=workspace, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
            scenes.append({"title": title, "command": "python3 " + " ".join(args),
                           "output": result.stdout, "exit_code": result.returncode, "seconds": seconds})
    (DESTINATION / "demo-transcript.json").write_text(
        json.dumps(scenes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    font = ImageFont.truetype(FONT, 22)
    heading = ImageFont.truetype(BOLD, 29)
    small = ImageFont.truetype(FONT, 17)
    frames_per_second = 8
    encoder = subprocess.Popen([
        "ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pixel_format", "rgb24",
        "-video_size", "1280x720", "-framerate", str(frames_per_second), "-i", "-",
        "-an", "-c:v", "libx264", "-preset", "medium", "-crf", "23", "-pix_fmt", "yuv420p",
        "-movflags", "+faststart", str(DESTINATION / "demo.mp4"),
    ], stdin=subprocess.PIPE)
    try:
        for scene in scenes:
            command = "$ " + scene["command"]
            for frame_number in range(scene["seconds"] * frames_per_second):
                elapsed = frame_number / frames_per_second
                frame = Image.new("RGB", (1280, 720), "#0b1220")
                draw = ImageDraw.Draw(frame)
                draw.rounded_rectangle((24, 24, 1256, 696), radius=20, fill="#121c2e", outline="#2b3c54", width=2)
                for x, color in [(52, "#ff657a"), (78, "#f6c85f"), (104, "#4cceac")]:
                    draw.ellipse((x, 47, x + 12, 59), fill=color)
                draw.text((140, 40), "Auth Log Analyzer / Python + SQLite", font=small, fill="#b8c8dc")
                draw.text((52, 100), scene["title"], font=heading, fill="#66e4c8")
                draw.text((52, 151), "Real executions / fictional login data / adjusted replay pacing", font=small, fill="#91a3bb")
                visible = command[:min(len(command), int(elapsed * 100))]
                lines = textwrap.wrap(visible, width=86, subsequent_indent="  ") or [""]
                y = 218
                for line in lines:
                    draw.text((52, y), line, font=font, fill="#f1cb79")
                    y += 34
                if elapsed >= 1.5:
                    output_lines = scene["output"].splitlines()
                    shown = min(len(output_lines), 1 + int((elapsed - 1.5) * 7))
                    y += 22
                    for line in output_lines[:shown]:
                        for wrapped in textwrap.wrap(line, width=86) or [""]:
                            draw.text((52, y), wrapped, font=font,
                                      fill="#66e4c8" if wrapped == "OK" else "#e0e9f6")
                            y += 34
                draw.text((52, 650), "Local analysis | configurable rule | no network scanning", font=small, fill="#91a3bb")
                encoder.stdin.write(frame.tobytes())
    finally:
        encoder.stdin.close()
        return_code = encoder.wait()
    if return_code:
        raise SystemExit(f"ffmpeg failed with exit code {return_code}")
    subprocess.run([
        "ffmpeg", "-y", "-loglevel", "error", "-i", str(DESTINATION / "demo.mp4"),
        "-filter_complex", "fps=4,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse",
        "-loop", "0", str(DESTINATION / "demo.gif"),
    ], check=True)
    print("Created MP4, GIF, and transcript in docs/media/.")


if __name__ == "__main__":
    main()
