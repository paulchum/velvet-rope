#!/usr/bin/env python3
"""Build the six-second ShadowPath breach reveal for social launch surfaces."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404 - fixed ffmpeg binary and generated arguments only.
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result")
    parser.add_argument("--output", required=True)
    parser.add_argument("--gif")
    args = parser.parse_args()

    raw = json.loads(Path(args.result).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SystemExit("result root must be an object")
    routes = _routes(raw)
    if not routes:
        raise SystemExit("result has no route_results")
    summary = raw.get("summary")
    if not isinstance(summary, Mapping):
        raise SystemExit("result summary must be an object")
    verdict = str(summary.get("overall_verdict", "UNKNOWN"))

    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise SystemExit("ffmpeg is required to build the launch loop")

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shadowpath-video-") as temp:
        temp_path = Path(temp)
        phases: list[tuple[Path, int]] = []
        phase_specs = [(0, False, 24), (0, True, 24)]
        phase_specs.extend((count, True, 14) for count in range(1, len(routes) + 1))
        phase_specs.append((len(routes), True, 20))
        for index, (revealed, blocked, frame_count) in enumerate(phase_specs):
            path = temp_path / f"phase-{index:02d}.png"
            _render_frame(
                routes,
                path,
                revealed=revealed,
                blocked=blocked,
                final=index == len(phase_specs) - 1,
                verdict=verdict,
            )
            phases.append((path, frame_count))
        frames_path = temp_path / "frames"
        frames_path.mkdir()
        frame_index = 0
        for phase_path, frame_count in phases:
            for _ in range(frame_count):
                os.link(phase_path, frames_path / f"frame-{frame_index:03d}.png")
                frame_index += 1
        if frame_index != 180:
            raise SystemExit(f"launch loop must contain 180 frames, got {frame_index}")
        command = [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-framerate",
            "30",
            "-i",
            str(frames_path / "frame-%03d.png"),
            "-frames:v",
            "180",
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            "-map_metadata",
            "-1",
            str(output),
        ]
        subprocess.run(command, check=True)  # noqa: S603
        if args.gif:
            gif = Path(args.gif).resolve()
            gif.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(  # noqa: S603
                [
                    ffmpeg,
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-y",
                    "-i",
                    str(output),
                    "-vf",
                    "fps=10,scale=540:-1:flags=lanczos",
                    "-t",
                    "6",
                    "-loop",
                    "0",
                    str(gif),
                ],
                check=True,
            )
    _update_manifest(output, Path(args.gif).resolve() if args.gif else None)
    print(output)
    return 0


def _routes(payload: Mapping[str, Any]) -> list[str]:
    normalized: list[str] = []
    raw = payload.get("route_results", [])
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return normalized
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        route = item.get("route", {})
        route_map = cast(Mapping[str, Any], route) if isinstance(route, Mapping) else {}
        normalized.append(str(route_map.get("route_id", item.get("route_id", "unknown"))))
    return normalized


def _render_frame(
    routes: Sequence[str],
    path: Path,
    *,
    revealed: int,
    blocked: bool,
    final: bool,
    verdict: str,
) -> None:
    figure = Figure(figsize=(10.8, 19.2), dpi=100, facecolor="#09070f")
    FigureCanvasAgg(figure)
    axis = figure.add_axes((0, 0, 1, 1))
    axis.set_facecolor("#09070f")
    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1)
    axis.axis("off")
    axis.text(
        0.07,
        0.94,
        "SHADOWPATH / EFFECT-LEVEL AUTHORIZATION",
        color="#bca6e8",
        fontsize=15,
        family="monospace",
        weight="bold",
    )
    axis.text(
        0.07,
        0.84,
        "The tool was blocked.\nDid it block the outcome?",
        color="white",
        fontsize=43,
        family="sans-serif",
        weight="bold",
        va="top",
        linespacing=1.06,
    )
    axis.text(
        0.07,
        0.68,
        "PROTECTED ROUTE",
        color="#897e93",
        fontsize=13,
        family="monospace",
    )
    axis.text(
        0.07,
        0.645,
        "customer.disable",
        color="white",
        fontsize=21,
        family="monospace",
    )
    axis.text(
        0.93,
        0.645,
        "BLOCKED ✓" if blocked else "TESTING…",
        color="#d9ff43" if blocked else "#897e93",
        fontsize=18,
        family="monospace",
        weight="bold",
        ha="right",
    )
    axis.plot([0.07, 0.93], [0.615, 0.615], color="#35283f", linewidth=1)
    for index, route in enumerate(routes):
        y = 0.565 - index * 0.052
        active = index < revealed
        axis.text(
            0.07,
            y,
            f"{index + 1:02d}",
            color="#685e70",
            fontsize=14,
            family="monospace",
        )
        axis.text(
            0.16,
            y,
            route,
            color="#ddd7eb" if active else "#554d5d",
            fontsize=16,
            family="monospace",
        )
        axis.text(
            0.93,
            y,
            "BREACH" if active else "WAIT",
            color="#ff4d6d" if active else "#554d5d",
            fontsize=14,
            family="monospace",
            weight="bold",
            ha="right",
        )
    if final:
        axis.text(
            0.07,
            0.105,
            "8/8 PATHS ESCAPED",
            color="#ff4d6d",
            fontsize=31,
            family="sans-serif",
            weight="bold",
        )
        axis.text(
            0.07,
            0.065,
            verdict,
            color="white",
            fontsize=19,
            family="monospace",
            weight="bold",
        )
    else:
        axis.text(
            0.07,
            0.065,
            f"TRACING EFFECT PATHS  {revealed}/{len(routes)}",
            color="#bca6e8",
            fontsize=17,
            family="monospace",
        )
    figure.savefig(path, dpi=100, facecolor=figure.get_facecolor())


def _update_manifest(video: Path, gif: Path | None) -> None:
    manifest_path = video.parent / "manifest.json"
    if not manifest_path.is_file():
        return
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return
    files = raw.get("files", [])
    if not isinstance(files, list):
        return
    retained = [
        item
        for item in files
        if not isinstance(item, Mapping) or item.get("kind") not in {"video", "animated_gif"}
    ]
    retained.append(
        {
            "path": video.name,
            "kind": "video",
            "width": 1080,
            "height": 1920,
            "duration_seconds": 6,
            "frames_per_second": 30,
        }
    )
    if gif is not None:
        retained.append(
            {
                "path": gif.name,
                "kind": "animated_gif",
                "width": 540,
                "height": 960,
                "duration_seconds": 6,
            }
        )
    raw["files"] = retained
    provenance = raw.setdefault("provenance", {})
    if isinstance(provenance, dict):
        provenance["video_renderer"] = "scripts/build_shadowpath_launch_video.py"
    manifest_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
