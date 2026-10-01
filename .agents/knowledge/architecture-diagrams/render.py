#!/usr/bin/env python3
"""Render the architecture document's Mermaid sources as opaque SVGs."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from xml.dom import minidom


def main() -> None:
    output_dir = Path(__file__).resolve().parent
    document = (output_dir.parent / "architecture-overview.md").read_text(
        encoding="utf-8"
    )
    diagrams = re.findall(
        r"!\[[^\]]*\]\(architecture-diagrams/([a-z0-9-]+\.svg)\)\s*"
        r"<details>\s*<summary>Mermaid source</summary>\s*"
        r"```text\n(.*?)\n```\s*</details>",
        document,
        re.DOTALL,
    )
    if not diagrams or len(diagrams) != document.count("<summary>Mermaid source</summary>"):
        raise SystemExit("Each Mermaid source block must follow its SVG image link.")
    if len({name for name, _ in diagrams}) != len(diagrams):
        raise SystemExit("Each diagram must have a unique SVG filename.")
    if shutil.which("mmdc") is None:
        raise SystemExit(
            "Mermaid CLI (mmdc) is required. Use the npm exec command in "
            "architecture-overview.md."
        )

    with tempfile.TemporaryDirectory(prefix="migtd-architecture-") as temporary:
        work_dir = Path(temporary)
        source = work_dir / "diagrams.md"
        source.write_text(
            "\n\n".join(f"```mermaid\n{code}\n```" for _, code in diagrams),
            encoding="utf-8",
        )
        subprocess.run(
            [
                "mmdc",
                "--input", str(source),
                "--output", str(work_dir / "diagram.svg"),
                "--backgroundColor", "transparent",
                "--width", "2200",
                "--height", "3000",
                "--jobs", "2",
                "--quiet",
            ],
            check=True,
        )
        rendered = []
        for index, (name, _) in enumerate(diagrams, 1):
            svg = minidom.parse(str(work_dir / f"diagram-{index}.svg"))
            root = svg.documentElement
            bounds = root.getAttribute("viewBox").split()
            if len(bounds) != 4:
                raise SystemExit(f"{name}: expected a four-value SVG viewBox.")
            # Image viewers otherwise fall back to a 300-pixel intrinsic width.
            root.setAttribute("width", bounds[2])
            root.setAttribute("height", bounds[3])
            # Paint real geometry: theme background colors do not fill the SVG canvas.
            background = svg.createElementNS(root.namespaceURI, "rect")
            for attribute, value in zip(("x", "y", "width", "height"), bounds):
                background.setAttribute(attribute, value)
            background.setAttribute("fill", "#ffffff")
            background.setAttribute("fill-opacity", "1")
            background.setAttribute("stroke", "none")
            background.setAttribute("data-diagram-background", "opaque-white")
            root.insertBefore(background, root.firstChild)
            rendered.append((name, root.toxml()))
            svg.unlink()

        for name, content in rendered:
            (output_dir / name).write_text(content + "\n", encoding="utf-8")
            print(f"Rendered {name}")


if __name__ == "__main__":
    main()
