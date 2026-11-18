"""Report renderer registry and file output helpers."""

from pathlib import Path

from reports.html import render_html
from reports.json import render_json
from reports.markdown import render_markdown
from reports.sarif import render_sarif
from reports.yaml import render_yaml

REPORT_RENDERERS = {
    "markdown": (".md", render_markdown),
    "json": (".json", render_json),
    "yaml": (".yaml", render_yaml),
    "sarif": (".sarif", render_sarif),
    "html": (".html", render_html),
}


def write_report(output_file, report, output_format):
    """Render a report and write it with the format-appropriate extension."""
    try:
        extension, renderer = REPORT_RENDERERS[output_format]
    except KeyError as error:
        formats = ", ".join(REPORT_RENDERERS)
        raise ValueError(
            f"Unsupported report format {output_format!r}; choose from {formats}"
        ) from error

    path = Path(output_file).with_suffix(extension)
    path.write_text(renderer(report), encoding="utf-8")
    return path
