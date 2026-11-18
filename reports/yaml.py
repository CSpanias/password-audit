"""YAML report rendering."""

import yaml


def render_yaml(report):
    """Render a complete analysis report as YAML."""
    return yaml.safe_dump(
        report,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )
