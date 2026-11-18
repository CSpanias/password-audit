"""SARIF 2.1.0 report rendering."""

import json

_SEVERITY_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(report):
    """Render report findings using the SARIF 2.1.0 JSON structure."""
    findings = report.get("findings", [])
    rules = {}
    results = []

    for finding in findings:
        rule_id = finding["id"]
        severity = str(finding.get("severity", "info")).lower()
        level = _SEVERITY_LEVELS.get(severity, "note")
        category = finding.get("category", "general")

        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": finding["title"]},
            "fullDescription": {
                "text": finding.get("description", finding["title"])
            },
            "defaultConfiguration": {"level": level},
            "help": {"text": finding.get("remediation", "")},
            "properties": {
                "severity": severity,
                "category": category,
                "tags": [category],
            },
        })

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": finding.get("description") or finding["title"]
            },
            "properties": {
                "severity": severity,
                "category": category,
                "remediation": finding.get("remediation", ""),
                "evidence": finding.get("evidence", []),
                "affectedAssets": finding.get("affected_assets", []),
                "references": finding.get("references", []),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Password Audit",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "summary": report.get("summary", {}),
            },
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
