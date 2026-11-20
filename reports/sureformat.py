"""SureFormat XML export for CSA Cyber findings."""

import xml.etree.ElementTree as ET

from common.console import warn


FINDING_MAP = {
    "PWD-AUDIT-001": "SC-1930",
    "PWD-STATS-001": "SC-2206",
    "DOMAIN-ADMIN-001": "SC-2113",
    "DOMAIN-ADMIN-002": "SC-10673",
    "PRIV-ACCOUNT-001": "SC-10672",
    "PWD-REUSE-001": "SC-10671",
    "PWD-REUSE-002": "SC-2202",
    "PWD-REUSE-003": "SC-10671",
    "PWD-PATTERN-001": "SC-2200",
    "PWD-PATTERN-002": "SC-2204",
    "PWD-PATTERN-003": "SC-2201",
    "PWD-PATTERN-004": "SC-2205",
    "PWD-PATTERN-005": "SC-2203",
    "PWD-POLICY-001": "SC-3307",
    "LM-AUTH-001": "SC-1801",
}


def write_sureformat(path, domain, findings):
    """Write mapped findings in the SureFormat XML structure."""
    root = ET.Element("items", source="SureFormat", version="1.0.0")
    item = ET.SubElement(root, "item", ipaddress="", hostname=domain)
    services = ET.SubElement(item, "services")
    service = ET.SubElement(services, "service", name="", port="", protocol="tcp")
    vulnerabilities = ET.SubElement(service, "vulnerabilities")

    mapped_vulnerabilities = {}
    for finding in findings:
        vulnerability_id = FINDING_MAP.get(finding["id"])
        if not vulnerability_id:
            warn(f"No SureFormat mapping found for finding: {finding['id']}")
            continue

        if vulnerability_id in mapped_vulnerabilities:
            information = mapped_vulnerabilities[vulnerability_id]
            information.text = (information.text or "") + "\n" + finding["description"]
        else:
            vulnerability = ET.SubElement(
                vulnerabilities, "vulnerability", id=vulnerability_id
            )
            information = ET.SubElement(vulnerability, "information")
            information.text = finding["description"]
            mapped_vulnerabilities[vulnerability_id] = information

    tree = ET.ElementTree(root)
    ET.indent(tree, space="    ")
    tree.write(path, encoding="utf-8", xml_declaration=False)
