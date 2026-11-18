"""
Finding data model.

This module defines the canonical finding structure used throughout
password-audit. Findings can be constructed programmatically from
analysis results or loaded declaratively from YAML definition files.

Attributes on the Finding dataclass mirror the structure used by
ad-kit's core/finding.py, extended with severity and category fields
for risk-based prioritisation.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """
    Represents a security finding identified during a password audit.

    Attributes:
        id:
            Unique finding identifier (e.g. DOMAIN-ADMIN-001).

        title:
            Human-readable finding title.

        description:
            Description of the identified security issue and its impact.

        severity:
            Risk severity: critical, high, medium, low, or info.

        category:
            Finding category for grouping and filtering:
            general, privileged_accounts, legacy_auth,
            password_policy, password_reuse, predictable_patterns.

        remediation:
            Recommended remediation guidance.

        evidence:
            Supporting evidence (e.g. affected usernames, passwords).

        affected_assets:
            Assets affected by the finding (e.g. hostnames, accounts).

        references:
            External references and supporting documentation.
    """

    id: str
    title: str
    description: str
    severity: str = "info"
    category: str = "general"
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the finding to a plain dictionary for JSON serialisation.

        Returns:
            dict: Finding as a dictionary with all fields.
        """
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "affected_assets": self.affected_assets,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """
        Create a Finding from a dictionary.

        Args:
            data:
                Dictionary containing finding fields.

        Returns:
            Finding: Constructed finding instance.
        """
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=data.get("severity", "info"),
            category=data.get("category", "general"),
            remediation=data.get("remediation", ""),
            evidence=data.get("evidence", []),
            affected_assets=data.get("affected_assets", []),
            references=data.get("references", []),
        )