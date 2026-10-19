"""Shared data models for scanner findings."""
from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    resource_kind: str
    resource_name: str
    namespace: str
    message: str
    recommendation: str
    container: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
