"""Human-readable and JSON output helpers."""

import json
from collections import Counter
from typing import Iterable

from . import __version__
from .models import Finding


def as_json(findings: Iterable[Finding], documents_scanned: int) -> str:
    """Serialize scan results as JSON."""
    items = list(findings)

    report = {
        "scanner": "KubeGuard",
        "version": __version__,
        "scan_mode": "offline-manifests",
        "documents_scanned": documents_scanned,
        "findings_count": len(items),
        "severity_summary": dict(Counter(item.severity for item in items)),
        "findings": [item.to_dict() for item in items],
    }

    return json.dumps(report, indent=2, sort_keys=True)


def as_text(findings: Iterable[Finding], documents_scanned: int) -> str:
    """Format scan results for terminal output."""
    items = list(findings)

    lines = [
        "KubeGuard — Kubernetes Manifest Security Scan",
        "Mode: offline YAML manifests (no live cluster connection)",
        f"Documents scanned: {documents_scanned}",
        f"Findings: {len(items)}",
        "",
    ]

    if not items:
        lines.append(
            "No configured checks were triggered by the scanned manifests."
        )
        return "\n".join(lines)

    for item in items:
        location = f"{item.namespace}/{item.resource_name}"
        if item.container:
            location += f" (container: {item.container})"

        lines.extend(
            [
                f"[{item.severity}] {item.rule_id} — {item.title}",
                f"  Resource: {item.resource_kind} {location}",
                f"  Finding: {item.message}",
                f"  Recommendation: {item.recommendation}",
                "",
            ]
        )

    lines.append(
        "Note: findings indicate potential misconfigurations, "
        "not proof of exploitability."
    )
    return "\n".join(lines)
