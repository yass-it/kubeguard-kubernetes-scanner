"""Offline scanner for Kubernetes YAML manifests; no live cluster connection."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable
import yaml
from .models import Finding, SEVERITY_ORDER

class ManifestError(ValueError):
    """Raised when a manifest file cannot be parsed or read."""

def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}

def _get_pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    kind = doc.get("kind")
    spec = _dict(doc.get("spec"))
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_template = _dict(spec.get("jobTemplate"))
        job_spec = _dict(job_template.get("spec"))
        template = _dict(job_spec.get("template"))
        return _dict(template.get("spec"))
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        template = _dict(spec.get("template"))
        return _dict(template.get("spec"))
    return None

def _containers(pod_spec: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for key in ("containers", "initContainers", "ephemeralContainers"):
        value = pod_spec.get(key, [])
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield str(item.get("name") or "<unnamed>"), item

def _finding(doc: dict[str, Any], rule_id: str, severity: str, title: str,
             message: str, recommendation: str, container: str | None = None) -> Finding:
    metadata = _dict(doc.get("metadata"))
    return Finding(rule_id, severity, title, str(doc.get("kind") or "Unknown"),
                   str(metadata.get("name") or "<unnamed>"),
                   str(metadata.get("namespace") or "default"), message, recommendation, container)

def _scan_workload(doc: dict[str, Any]) -> list[Finding]:
    pod_spec = _get_pod_spec(doc)
    if pod_spec is None:
        return []
    findings: list[Finding] = []
    pod_security = _dict(pod_spec.get("securityContext"))
    if pod_spec.get("hostNetwork") is True:
        findings.append(_finding(doc, "KG-WORKLOAD-004", "HIGH", "Host network enabled",
            "The Pod uses the node network namespace.",
            "Disable hostNetwork unless the workload has a documented requirement."))
    volumes = pod_spec.get("volumes", [])
    if isinstance(volumes, list):
        for volume in volumes:
            if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
                name = volume.get("name", "<unnamed>")
                findings.append(_finding(doc, "KG-WORKLOAD-005", "HIGH", "hostPath volume mounted",
                    f"Volume '{name}' references a path on the node filesystem.",
                    "Prefer a dedicated volume type; if hostPath is required, restrict the path and access."))
    for name, container in _containers(pod_spec):
        security_context = _dict(container.get("securityContext"))
        if security_context.get("privileged") is True:
            findings.append(_finding(doc, "KG-WORKLOAD-001", "CRITICAL", "Privileged container",
                "The container is configured with privileged access.",
                "Set securityContext.privileged to false unless explicitly justified and approved.", name))
        if security_context.get("allowPrivilegeEscalation") is True:
            findings.append(_finding(doc, "KG-WORKLOAD-002", "HIGH", "Privilege escalation allowed",
                "The container explicitly allows privilege escalation.",
                "Set securityContext.allowPrivilegeEscalation to false.", name))
        effective_non_root = security_context.get("runAsNonRoot", pod_security.get("runAsNonRoot"))
        if effective_non_root is not True:
            findings.append(_finding(doc, "KG-WORKLOAD-003", "MEDIUM", "Non-root execution not enforced",
                "runAsNonRoot is not explicitly true at container or Pod level.",
                "Set runAsNonRoot: true and verify the image can run without root privileges.", name))
    return findings

def _scan_rbac(doc: dict[str, Any]) -> list[Finding]:
    if doc.get("kind") not in {"Role", "ClusterRole"}:
        return []
    rules = doc.get("rules", _dict(doc.get("spec")).get("rules", []))
    if not isinstance(rules, list):
        return []
    findings: list[Finding] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        verbs, resources, api_groups = rule.get("verbs", []), rule.get("resources", []), rule.get("apiGroups", [])
        wildcard = any(isinstance(v, str) and v == "*" for seq in (verbs, resources, api_groups) if isinstance(seq, list) for v in seq)
        if wildcard:
            findings.append(_finding(doc, "KG-RBAC-001", "HIGH", "Wildcard RBAC permission",
                f"RBAC rule {index} contains a wildcard in verbs, resources, or API groups.",
                "Replace wildcards with the minimum verbs, resources, and API groups required."))
        if isinstance(verbs, list) and any(v in verbs for v in ("bind", "escalate", "impersonate")):
            findings.append(_finding(doc, "KG-RBAC-002", "HIGH", "Sensitive RBAC verb",
                f"RBAC rule {index} grants a sensitive verb (bind, escalate, or impersonate).",
                "Review the permission and remove sensitive verbs unless strictly required."))
    return findings

def scan_documents(documents: Iterable[Any]) -> list[Finding]:
    findings: list[Finding] = []
    for doc in documents:
        if isinstance(doc, dict):
            findings.extend(_scan_workload(doc))
            findings.extend(_scan_rbac(doc))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.namespace, f.resource_kind, f.resource_name, f.rule_id))

def scan_path(path: str | Path) -> tuple[list[Finding], int]:
    """Scan a YAML file or all .yaml/.yml files below a directory."""
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if target.is_file():
        if target.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError("Input file must have a .yaml or .yml extension.")
        files = [target]
    elif target.is_dir():
        files = sorted(p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in {".yaml", ".yml"})
    else:
        raise ValueError("Input path must be a YAML file or directory.")
    documents: list[Any] = []
    for file_path in files:
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                documents.extend(list(yaml.safe_load_all(handle)))
        except yaml.YAMLError as exc:
            raise ManifestError(f"Could not parse {file_path}: {exc}") from exc
        except OSError as exc:
            raise ManifestError(f"Could not read {file_path}: {exc}") from exc
    parsed = sum(1 for item in documents if isinstance(item, dict))
    return scan_documents(documents), parsed
