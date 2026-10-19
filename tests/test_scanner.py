from kubeguard.scanner import scan_documents, scan_path

def test_detects_workload_risks():
    pod = {"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"bad-pod", "namespace":"test"},
           "spec":{"hostNetwork":True, "volumes":[{"name":"host", "hostPath":{"path":"/etc"}}],
                   "containers":[{"name":"app", "securityContext":{"privileged":True, "allowPrivilegeEscalation":True}}]}}
    ids = {f.rule_id for f in scan_documents([pod])}
    assert {"KG-WORKLOAD-001", "KG-WORKLOAD-002", "KG-WORKLOAD-003", "KG-WORKLOAD-004", "KG-WORKLOAD-005"} <= ids

def test_detects_rbac_risks():
    role = {"apiVersion":"rbac.authorization.k8s.io/v1", "kind":"ClusterRole", "metadata":{"name":"wide"},
            "rules":[{"apiGroups":["*"], "resources":["*"], "verbs":["*"]},
                     {"apiGroups":[""], "resources":["pods"], "verbs":["impersonate"]}]}
    ids = {f.rule_id for f in scan_documents([role])}
    assert "KG-RBAC-001" in ids and "KG-RBAC-002" in ids

def test_hardened_deployment_does_not_trigger_workload_rules():
    deployment = {"apiVersion":"apps/v1", "kind":"Deployment", "metadata":{"name":"safe"},
                  "spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":True},
                          "containers":[{"name":"app", "securityContext":{"privileged":False, "allowPrivilegeEscalation":False}}]}}}}
    assert scan_documents([deployment]) == []

def test_scan_examples_directory():
    findings, count = scan_path("examples")
    assert count == 3
    assert findings


import pytest

from kubeguard.cli import main
from kubeguard.scanner import ManifestError


def test_missing_path_returns_error_code(capsys, tmp_path):
    missing = tmp_path / "does-not-exist.yaml"

    exit_code = main(["scan", "--path", str(missing)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Path does not exist" in captured.err


def test_invalid_yaml_raises_manifest_error(tmp_path):
    bad_yaml = tmp_path / "invalid.yaml"
    bad_yaml.write_text("kind: Pod\nmetadata: [invalid\n", encoding="utf-8")

    with pytest.raises(ManifestError, match="Could not parse"):
        scan_path(bad_yaml)


def test_empty_yaml_file_has_no_findings(tmp_path):
    empty_yaml = tmp_path / "empty.yaml"
    empty_yaml.write_text("", encoding="utf-8")

    findings, count = scan_path(empty_yaml)

    assert findings == []
    assert count == 0


def test_safe_manifest_returns_zero_exit_code(capsys):
    exit_code = main(["scan", "--path", "examples/hardened.yaml"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Findings: 0" in captured.out
