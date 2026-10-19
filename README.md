# KubeGuard — Kubernetes Manifest Security Scanner

**Status:** proof-of-concept (PoC), not a production security product.

KubeGuard scans Kubernetes YAML manifest files for a small set of security-relevant misconfigurations. It is designed to run locally without a Kubernetes cluster so reviewers can reproduce the demo with included examples.

## Implemented checks

| Rule ID | Severity | Check | Recommendation |
|---|---|---|---|
| `KG-WORKLOAD-001` | Critical | Container sets `privileged: true` | Disable privileged mode unless explicitly justified |
| `KG-WORKLOAD-002` | High | Container sets `allowPrivilegeEscalation: true` | Set it to `false` |
| `KG-WORKLOAD-003` | Medium | `runAsNonRoot: true` is not set on container or Pod security context | Set it to `true` and validate image compatibility |
| `KG-WORKLOAD-004` | High | Pod sets `hostNetwork: true` | Disable unless there is a documented need |
| `KG-WORKLOAD-005` | High | Pod spec contains a `hostPath` volume | Prefer a safer volume type or tightly restrict access |
| `KG-RBAC-001` | High | Role/ClusterRole has wildcard verbs, resources, or API groups | Replace wildcards with minimum required permissions |
| `KG-RBAC-002` | High | Role/ClusterRole grants `bind`, `escalate`, or `impersonate` | Review and remove sensitive verbs unless required |

The rules are intentionally small and transparent. A finding is a potential misconfiguration, not proof that a workload is exploitable. Severity is a simple prototype classification, not a complete risk score.

## Requirements

- Python 3.10+
- pip
- PyYAML (installed from project metadata)

No cluster, cloud credentials, or elevated permissions are needed for the offline scan.

## Quick start

From the repository root:

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e ".[dev]"
kubeguard scan --path examples/vulnerable.yaml

# Alternative after installing PyYAML, without installing the CLI entry point:
PYTHONPATH=src python -m kubeguard.cli scan --path examples/vulnerable.yaml
```

The scanner exits with code `1` when findings are reported, `0` when no configured checks trigger, and `2` for input/execution errors. Exit code `1` can be useful in CI, but should be interpreted with the rule scope in mind.

## JSON report

```bash
kubeguard scan --path examples --format json --output report.json
```

JSON includes scanner version, scan mode, number of parsed documents, severity counts, and findings with resource, rule, message, and remediation details.

## Scan your own manifests

```bash
kubeguard scan --path ./k8s/
```

A single file must end in `.yaml` or `.yml`. Directories are scanned recursively for those extensions. Multi-document YAML files are supported.

## Run tests

```bash
pytest
```

Tests cover workload rules, RBAC rules, a hardened Deployment, and the included examples. They do not require a live cluster.

## Architecture

1. CLI parses arguments and handles exit codes.
2. Manifest loader safely parses YAML documents.
3. Rule engine evaluates workload and RBAC fields.
4. Reporter formats findings as readable text or JSON.

The scanner does not modify manifests or cluster resources.

## Limitations and roadmap

- **Offline only:** this version scans YAML files, not a live Kubernetes API. Live collection is a proposed next step, not implemented.
- **Partial coverage:** it does not check network policies, image provenance, secrets exposure, Pod Security Admission, admission policies, or all RBAC escalation paths.
- **Context matters:** `hostPath`, wildcards, and sensitive verbs may be legitimate in tightly controlled cases; findings need human review.
- **Not a full schema validator:** unknown or unsupported resource kinds may be ignored.
- **No auto-remediation:** it never changes input files or cluster state.
- **No external benchmark claim:** the rules have not been benchmarked against a commercial scanner or a comprehensive security suite.

Suggested next steps: add optional live-cluster collection with the Kubernetes Python client and a read-only ServiceAccount; configurable rules and exclusions; more controls; SARIF output; and integration tests against a disposable cluster.

## Security design decisions

- Uses `yaml.safe_load_all` for YAML parsing.
- Offline mode requires no Kubernetes credentials.
- Output is limited to resource identifiers and findings; it does not dump Secret contents.
- Any future live mode should use least-privilege read-only access and document exactly which API resources are read.

## Solution and strategic plan

See [`SOLUTION.md`](SOLUTION.md) for the feature priorities, technical implementation, and strategic development plan prepared for the take-home challenge.

## Demo talking points

- Offline manifests first makes the take-home demo reproducible without cluster setup.
- The selected checks target recognizable configuration risks with clear remediation.
- Findings are not auto-fixed because changes should be reviewed and tested by the owning team.
- A logical next step is live read-only collection, policy configuration, tests against a disposable cluster, and CI integration.
