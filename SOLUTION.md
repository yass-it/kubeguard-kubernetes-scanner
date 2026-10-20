# KubeGuard — Kubernetes Security Scanner

## 1. Overview and Scope

KubeGuard is a lightweight proof of concept for detecting common Kubernetes security misconfigurations and producing actionable findings.

The initial implementation scans local Kubernetes YAML manifests without requiring cluster access or credentials. This scope makes the prototype 
reproducible, easy to evaluate, and suitable for pre-deployment checks.

The current version implements workload security and RBAC checks, human-readable and JSON reporting, and automated tests. It is not a 
live-cluster scanner or a production-ready security product.

## 2. Top Three Feature Ideas

### Feature 1 — Workload Security Misconfiguration Detection

Detect risky workload configurations such as privileged containers, privilege escalation, missing non-root enforcement, host networking, and 
hostPath volumes.

**Why it matters:** These settings can increase the impact of a compromised workload or expand its access to the underlying node.

**Current status:** Implemented for the supported manifest structures and rules.

**Future improvement:** Expand coverage across Kubernetes workload types, validate resource structures, and add tests for nested Pod templates 
and edge cases.

### Feature 2 — RBAC Risk Detection

Identify wildcard permissions and sensitive RBAC verbs such as `bind`, `escalate`, and `impersonate` in Roles and ClusterRoles.

**Why it matters:** Excessive permissions can enable privilege escalation and expand the blast radius of compromised identities.

**Current status:** Basic checks for wildcard permissions and sensitive verbs are implemented for Roles and ClusterRoles.

**Future improvement:** Add contextual analysis of RoleBindings and ClusterRoleBindings, effective permissions, and privilege-escalation paths. 
Findings should distinguish suspicious patterns from permissions justified by operational requirements.

### Feature 3 — Actionable Findings and CI/CD Integration

Provide stable rule IDs, severity, resource context, explanations, and remediation recommendations. Support machine-readable output so findings 
can be consumed by automated workflows.

**Why it matters:** A scanner is more useful when engineers can understand, prioritize, and act on findings instead of receiving an opaque 
pass/fail result.

**Current status:** Human-readable and JSON reports are implemented. The CLI returns distinct exit codes for findings, clean scans, and execution 
errors.

**Future improvement:** Add configurable policies and exclusions, SARIF output, and CI/CD examples. Establish a documented severity model and 
validate false positives before recommending the scanner as a blocking security gate.

## 3. Technical Implementation

### Architecture

The prototype uses a small, modular pipeline:

1. **CLI:** Accepts a file or directory path and the desired output format.
2. **Manifest loader:** Reads YAML files and parses multiple YAML documents safely.
3. **Rule engine:** Evaluates supported workload and RBAC configurations.
4. **Finding model:** Represents each finding with a rule ID, severity, resource context, explanation, and recommendation.
5. **Reporter:** Produces readable terminal output or JSON.

### Technology Choices

- **Python:** Chosen for implementation speed, readability, and straightforward testing within the take-home time limit.
- **PyYAML:** Used with `safe_load_all` to parse YAML documents.
- **pytest:** Used to validate rule behavior, error handling, and safe versus vulnerable examples.
- **CLI and JSON:** Keep the tool easy to run locally and make its output suitable for later automation.

Go would be a reasonable alternative if standalone binary distribution or different operational constraints became important. For this prototype, 
Python allows faster iteration on the security logic.

### Execution Model

The current version runs locally against YAML files or directories. It does not connect to a Kubernetes API, require cluster credentials, modify 
manifests, or perform automatic remediation.

Example commands:

```bash
python -m pip install -e ".[dev]"
kubeguard scan --path examples/vulnerable.yaml
kubeguard scan --path examples/hardened.yaml
kubeguard scan --path examples --format json --output report.json
pytest -q
```

A scan returns exit code `1` when findings are reported, `0` when no configured checks are triggered, and `2` for input or execution errors.

### Validation Performed

The prototype was tested against the included vulnerable and hardened examples. The vulnerable example produced seven findings across workload 
and RBAC rules, while the hardened example produced zero findings under the current rule set. The automated test suite passed eight tests.

These results validate the included scenarios only; they do not establish comprehensive Kubernetes security coverage.

### Security and Reliability Considerations

- Use safe YAML parsing.
- Keep scanning read-only and avoid unnecessary permissions.
- The current rules do not report Secret contents. Secret exposure detection is outside the current scope.
- Test both positive and negative cases.
- Treat findings as potential misconfigurations, not proof of exploitability.
- Make rule coverage and limitations explicit.

## 4. Strategic Development Plan

### Phase 1 — Establish a Reliable Baseline

**Goal:** Make the core scanner predictable and easy to evaluate.

- Define the initial rule set and stable rule IDs.
- Test supported Kubernetes resource structures.
- Improve malformed-input handling and edge-case coverage.
- Document severity definitions and known limitations.
- Measure false positives using representative manifests.

**Exit criteria:** Reproducible scans, deterministic output, passing tests, and documented behavior.

### Phase 2 — Improve Coverage and Developer Experience

**Goal:** Increase usefulness without making findings noisy or difficult to act on.

- Expand workload and RBAC analysis.
- Add configurable exclusions and documented exceptions.
- Include remediation guidance and structured output.
- Add SARIF and CI/CD integration examples.
- Test against representative repositories and review findings with Kubernetes practitioners.

**Exit criteria:** Useful findings with understandable rationale, controlled false positives, and output that fits developer workflows.

### Phase 3 — Introduce Optional Live-Cluster Scanning

**Goal:** Extend beyond deployment manifests to inspect deployed resources.

- Add a separate live-scanning mode using the Kubernetes Python client.
- Start with an explicit, read-only list of API resources.
- Use a dedicated ServiceAccount with least-privilege RBAC.
- Handle API failures, permissions, pagination, and partial scans explicitly.
- Avoid collecting sensitive data that is not required for the checks.
- Test against a disposable cluster before wider deployment.

**Exit criteria:** Documented permissions, predictable API behavior, safe failure handling, and validated results.

### Phase 4 — Production Readiness

**Goal:** Establish operational trust before presenting the scanner as production-ready.

- Define a risk model that considers severity, context, and exceptions.
- Add regression testing and broader Kubernetes compatibility coverage.
- Evaluate performance on larger repositories and clusters.
- Version rules and define a process for updates.
- Add monitoring and operational documentation where appropriate.
- Validate the scanner against independent test cases and established security benchmarks.

Production readiness should be an evidence-based decision, not an assumption based on the number of implemented rules.

## 5. Current Limitations

This is a time-boxed proof of concept. The current version:

- Scans local YAML manifests only.
- Implements a limited set of workload and RBAC rules.
- Does not analyze RoleBindings or ClusterRoleBindings to calculate effective permissions.
- Does not perform live-cluster collection.
- Does not implement automatic remediation.
- Does not provide comprehensive Kubernetes security coverage.
- Does not claim to prove exploitability or replace a full security assessment.

## 6. Summary

KubeGuard prioritizes a small, transparent set of actionable checks over broad but unvalidated coverage. The prototype demonstrates the core 
scanning pipeline and reporting behavior while keeping its operational scope explicit.

The next priority is to validate rule quality, improve coverage and contextual analysis, and integrate the scanner into developer workflows. 
Live-cluster scanning should follow with carefully scoped, least-privilege access and explicit validation criteria.
