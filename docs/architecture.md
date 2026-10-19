# Architecture notes

```text
CLI arguments
    |
    v
YAML file/directory loader
    |
    v
Kubernetes resource dictionaries
    |
    +--> Workload checks (Pod and common Pod-template controllers)
    +--> RBAC checks (Role and ClusterRole)
    |
    v
Sorted Finding objects
    |
    +--> Text report
    +--> JSON report
```

## Deliberate boundaries

- First version is offline-only; live API access is not implemented.
- Rule engine is read-only and has no remediation side effects.
- Each rule has a stable ID to support future baselines and CI policy.
- Scanner identifies configuration patterns that deserve review; it does not claim to determine exploitability.
