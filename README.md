# k8s-manifest-security-hardening-lint-cli-lite

**Zero-dependency Python 3.9+ CLI linter for Kubernetes YAML manifest security hardening.**

Audit `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, `CronJob`, and `Job` manifests in CI/CD pipelines with **100% Python stdlib** — no `PyYAML`, no `kubectl`, no external binaries required.

## Key Features

- **100% Python 3.9+ stdlib** — includes a custom multi-document YAML parser (`---` support).
- **12 Built-in Security Rules** covering Pod Security Standards (Restricted/Baseline), resource limits, image pinning, capabilities, probes, and hardcoded secrets.
- **CI/CD Ready** — `text`, `json`, and `markdown` output formats with configurable `--fail-on` severity thresholds (`none`, `low`, `medium`, `high`, `critical`).
- **Multi-Workload Support** — `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, `CronJob`, and `Job`.

## Quick Start

```bash
# Scan a single manifest (default: text output, fail on high/critical)
python -m k8s_sec_lint sample_manifests/insecure-deployment.yaml

# Scan a directory and output JSON
python -m k8s_sec_lint sample_manifests/ --format json --fail-on medium

# Output Markdown report for GitHub Actions PR comments
python -m k8s_sec_lint sample_manifests/ --format markdown --fail-on critical
```

## Security Rules

| Rule ID | Severity | Description |
| --- | --- | --- |
| `K8S-SEC-001` | `CRITICAL` | Container runs in `privileged: true` mode |
| `K8S-SEC-002` | `HIGH` | `allowPrivilegeEscalation` is not explicitly `false` |
| `K8S-SEC-003` | `HIGH` | `runAsNonRoot` is not set to `true` |
| `K8S-SEC-004` | `MEDIUM` | `readOnlyRootFilesystem` is not set to `true` |
| `K8S-SEC-005` | `CRITICAL` | `hostNetwork`, `hostPID`, or `hostIPC` enabled |
| `K8S-SEC-006` | `MEDIUM` | Missing CPU and/or memory `resources.limits` |
| `K8S-SEC-007` | `MEDIUM` | Image uses `:latest` tag or omits an explicit tag |
| `K8S-SEC-008` | `HIGH` | Dangerous Linux capabilities added or `drop: ["ALL"]` missing |
| `K8S-SEC-009` | `LOW` | Missing `livenessProbe` or `readinessProbe` |
| `K8S-SEC-010` | `CRITICAL` | Hardcoded secret detected in `env` literal `value` |
| `K8S-SEC-011` | `HIGH` | `hostPath` volume mounted |
| `K8S-SEC-012` | `MEDIUM` | `automountServiceAccountToken` not set to `false` |

## CI/CD Integration (GitHub Actions)

```yaml
name: Kubernetes Security Lint
on: [push, pull_request]
jobs:
  k8s-sec-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Run k8s-sec-lint
        run: python -m k8s_sec_lint k8s/ --format markdown --fail-on high
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Pro Studio Version (Web UI + SARIF + 15+ Rules + Custom Policies)

Looking for **SARIF output for GitHub Code Scanning**, an interactive **Web UI**, **15+ advanced compliance rules** (CIS Kubernetes Benchmark / NSA-CISA), and **custom OPA/YAML policy rules**?

Check out the **Pro Studio Version** on our storefront:
👉 https://funpay.com/users/20096179/

## License

MIT
