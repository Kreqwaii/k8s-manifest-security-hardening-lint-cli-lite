"""Security audit rules for Kubernetes workload manifests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SUPPORTED_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Pod", "CronJob", "Job"}

DANGEROUS_CAPABILITIES = {
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "NET_RAW",
    "SYS_MODULE",
    "DAC_OVERRIDE",
    "SYS_RAWIO",
    "SYS_CHROOT",
}

SECRET_ENV_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AWS_SECRET|ACCESS_KEY|CREDENTIALS|AUTH_KEY)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    kind: str
    resource: str
    container: str
    message: str
    remediation: str
    file: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "kind": self.kind,
            "resource": self.resource,
            "container": self.container,
            "message": self.message,
            "remediation": self.remediation,
            "file": self.file,
        }


def _extract_pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = doc.get("kind")
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
        template = spec.get("template")
        if isinstance(template, dict) and isinstance(template.get("spec"), dict):
            return template["spec"]
    if kind == "CronJob":
        job_tmpl = spec.get("jobTemplate")
        if isinstance(job_tmpl, dict):
            job_spec = job_tmpl.get("spec")
            if isinstance(job_spec, dict):
                template = job_spec.get("template")
                if isinstance(template, dict) and isinstance(template.get("spec"), dict):
                    return template["spec"]
    return None


def audit_document(doc: Any, file_path: str = "") -> List[Finding]:
    """Run all 12 security rules against a single parsed Kubernetes YAML document."""
    if not isinstance(doc, dict):
        return []

    kind = doc.get("kind")
    if kind not in SUPPORTED_KINDS:
        return []

    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    resource_name = str(metadata.get("name", "<unnamed>"))
    pod_spec = _extract_pod_spec(doc)
    if not isinstance(pod_spec, dict):
        return []

    findings: List[Finding] = []
    pod_sec_ctx = pod_spec.get("securityContext") if isinstance(pod_spec.get("securityContext"), dict) else {}

    # K8S-SEC-005: hostNetwork / hostPID / hostIPC
    for host_flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(host_flag) is True:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-005",
                    severity="CRITICAL",
                    kind=kind,
                    resource=resource_name,
                    container="<pod>",
                    message=f"Pod enables {host_flag}: true, breaking host isolation.",
                    remediation=f"Set spec.{host_flag}: false or remove it.",
                    file=file_path,
                )
            )

    # K8S-SEC-011: hostPath volume mount
    volumes = pod_spec.get("volumes")
    if isinstance(volumes, list):
        for vol in volumes:
            if isinstance(vol, dict) and "hostPath" in vol:
                vol_name = vol.get("name", "<unnamed>")
                findings.append(
                    Finding(
                        rule_id="K8S-SEC-011",
                        severity="HIGH",
                        kind=kind,
                        resource=resource_name,
                        container="<pod>",
                        message=f"Volume '{vol_name}' uses hostPath, exposing host filesystem.",
                        remediation="Replace hostPath with emptyDir, configMap, secret, or PVC.",
                        file=file_path,
                    )
                )

    # K8S-SEC-012: automountServiceAccountToken
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(
            Finding(
                rule_id="K8S-SEC-012",
                severity="MEDIUM",
                kind=kind,
                resource=resource_name,
                container="<pod>",
                message="automountServiceAccountToken is not explicitly set to false.",
                remediation="Set automountServiceAccountToken: false unless the pod needs Kubernetes API access.",
                file=file_path,
            )
        )

    containers: List[Dict[str, Any]] = []
    for key in ("containers", "initContainers"):
        c_list = pod_spec.get(key)
        if isinstance(c_list, list):
            containers.extend([c for c in c_list if isinstance(c, dict)])

    for container in containers:
        c_name = str(container.get("name", "<unnamed>"))
        sec_ctx = container.get("securityContext") if isinstance(container.get("securityContext"), dict) else {}

        # K8S-SEC-001: privileged: true
        if sec_ctx.get("privileged") is True:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-001",
                    severity="CRITICAL",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="Container runs in privileged mode (privileged: true).",
                    remediation="Set securityContext.privileged: false.",
                    file=file_path,
                )
            )

        # K8S-SEC-002: allowPrivilegeEscalation != false
        if sec_ctx.get("allowPrivilegeEscalation") is not False:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-002",
                    severity="HIGH",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="allowPrivilegeEscalation is not explicitly set to false.",
                    remediation="Set securityContext.allowPrivilegeEscalation: false.",
                    file=file_path,
                )
            )

        # K8S-SEC-003: runAsNonRoot != true (check container then pod)
        run_as_non_root = sec_ctx.get("runAsNonRoot")
        if run_as_non_root is None:
            run_as_non_root = pod_sec_ctx.get("runAsNonRoot")
        if run_as_non_root is not True:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-003",
                    severity="HIGH",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="runAsNonRoot is not set to true.",
                    remediation="Set securityContext.runAsNonRoot: true at pod or container level.",
                    file=file_path,
                )
            )

        # K8S-SEC-004: readOnlyRootFilesystem != true
        if sec_ctx.get("readOnlyRootFilesystem") is not True:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-004",
                    severity="MEDIUM",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="readOnlyRootFilesystem is not set to true.",
                    remediation="Set securityContext.readOnlyRootFilesystem: true and mount writable emptyDir where needed.",
                    file=file_path,
                )
            )

        # K8S-SEC-006: Missing CPU/memory limits
        resources = container.get("resources") if isinstance(container.get("resources"), dict) else {}
        limits = resources.get("limits") if isinstance(resources.get("limits"), dict) else {}
        if not limits.get("cpu") or not limits.get("memory"):
            findings.append(
                Finding(
                    rule_id="K8S-SEC-006",
                    severity="MEDIUM",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="Container is missing CPU and/or memory resource limits.",
                    remediation="Define resources.limits.cpu and resources.limits.memory.",
                    file=file_path,
                )
            )

        # K8S-SEC-007: :latest tag or untagged image
        image = str(container.get("image", ""))
        if image:
            last_part = image.split("/")[-1]
            if ":" not in last_part or last_part.endswith(":latest"):
                findings.append(
                    Finding(
                        rule_id="K8S-SEC-007",
                        severity="MEDIUM",
                        kind=kind,
                        resource=resource_name,
                        container=c_name,
                        message=f"Container image '{image}' uses ':latest' or omits an explicit tag.",
                        remediation="Pin image to an immutable version tag or SHA256 digest.",
                        file=file_path,
                    )
                )

        # K8S-SEC-008: Dangerous capabilities or missing drop ALL
        caps = sec_ctx.get("capabilities") if isinstance(sec_ctx.get("capabilities"), dict) else {}
        add_caps = caps.get("add") if isinstance(caps.get("add"), list) else []
        drop_caps = caps.get("drop") if isinstance(caps.get("drop"), list) else []
        bad_added = [str(c).upper() for c in add_caps if str(c).upper() in DANGEROUS_CAPABILITIES]
        if bad_added:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-008",
                    severity="HIGH",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message=f"Container adds dangerous Linux capabilities: {', '.join(bad_added)}.",
                    remediation="Remove dangerous capabilities and drop ALL.",
                    file=file_path,
                )
            )
        elif "ALL" not in [str(c).upper() for c in drop_caps]:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-008",
                    severity="HIGH",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="Container does not drop ALL Linux capabilities.",
                    remediation="Set securityContext.capabilities.drop: ['ALL'].",
                    file=file_path,
                )
            )

        # K8S-SEC-009: Missing livenessProbe or readinessProbe
        if "livenessProbe" not in container or "readinessProbe" not in container:
            findings.append(
                Finding(
                    rule_id="K8S-SEC-009",
                    severity="LOW",
                    kind=kind,
                    resource=resource_name,
                    container=c_name,
                    message="Container is missing livenessProbe and/or readinessProbe.",
                    remediation="Configure both livenessProbe and readinessProbe.",
                    file=file_path,
                )
            )

        # K8S-SEC-010: Hardcoded secrets in env
        env_list = container.get("env")
        if isinstance(env_list, list):
            for env_item in env_list:
                if isinstance(env_item, dict):
                    env_name = str(env_item.get("name", ""))
                    if SECRET_ENV_PATTERN.search(env_name) and "value" in env_item and env_item["value"] is not None:
                        findings.append(
                            Finding(
                                rule_id="K8S-SEC-010",
                                severity="CRITICAL",
                                kind=kind,
                                resource=resource_name,
                                container=c_name,
                                message=f"Hardcoded secret detected in env var '{env_name}'.",
                                remediation="Use valueFrom.secretKeyRef instead of plaintext value.",
                                file=file_path,
                            )
                        )

    return findings
