"""Unit tests for k8s_sec_lint (YAML parser, 12 security rules, CLI, and formats)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from k8s_sec_lint.cli import format_json, format_markdown, format_text, main, should_fail
from k8s_sec_lint.rules import audit_document
from k8s_sec_lint.yaml_parser import parse_yaml_documents

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "sample_manifests"


class TestYamlParser(unittest.TestCase):
    def test_single_document_basic_types(self):
        yaml_text = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  replicas: 3
  enabled: true
  disabled: false
"""
        docs = parse_yaml_documents(yaml_text)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["kind"], "Pod")
        self.assertEqual(docs[0]["metadata"]["replicas"], 3)
        self.assertIs(docs[0]["metadata"]["enabled"], True)
        self.assertIs(docs[0]["metadata"]["disabled"], False)

    def test_multi_document_separator(self):
        yaml_text = """
---
kind: Pod
metadata:
  name: pod-one
---
kind: Deployment
metadata:
  name: deploy-two
"""
        docs = parse_yaml_documents(yaml_text)
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0]["metadata"]["name"], "pod-one")
        self.assertEqual(docs[1]["metadata"]["name"], "deploy-two")

    def test_inline_lists_and_comments(self):
        yaml_text = """
# Top comment
kind: Pod # inline comment
spec:
  capabilities:
    drop: ["ALL", "NET_RAW"] # another comment
"""
        docs = parse_yaml_documents(yaml_text)
        self.assertEqual(docs[0]["spec"]["capabilities"]["drop"], ["ALL", "NET_RAW"])

    def test_list_of_dicts(self):
        yaml_text = """
containers:
  - name: app
    image: nginx:1.25
  - name: sidecar
    image: busybox:1.36
"""
        docs = parse_yaml_documents(yaml_text)
        self.assertEqual(len(docs[0]["containers"]), 2)
        self.assertEqual(docs[0]["containers"][0]["name"], "app")
        self.assertEqual(docs[0]["containers"][1]["image"], "busybox:1.36")


class TestSecurityRules(unittest.TestCase):
    def _base_pod(self, container_override=None, pod_override=None):
        container = {
            "name": "app",
            "image": "ghcr.io/org/app:1.0.0",
            "securityContext": {
                "privileged": False,
                "allowPrivilegeEscalation": False,
                "runAsNonRoot": True,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
            "resources": {"limits": {"cpu": "200m", "memory": "128Mi"}},
            "livenessProbe": {"httpGet": {"path": "/health", "port": 8080}},
            "readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
        }
        if container_override:
            container.update(container_override)
        spec = {"automountServiceAccountToken": False, "containers": [container]}
        if pod_override:
            spec.update(pod_override)
        return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"}, "spec": spec}

    def test_hardened_pod_has_zero_findings(self):
        findings = audit_document(self._base_pod())
        self.assertEqual(findings, [])

    def test_rule_001_privileged(self):
        doc = self._base_pod({"securityContext": {
            "privileged": True,
            "allowPrivilegeEscalation": False,
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-001", ids)

    def test_rule_002_allow_privilege_escalation(self):
        doc = self._base_pod({"securityContext": {
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-002", ids)

    def test_rule_003_run_as_non_root_missing(self):
        doc = self._base_pod({"securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-003", ids)

    def test_rule_003_run_as_non_root_inherited_from_pod(self):
        doc = self._base_pod(
            container_override={"securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            }},
            pod_override={"runAsNonRoot": True, "securityContext": {"runAsNonRoot": True}},
        )
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertNotIn("K8S-SEC-003", ids)

    def test_rule_004_readonly_root_fs(self):
        doc = self._base_pod({"securityContext": {
            "allowPrivilegeEscalation": False,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
        }})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-004", ids)

    def test_rule_005_host_network(self):
        doc = self._base_pod(pod_override={"hostNetwork": True})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-005", ids)

    def test_rule_005_host_pid(self):
        doc = self._base_pod(pod_override={"hostPID": True})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-005", ids)

    def test_rule_006_missing_resource_limits(self):
        doc = self._base_pod({"resources": {}})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-006", ids)

    def test_rule_007_latest_image_tag(self):
        doc = self._base_pod({"image": "nginx:latest"})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-007", ids)

    def test_rule_007_untagged_image(self):
        doc = self._base_pod({"image": "nginx"})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-007", ids)

    def test_rule_008_dangerous_capability(self):
        doc = self._base_pod({"securityContext": {
            "allowPrivilegeEscalation": False,
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "capabilities": {"add": ["SYS_ADMIN"], "drop": ["ALL"]},
        }})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-008", ids)

    def test_rule_008_missing_drop_all(self):
        doc = self._base_pod({"securityContext": {
            "allowPrivilegeEscalation": False,
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
        }})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-008", ids)

    def test_rule_009_missing_probes(self):
        doc = self._base_pod({"livenessProbe": None})
        doc["spec"]["containers"][0].pop("livenessProbe", None)
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-009", ids)

    def test_rule_010_hardcoded_secret_env(self):
        doc = self._base_pod({"env": [{"name": "API_KEY", "value": "12345"}]})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-010", ids)

    def test_rule_010_secret_key_ref_allowed(self):
        doc = self._base_pod({"env": [{"name": "API_KEY", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertNotIn("K8S-SEC-010", ids)

    def test_rule_011_host_path_volume(self):
        doc = self._base_pod(pod_override={"volumes": [{"name": "v", "hostPath": {"path": "/etc"}}]})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-011", ids)

    def test_rule_012_automount_service_account_token(self):
        doc = self._base_pod(pod_override={"automountServiceAccountToken": True})
        ids = [f.rule_id for f in audit_document(doc)]
        self.assertIn("K8S-SEC-012", ids)

    def test_cronjob_and_statefulset_and_daemonset_supported(self):
        for kind in ("StatefulSet", "DaemonSet"):
            doc = {"kind": kind, "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "alpine:latest"}]}}}}
            self.assertGreater(len(audit_document(doc)), 0)
        cron = {"kind": "CronJob", "metadata": {"name": "cj"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "c", "image": "alpine:latest"}]}}}}}}
        self.assertGreater(len(audit_document(cron)), 0)

    def test_unsupported_kind_ignored(self):
        doc = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {"ports": []}}
        self.assertEqual(audit_document(doc), [])


class TestCliAndOutputs(unittest.TestCase):
    def test_cli_hardened_sample_passes(self):
        code = main([str(SAMPLES_DIR / "hardened-deployment.yaml"), "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_cli_insecure_sample_fails_on_high(self):
        code = main([str(SAMPLES_DIR / "insecure-deployment.yaml"), "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_cli_insecure_sample_passes_when_fail_on_none(self):
        code = main([str(SAMPLES_DIR / "insecure-deployment.yaml"), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_format_json_and_markdown_and_text(self):
        docs = parse_yaml_documents((SAMPLES_DIR / "insecure-deployment.yaml").read_text(encoding="utf-8"))
        findings = []
        for d in docs:
            findings.extend(audit_document(d, file_path="insecure.yaml"))
        parsed = json.loads(format_json(findings))
        self.assertEqual(parsed["total"], len(findings))
        self.assertIn("| Severity | Rule |", format_markdown(findings))
        self.assertIn("Found ", format_text(findings))

    def test_should_fail_thresholds(self):
        docs = parse_yaml_documents((SAMPLES_DIR / "insecure-deployment.yaml").read_text(encoding="utf-8"))
        findings = audit_document(docs[0])
        self.assertTrue(should_fail(findings, "critical"))
        self.assertFalse(should_fail([], "low"))

    def test_subprocess_module_invocation(self):
        proc = subprocess.run(
            [sys.executable, "-m", "k8s_sec_lint", str(SAMPLES_DIR / "hardened-deployment.yaml"), "--format", "json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["total"], 0)


if __name__ == "__main__":
    unittest.main()
