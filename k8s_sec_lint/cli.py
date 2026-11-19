"""CLI interface for k8s-manifest-security-hardening-lint-cli-lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Sequence

from . import __version__
from .rules import SEVERITY_ORDER, Finding, audit_document
from .yaml_parser import parse_yaml_documents


def collect_yaml_files(paths: Sequence[str]) -> List[Path]:
    files: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for ext in ("*.yaml", "*.yml"):
                files.extend(sorted(p.rglob(ext)))
    return files


def format_text(findings: List[Finding]) -> str:
    if not findings:
        return "No security issues found."
    lines = [f"Found {len(findings)} security issue(s):"]
    for f in findings:
        loc = f"{f.kind}/{f.resource}"
        if f.container != "<pod>":
            loc += f" (container: {f.container})"
        file_prefix = f"[{f.file}] " if f.file else ""
        lines.append(f"  {file_prefix}[{f.severity}] {f.rule_id} {loc}: {f.message}")
    return "\n".join(lines)


def format_json(findings: List[Finding]) -> str:
    payload = {
        "version": __version__,
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def format_markdown(findings: List[Finding]) -> str:
    if not findings:
        return "## Kubernetes Security Audit\n\nNo security issues found."
    lines = [
        "## Kubernetes Security Audit",
        "",
        f"Total findings: **{len(findings)}**",
        "",
        "| Severity | Rule | Resource | Container | Message |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| {f.severity} | `{f.rule_id}` | `{f.kind}/{f.resource}` | `{f.container}` | {f.message} |"
        )
    return "\n".join(lines)


def should_fail(findings: List[Finding], fail_on: str) -> bool:
    if fail_on.upper() == "NONE":
        return False
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 3)
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s-sec-lint",
        description="Zero-dependency Kubernetes YAML manifest security linter.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="YAML manifest files or directories to scan.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="Minimum severity to exit with code 1 (default: high).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    files = collect_yaml_files(args.paths)
    if not files:
        print("No YAML files found.", file=sys.stderr)
        return 2

    all_findings: List[Finding] = []
    for file_path in files:
        content = file_path.read_text(encoding="utf-8")
        docs = parse_yaml_documents(content)
        for doc in docs:
            all_findings.extend(audit_document(doc, file_path=str(file_path)))

    if args.format == "json":
        print(format_json(all_findings))
    elif args.format == "markdown":
        print(format_markdown(all_findings))
    else:
        print(format_text(all_findings))

    return 1 if should_fail(all_findings, args.fail_on) else 0
