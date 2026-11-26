"""CLI and report formatters for FSI TLS Cert Sentinel."""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from tls_sentinel import __version__
from tls_sentinel.auditor import AuditFinding, audit_inventory


def format_markdown(findings: List[AuditFinding]) -> str:
    if not findings:
        return "# FSI TLS Audit Report\n\nAll endpoints meet cryptographic baselines.\n"
    lines = [
        "# FSI TLS Audit Report",
        "",
        "| Severity | Rule ID | Endpoint | Issue | Framework |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            f"| {f.severity.upper()} | `{f.rule_id}` | `{f.endpoint}` | {f.message} | {f.framework} |"
        )
    return "\n".join(lines) + "\n"


def format_sarif(findings: List[AuditFinding], source_file: str = "inventory.json") -> str:
    """Render TLS audit findings in SARIF 2.1.0 format."""
    level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    results = [
        {
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f"[{f.endpoint}] {f.message} ({f.framework})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": source_file}}}],
        }
        for f in findings
    ]
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "fsi-tls-cert-sentinel", "version": __version__}}, "results": results}],
        },
        indent=2,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fsi-tls-sentinel",
        description="Audit TLS endpoint inventories for FSI compliance and PQC readiness.",
    )
    parser.add_argument("inventory", type=Path, help="Path to TLS inventory JSON file.")
    parser.add_argument(
        "--format", choices=["json", "markdown", "sarif"], default="markdown", help="Output format."
    )
    parser.add_argument(
        "--warn-days", type=int, default=30, help="Expiry warning threshold in days."
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    data = json.loads(args.inventory.read_text(encoding="utf-8"))
    findings = audit_inventory(data.get("endpoints", []), warn_days=args.warn_days)

    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    elif args.format == "sarif":
        print(format_sarif(findings, source_file=str(args.inventory)))
    else:
        print(format_markdown(findings))

    has_critical = any(f.severity == "critical" for f in findings)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
