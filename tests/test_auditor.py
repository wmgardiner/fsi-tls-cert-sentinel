"""Unit tests for FSI TLS Cert Sentinel."""

from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from tls_sentinel.auditor import audit_inventory

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


class TestTlsAuditor(unittest.TestCase):
    def test_sample_inventory_flags_legacy_endpoint_only(self) -> None:
        now = datetime(2026, 11, 26, tzinfo=timezone.utc)
        data = json.loads((EXAMPLES_DIR / "sample_inventory.json").read_text(encoding="utf-8"))
        findings = audit_inventory(data["endpoints"], now=now, warn_days=30)

        by_endpoint = {}
        for f in findings:
            by_endpoint.setdefault(f.endpoint, set()).add(f.rule_id)

        self.assertNotIn("api.corebanking.example:443", by_endpoint)
        self.assertEqual(
            by_endpoint["legacy-swift-gw.example:443"],
            {"TLS-EXP-002", "TLS-PROTO-001", "TLS-KEY-001", "TLS-SIG-001", "TLS-PQC-001"},
        )


if __name__ == "__main__":
    unittest.main()
