"""TLS certificate, protocol, and post-quantum readiness auditing rules."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

DEPRECATED_PROTOCOLS = {"TLS 1.0", "TLS 1.1", "SSL 3.0"}
WEAK_SIGNATURES = {"MD5", "SHA1", "SHA-1"}
PQC_KEY_EXCHANGES = {"X25519MLKEM768", "ML-KEM-768", "ML-KEM-1024"}


@dataclass(frozen=True)
class AuditFinding:
    rule_id: str
    endpoint: str
    severity: str  # low, medium, high, critical
    message: str
    framework: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "message": self.message,
            "framework": self.framework,
        }


def audit_endpoint(
    entry: Dict[str, Any],
    now: datetime | None = None,
    warn_days: int = 30,
) -> List[AuditFinding]:
    """Audit a single TLS endpoint inventory record against FSI baselines."""
    now = now or datetime.now(timezone.utc)
    endpoint = str(entry.get("endpoint", "unknown"))
    findings: List[AuditFinding] = []

    not_after_raw = entry.get("not_after")
    if not_after_raw:
        not_after = datetime.fromisoformat(str(not_after_raw).replace("Z", "+00:00"))
        days_left = (not_after - now).days
        if days_left < 0:
            findings.append(
                AuditFinding(
                    "TLS-EXP-001",
                    endpoint,
                    "critical",
                    f"Certificate expired {abs(days_left)} day(s) ago.",
                    "PCI-DSS v4.0 4.2.1",
                )
            )
        elif days_left <= warn_days:
            findings.append(
                AuditFinding(
                    "TLS-EXP-002",
                    endpoint,
                    "high",
                    f"Certificate expires in {days_left} day(s) (threshold: {warn_days}d).",
                    "APRA CPS 234",
                )
            )

    protocols = set(entry.get("protocols", []))
    weak_protos = sorted(protocols & DEPRECATED_PROTOCOLS)
    if weak_protos:
        findings.append(
            AuditFinding(
                "TLS-PROTO-001",
                endpoint,
                "critical",
                f"Deprecated TLS protocol(s) enabled: {', '.join(weak_protos)}.",
                "PCI-DSS v4.0 4.2.1 / NIST SP 800-52r2",
            )
        )

    key_type = str(entry.get("key_type", "RSA")).upper()
    key_bits = int(entry.get("key_bits", 0))
    if key_type == "RSA" and key_bits < 2048:
        findings.append(
            AuditFinding(
                "TLS-KEY-001",
                endpoint,
                "critical",
                f"RSA key length {key_bits} bits is below 2048-bit minimum.",
                "NIST SP 800-52r2",
            )
        )
    elif key_type == "ECDSA" and key_bits < 256:
        findings.append(
            AuditFinding(
                "TLS-KEY-002",
                endpoint,
                "high",
                f"ECDSA curve size {key_bits} bits is below 256-bit minimum.",
                "NIST SP 800-52r2",
            )
        )

    sig_alg = str(entry.get("signature_algorithm", "")).upper()
    if any(w in sig_alg for w in WEAK_SIGNATURES):
        findings.append(
            AuditFinding(
                "TLS-SIG-001",
                endpoint,
                "critical",
                f"Weak certificate signature algorithm detected: {sig_alg}.",
                "PCI-DSS v4.0 4.2.1",
            )
        )

    kex = set(entry.get("key_exchange", []))
    if not (kex & PQC_KEY_EXCHANGES):
        findings.append(
            AuditFinding(
                "TLS-PQC-001",
                endpoint,
                "low",
                "Endpoint does not advertise hybrid post-quantum key exchange (e.g., X25519MLKEM768).",
                "DORA / NIST PQC Migration",
            )
        )

    return findings


def audit_inventory(
    endpoints: List[Dict[str, Any]],
    now: datetime | None = None,
    warn_days: int = 30,
) -> List[AuditFinding]:
    """Audit a full list of TLS endpoint records."""
    all_findings: List[AuditFinding] = []
    for entry in endpoints:
        all_findings.extend(audit_endpoint(entry, now=now, warn_days=warn_days))
    return all_findings
