# FSI TLS Cert Sentinel

Cryptographic, TLS certificate, and Post-Quantum Cryptography (PQC) readiness auditor for Financial Services workloads.

## Checks Performed
- Certificate expiry window alerts (expired / expiring within 30 days)
- Weak asymmetric key sizes (RSA < 2048 bits, ECDSA < 256 bits)
- Deprecated TLS protocol versions (`TLS 1.0`, `TLS 1.1`)
- Legacy signature algorithms (`SHA-1`, `MD5`)
- Post-Quantum (PQC) migration readiness tracking (ML-KEM / hybrid key exchange)

## Quick Start

```bash
python3 -m tls_sentinel.cli examples/sample_inventory.json --format markdown
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
