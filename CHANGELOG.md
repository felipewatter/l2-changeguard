# Changelog

## [0.1.1] - 2026-11-09

- Maintenance release aligning the package and immutable release tag with the verified `main` revision.
- Update SHA-pinned GitHub Actions to `actions/checkout` v7.0.1 and `actions/setup-python` v7.1.0 for CI and release automation.
- No changes to the offline Layer 2 audit rules or input schemas.

## [0.1.0] - 2026-11-09

- Initial offline Layer 2 analyzer: LLDP reciprocity, VLAN/mode asymmetry, observed STP-forwarding cycles, MAC movement candidates and access-edge hardening.
- Baseline/candidate differential security gate with deterministic fingerprints.
- JSON and SARIF 2.1.0 reports, bounded schema validation, sample dataset, regression suite and 3x3 GitHub Actions CI matrix.
- Explicit model limitations, security policy, threat model and MIT licensing.
