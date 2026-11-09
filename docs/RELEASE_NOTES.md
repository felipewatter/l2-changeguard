# L2 ChangeGuard v0.1.1 — Maintenance release

This patch release incorporates GitHub Actions dependency upgrades already validated on the `main` branch.

- Update `actions/checkout` to v7.0.1 and `actions/setup-python` to v7.1.0, both pinned to reviewed commit SHAs.
- Retain the eight offline Layer 2 audit checks, baseline comparison, JSON/SARIF reporting, and existing model limitations without changing the detection engine.
- Build source ZIP, per-file SHA-256 manifest, and release checksums from the exact commit passing CI.

This release does not modify network devices or access live environments. Previous release `v0.1.0` remains immutable.
