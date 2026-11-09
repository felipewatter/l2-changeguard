# L2 ChangeGuard — English overview

Offline, deterministic Layer 2 network change auditing for structured JSON snapshots. License: MIT. Python 3.11+, no runtime dependencies.

**Maintainer:** [Felipe Silva](https://github.com/felipewatter) · **Project:** [GitHub](https://github.com/felipewatter/l2-changeguard) · [Full Portuguese guide](README.md).

## What it does

- Checks reciprocal LLDP connectivity, trunk/access VLAN mismatches, VLAN allowlist and native-VLAN inconsistencies.
- Finds *possible* forwarding cycles only when three or more switches form a trunk graph with **explicit** STP forwarding evidence on both ends of every link for the same VLAN. This is not a live loop guarantee.
- Flags local MAC/VLAN entries seen on multiple ports on the same switch.
- Enforces configurable edge-port BPDU Guard / port security requirements, approved native VLANs, protected VLAN STP configuration and critical-switch neighbor diversity.
- Compares baseline vs candidate: introduced, resolved and persisting findings; fails on newly introduced findings above a configured threshold.
- Produces deterministic JSON and SARIF 2.1.0 output, stable finding fingerprints and checksum-verifiable releases.

## Run

```bash
python -m pip install -e .
l2changeguard audit --candidate examples/baseline.json --policy examples/policy.json
l2changeguard compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --policy examples/policy.json --fail-on high --output report.json --sarif report.sarif
python -m unittest discover -s tests -v
```

Exit status: `0` pass, `2` gate blocked, `3` input/output error. Positional mode: `audit` or `compare`; `--fail-on critical|high|medium|low|none` (defaults to high). `audit` applies the threshold to all findings; `compare` applies it **only** to new findings. Existing issues remain visible.

## CI and security

Nine CI matrix combinations (3 operating systems × Python 3.11/3.12/3.13), minimum-permission GitHub token, SHA-pinned third-party actions and a conditional post-CI GitHub Release workflow. Only synthetic fixtures are included. Never upload confidential switch inventories to public issues.

This tool does **not** connect to network equipment, collect packets, remediate, verify LLDP authenticity, inspect L3 routing or model all STP/LACP/MLAG vendor behaviors. Incomplete observations can hide risk. Read [the schema](docs/SCHEMA.md), [architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md) before making decisions.
