# Security policy

Supported releases: latest minor series (currently `0.1.x`).

Please do not submit real switch configs, serial numbers, MAC inventories, credentials, management IPs or private topology to public issues. Use sanitized synthetic fixtures.

Report security issues privately using the GitHub repository's **Security → Report a vulnerability** feature, if enabled, or contact the maintainer through a private channel. Include affected version, bounded reproduction, impact and a synthetic testcase. Do not publish an exploit before coordinating disclosure.

## Security properties

* No device login, no SNMP, no subprocesses, no socket use, and no automatic remediation.
* Reads only explicit local JSON file paths; JSON size capped at 2 MB per input. Device/port/MAC counts are bounded.
* Unrecognized fields, invalid VLANs, invalid MACs and contradictory per-port modes are rejected.
* Only standard-library runtime dependencies. Reports may contain sensitive topology; store accordingly.
* Findings are **not** proof of actual loops, unauthorized hosts or end-to-end forwarding; see docs/THREAT_MODEL.md.

## Reporting and dependencies

Source is MIT-licensed, but third-party GitHub Actions are pinned to commit SHA. CI uses a read-only GitHub token and does not run network discovery against production.
