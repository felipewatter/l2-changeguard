"""Deterministic offline L2 checks with explicit evidence limitations."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from .model import Policy, Port, Snapshot

LEVELS = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
RULES = {
    'L2C001': ('LLDP peer not reciprocal', 'medium'),
    'L2C002': ('VLAN / port mode disagreement', 'high'),
    'L2C003': ('Possible STP forwarding cycle', 'critical'),
    'L2C004': ('MAC learned on multiple switchports', 'high'),
    'L2C005': ('Access-edge protection missing', 'medium'),
    'L2C006': ('Native VLAN outside approved set', 'medium'),
    'L2C007': ('Critical switch has fewer than two distinct neighbors', 'medium'),
    'L2C008': ('Protected VLAN with STP explicitly disabled', 'high'),
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    subject: str
    evidence: str
    remediation: str

    @property
    def fingerprint(self) -> str:
        # Deliberately stable when evidence text changes, to track issue identity.
        basis = json.dumps([self.rule_id, self.subject], ensure_ascii=True)
        return hashlib.sha256(basis.encode()).hexdigest()[:20]

    def json(self) -> dict:
        return dict(rule_id=self.rule_id, title=RULES[self.rule_id][0], severity=self.severity,
                    subject=self.subject, evidence=self.evidence, remediation=self.remediation,
                    fingerprint=self.fingerprint)


def audit(snapshot: Snapshot, policy: Policy) -> list[Finding]:
    issues: list[Finding] = []

    def add(code: str, subject: str, evidence: str, remediation: str) -> None:
        issues.append(Finding(code, RULES[code][1], subject, evidence, remediation))

    # Both sides must explicitly agree. Otherwise links are untrusted observations.
    links: list[tuple[Port, Port]] = []
    neighbor_sets: dict[str, set[str]] = {d: set() for d in snapshot.devices}
    for p in snapshot.ports():
        if not p.admin_up:
            continue
        if p.mode == 'access':
            if policy.require_access_bpdu_guard and not p.bpdu_guard:
                add('L2C005', p.key+':bpdu_guard', 'Operational access port lacks BPDU guard.', 'Enable BPDU guard on user-facing ports after validating endpoint role.')
            if policy.require_access_port_security and not p.port_security:
                add('L2C005', p.key+':port_security', 'Operational access port lacks configured port security.', 'Apply a site-specific edge port-security policy.')
        elif policy.allowed_native_vlans and p.native_vlan not in policy.allowed_native_vlans:
            add('L2C006', p.key, f'Native VLAN {p.native_vlan} is not approved.', 'Use an approved native VLAN consistently on both ends.')
        for v in sorted(policy.protected_vlans & p.vlans):
            if p.stp.get(v) == 'disabled':
                add('L2C008', f'{p.key}:vlan-{v}', 'Protected VLAN has explicitly disabled STP on this port.', 'Review STP configuration and L2 design; enable loop prevention where applicable.')
        if p.peer is None:
            continue
        other = snapshot.port(p.peer)
        if other is None or not other.admin_up or other.peer != type(p.peer)(p.device, p.id):
            add('L2C001', p.key, f'LLDP claims {p.peer.device}/{p.peer.port} without an active reciprocal observation.', 'Verify inventory, LLDP freshness and cable/neighbor mapping.')
            continue
        if p.key >= other.key:
            continue
        links.append((p, other))
        neighbor_sets[p.device].add(other.device)
        neighbor_sets[other.device].add(p.device)
        if p.mode != other.mode:
            add('L2C002', f'{p.key}<->{other.key}', f'Port modes disagree: {p.mode} versus {other.mode}.', 'Align port modes with the intended topology.')
        elif p.mode == 'access':
            if p.access_vlan != other.access_vlan:
                add('L2C002', f'{p.key}<->{other.key}', f'Access VLANs disagree: {p.access_vlan} versus {other.access_vlan}.', 'Align VLANs; confirm that an access-to-access link is intentional.')
        else:
            if p.native_vlan != other.native_vlan:
                add('L2C002', f'{p.key}<->{other.key}:native', f'Native VLANs disagree: {p.native_vlan} versus {other.native_vlan}.', 'Align native VLANs at both ends.')
            if p.vlans != other.vlans:
                add('L2C002', f'{p.key}<->{other.key}:allowed', f'Allowed VLAN symmetric difference: {sorted(p.vlans ^ other.vlans)}.', 'Review and reconcile VLAN allowlists for the link.')

    for device in sorted(policy.critical_devices):
        if device in snapshot.devices and len(neighbor_sets[device]) < 2:
            add('L2C007', device, f'Only {len(neighbor_sets[device])} distinct reciprocal, active LLDP neighbors found.', 'Validate failure-domain diversity and actual uplink resiliency; LLDP inventory may be incomplete.')

    # Learnings are scoped to (switch, VLAN, MAC). Observations across switches are normal.
    seen: dict[tuple[str, int, str], set[str]] = {}
    for p in snapshot.ports():
        if not p.admin_up:
            continue
        for mac, v in p.macs:
            seen.setdefault((p.device, v, mac), set()).add(p.id)
    for (device, v, mac), ports in sorted(seen.items()):
        if len(ports) > 1:
            add('L2C004', f'{device}/vlan-{v}/{mac}', f'MAC observed on ports {sorted(ports)} in the same snapshot.', 'Check MAC move events, loop symptoms, virtualization and sampling freshness.')

    # STP must be explicitly known as forwarding on BOTH endpoints for a given VLAN.
    # Union-find finds a candidate cycle only among fully observed L2 links.
    for v in sorted({k for a,b in links for k in a.vlans & b.vlans}):
        parent: dict[str, str] = {}
        edges: list[tuple[str, str]] = []

        def root(n: str) -> str:
            parent.setdefault(n, n)
            while parent[n] != n:
                parent[n] = parent[parent[n]]
                n = parent[n]
            return n

        for a, b in links:
            if not (a.carries(v) and b.carries(v) and a.stp.get(v) == b.stp.get(v) == 'forwarding'):
                continue
            # Skip explicit access links to avoid claiming that a simple host-facing access link is transit.
            if a.mode != 'trunk' or b.mode != 'trunk':
                continue
            ra, rb = root(a.device), root(b.device)
            if ra == rb:
                # Parallel links between the same two switches may be valid LAGs; do not claim a cycle.
                if len({x for pair in edges for x in pair} | {a.device,b.device}) >= 3:
                    add('L2C003', f'vlan-{v}:{min(a.device,b.device)}<->{max(a.device,b.device)}',
                        f'Reciprocal LLDP topology with STP forwarding on both ends closes a cycle via {a.key}<->{b.key}.',
                        'Verify actual bridge topology, STP state, LAGs and storm controls before rollout.')
            else:
                parent[ra] = rb
            edges.append((a.device,b.device))

    return sorted(issues, key=lambda x: (-LEVELS[x.severity], x.rule_id, x.subject))


def compare(before: list[Finding], after: list[Finding]) -> dict:
    old = {f.fingerprint: f for f in before}
    new = {f.fingerprint: f for f in after}
    sort = lambda xs: sorted(xs, key=lambda f: (-LEVELS[f.severity], f.rule_id, f.subject))
    return {
        'introduced': [f.json() for f in sort([f for k,f in new.items() if k not in old])],
        'resolved': [f.json() for f in sort([f for k,f in old.items() if k not in new])],
        'persisting': [f.json() for f in sort([f for k,f in new.items() if k in old])],
    }


def should_block(findings: list[dict], fail_on: str) -> bool:
    return any(LEVELS[f['severity']] >= LEVELS[fail_on] for f in findings) if fail_on != 'none' else False


def sarif(findings: list[dict], input_name: str) -> dict:
    # Filename is a basename only; never include local directory structure.
    rules = [dict(id=code, shortDescription={'text': title}, properties={'security-severity':str({'critical':9.5,'high':8.0,'medium':5.0,'low':2.0}[sev])}) for code,(title,sev) in RULES.items()]
    level = {'critical':'error','high':'error','medium':'warning','low':'note'}
    return {'version':'2.1.0', '$schema':'https://json.schemastore.org/sarif-2.1.0.json', 'runs':[{'tool':{'driver':{'name':'L2 ChangeGuard','version':'0.1.0','rules':rules}},'results':[
        {'ruleId':x['rule_id'],'level':level[x['severity']], 'message':{'text':f"{x['subject']}: {x['evidence']}"},
         'locations':[{'physicalLocation':{'artifactLocation':{'uri': input_name}}}],
         'partialFingerprints':{'primaryLocationLineHash':x['fingerprint']}} for x in findings]}]}
