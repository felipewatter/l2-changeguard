"""Strict, bounded JSON input model. No device connections or remote execution."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000
MAX_DEVICES = 256
MAX_PORTS = 4096
MAX_MACS = 16384
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
STATES = {"forwarding", "blocking", "disabled"}


class InputError(ValueError):
    """Malformed or out-of-scope snapshot, never silently repaired."""


def mapping(value: Any, context: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{context}: expected object")
    unknown = set(value) - allowed
    if unknown:
        raise InputError(f"{context}: unknown keys {sorted(unknown)}")
    return value


def bounded_str(value: Any, context: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 80 or any(ord(c) < 32 for c in value):
        raise InputError(f"{context}: expected printable string of 1..80 characters")
    return value


def flag(value: Any, context: str) -> bool:
    if type(value) is not bool:
        raise InputError(f"{context}: expected boolean")
    return value


def vlan(value: Any, context: str) -> int:
    if type(value) is not int or not 1 <= value <= 4094:
        raise InputError(f"{context}: VLAN must be integer 1..4094")
    return value


def vlan_set(value: Any, context: str) -> frozenset[int]:
    if not isinstance(value, list) or len(value) > 4094:
        raise InputError(f"{context}: expected VLAN list <=4094")
    result = [vlan(x, context) for x in value]
    if len(set(result)) != len(result):
        raise InputError(f"{context}: duplicate VLAN")
    return frozenset(result)


@dataclass(frozen=True)
class Peer:
    device: str
    port: str


@dataclass(frozen=True)
class Port:
    device: str
    id: str
    mode: str
    vlans: frozenset[int]
    native_vlan: int | None
    access_vlan: int | None
    admin_up: bool
    bpdu_guard: bool
    port_security: bool
    stp: dict[int, str]
    peer: Peer | None
    macs: tuple[tuple[str, int], ...]

    @property
    def key(self) -> str:
        return f"{self.device}/{self.id}"

    def carries(self, v: int) -> bool:
        return v in self.vlans and self.admin_up


@dataclass(frozen=True)
class Snapshot:
    devices: dict[str, dict[str, Port]]

    def ports(self) -> list[Port]:
        return [p for name in sorted(self.devices) for p in sorted(self.devices[name].values(), key=lambda x: x.id)]

    def port(self, peer: Peer) -> Port | None:
        return self.devices.get(peer.device, {}).get(peer.port)


@dataclass(frozen=True)
class Policy:
    protected_vlans: frozenset[int]
    allowed_native_vlans: frozenset[int]
    critical_devices: frozenset[str]
    require_access_bpdu_guard: bool
    require_access_port_security: bool


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise InputError(f'duplicate JSON property {key!r}')
        obj[key] = value
    return obj


def load_json(path: str | Path) -> Any:
    file = Path(path)
    try:
        if file.stat().st_size > MAX_BYTES:
            raise InputError(f"{file.name}: file exceeds {MAX_BYTES} bytes")
        raw = file.read_bytes()
        if len(raw) > MAX_BYTES:
            raise InputError(f"{file.name}: file exceeds {MAX_BYTES} bytes")
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_json_keys)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError(f"{file.name}: unable to parse JSON: {exc}") from exc


def parse_snapshot(value: Any) -> Snapshot:
    obj = mapping(value, 'snapshot', {'schema_version', 'devices'})
    if type(obj.get('schema_version')) is not int or obj['schema_version'] != 1:
        raise InputError('snapshot: unsupported schema_version (expected 1)')
    raw_devices = obj.get('devices')
    if not isinstance(raw_devices, list) or not 1 <= len(raw_devices) <= MAX_DEVICES:
        raise InputError(f'snapshot: devices must contain 1..{MAX_DEVICES} entries')
    devices: dict[str, dict[str, Port]] = {}
    total_ports, total_macs = 0, 0
    for d in raw_devices:
        d = mapping(d, 'device', {'id', 'ports'})
        device_id = bounded_str(d.get('id'), 'device.id')
        if device_id in devices:
            raise InputError(f'duplicate device {device_id}')
        raw_ports = d.get('ports')
        if not isinstance(raw_ports, list):
            raise InputError(f'{device_id}: ports must be a list')
        total_ports += len(raw_ports)
        if total_ports > MAX_PORTS:
            raise InputError(f'snapshot: exceeds {MAX_PORTS} ports')
        ports: dict[str, Port] = {}
        for raw in raw_ports:
            p = mapping(raw, f'{device_id}.port', {'id','mode','access_vlan','native_vlan','allowed_vlans','admin_up','bpdu_guard','port_security','stp','lldp','macs'})
            name = bounded_str(p.get('id'), f'{device_id}.port.id')
            if name in ports:
                raise InputError(f'{device_id}: duplicate port {name}')
            mode = p.get('mode')
            if mode not in ('access','trunk'):
                raise InputError(f'{device_id}/{name}: mode must be access or trunk')
            access = native = None
            if mode == 'access':
                if 'native_vlan' in p or 'allowed_vlans' in p:
                    raise InputError(f'{device_id}/{name}: trunk fields on access port')
                access = vlan(p.get('access_vlan'), f'{device_id}/{name}.access_vlan')
                effective = frozenset({access})
            else:
                if 'access_vlan' in p:
                    raise InputError(f'{device_id}/{name}: access_vlan on trunk port')
                native = vlan(p.get('native_vlan'), f'{device_id}/{name}.native_vlan')
                effective = vlan_set(p.get('allowed_vlans'), f'{device_id}/{name}.allowed_vlans')
            up = flag(p.get('admin_up', True), f'{device_id}/{name}.admin_up')
            bpdu = flag(p.get('bpdu_guard', False), f'{device_id}/{name}.bpdu_guard')
            security = flag(p.get('port_security', False), f'{device_id}/{name}.port_security')
            raw_stp = p.get('stp', {})
            if not isinstance(raw_stp, dict) or len(raw_stp) > 4094:
                raise InputError(f'{device_id}/{name}.stp: expected VLAN/state map')
            stp: dict[int, str] = {}
            for k, state in raw_stp.items():
                if not isinstance(k, str) or not k.isascii() or not k.isdecimal() or len(k) > 4 or str(int(k)) != k:
                    raise InputError(f'{device_id}/{name}.stp: keys must be canonical decimal VLAN strings')
                v = vlan(int(k), f'{device_id}/{name}.stp')
                if v not in effective or not isinstance(state, str) or state not in STATES:
                    raise InputError(f'{device_id}/{name}.stp: unsupported VLAN/state {k}:{state}')
                stp[v] = state
            raw_peer = p.get('lldp')
            peer = None
            if raw_peer is not None:
                raw_peer = mapping(raw_peer, f'{device_id}/{name}.lldp', {'device','port'})
                peer = Peer(bounded_str(raw_peer.get('device'), 'lldp.device'), bounded_str(raw_peer.get('port'), 'lldp.port'))
                if peer == Peer(device_id, name):
                    raise InputError(f'{device_id}/{name}: self-referential LLDP port')
            raw_macs = p.get('macs', [])
            if not isinstance(raw_macs, list):
                raise InputError(f'{device_id}/{name}.macs: expected list')
            total_macs += len(raw_macs)
            if total_macs > MAX_MACS:
                raise InputError(f'snapshot: exceeds {MAX_MACS} MAC observations')
            macs = []
            for m in raw_macs:
                m = mapping(m, f'{device_id}/{name}.mac', {'address','vlan'})
                mac = m.get('address')
                mv = vlan(m.get('vlan'), f'{device_id}/{name}.mac.vlan')
                if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):
                    raise InputError(f'{device_id}/{name}: invalid MAC address')
                if mv not in effective:
                    raise InputError(f'{device_id}/{name}: MAC VLAN {mv} not carried by port')
                macs.append((mac.lower(), mv))
            if len(set(macs)) != len(macs):
                raise InputError(f'{device_id}/{name}: duplicate MAC observation')
            ports[name] = Port(device_id, name, mode, effective, native, access, up, bpdu, security, stp, peer, tuple(sorted(macs)))
        devices[device_id] = ports
    return Snapshot(devices)


def parse_policy(value: Any) -> Policy:
    o = mapping(value, 'policy', {'protected_vlans','allowed_native_vlans','critical_devices','require_access_bpdu_guard','require_access_port_security'})
    d = o.get('critical_devices', [])
    if not isinstance(d, list) or len(d) > MAX_DEVICES:
        raise InputError('policy.critical_devices: expected list')
    ids = [bounded_str(x, 'critical_devices') for x in d]
    if len(set(ids)) != len(ids):
        raise InputError('policy.critical_devices: duplicate device')
    return Policy(vlan_set(o.get('protected_vlans', []), 'protected_vlans'), vlan_set(o.get('allowed_native_vlans', []), 'allowed_native_vlans'), frozenset(ids), flag(o.get('require_access_bpdu_guard', False), 'require_access_bpdu_guard'), flag(o.get('require_access_port_security', False), 'require_access_port_security'))
