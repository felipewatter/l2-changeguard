"""Offline command-line entry point; no code paths open sockets or mutate devices."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from . import __version__
from .analyzer import LEVELS, audit, compare, sarif, should_block
from .model import InputError, load_json, parse_policy, parse_snapshot


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='l2changeguard', description='Offline change gate for Layer 2 switch snapshots')
    parser.add_argument('--version', action='version', version=f'l2changeguard {__version__}')
    parser.add_argument('command', choices=['audit', 'compare'])
    parser.add_argument('--candidate', required=True, help='JSON candidate snapshot')
    parser.add_argument('--baseline', help='JSON baseline snapshot (mandatory for compare)')
    parser.add_argument('--policy', required=True, help='JSON site policy')
    parser.add_argument('--fail-on', choices=list(LEVELS), default='high')
    parser.add_argument('--output', help='Write machine report to this path; stdout if not provided')
    parser.add_argument('--sarif', help='Write SARIF 2.1.0 to this path')
    args = parser.parse_args(argv)
    if args.command == 'compare' and not args.baseline:
        parser.error('--baseline is required for compare')
    if args.command == 'audit' and args.baseline:
        parser.error('--baseline is only accepted for compare')
    try:
        policy = parse_policy(load_json(args.policy))
        candidate = parse_snapshot(load_json(args.candidate))
        after = audit(candidate, policy)
        if args.command == 'compare':
            baseline = parse_snapshot(load_json(args.baseline))
            change = compare(audit(baseline, policy), after)
            gate_items = change['introduced']
            payload = {'schema_version':1, 'mode':'compare', 'gate':'new-findings-only', 'threshold':args.fail_on, **change}
        else:
            gate_items = [f.json() for f in after]
            payload = {'schema_version':1, 'mode':'audit', 'gate':'all-findings', 'threshold':args.fail_on, 'findings':gate_items}
        blocked = should_block(gate_items, args.fail_on)
        payload['verdict'] = 'blocked' if blocked else 'pass'
        body = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
        # SARIF and JSON file writes do not access external services.
        if args.output:
            Path(args.output).write_text(body, encoding='utf-8')
        else:
            print(body, end='')
        if args.sarif:
            Path(args.sarif).write_text(json.dumps(sarif(gate_items, Path(args.candidate).name), indent=2, sort_keys=True)+'\n', encoding='utf-8')
        return 2 if blocked else 0
    except (InputError, OSError) as exc:
        print(f'input error: {exc}', file=sys.stderr)
        return 3


def main() -> None:
    sys.exit(run())


if __name__ == '__main__':
    main()
