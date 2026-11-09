import copy
import json
import tempfile
import unittest
from pathlib import Path
from l2_changeguard.model import InputError, load_json, parse_snapshot, parse_policy

BASE = Path(__file__).resolve().parents[1] / 'examples'


class ModelTest(unittest.TestCase):
    def setUp(self):
        self.sample = load_json(BASE / 'baseline.json')
        self.policy = load_json(BASE / 'policy.json')

    def mutate(self, fn):
        o = copy.deepcopy(self.sample)
        fn(o)
        return o

    def assertBad(self, value):
        with self.assertRaises(InputError):
            parse_snapshot(value)

    def test_known_good_snapshot(self):
        s = parse_snapshot(self.sample)
        self.assertEqual(len(s.devices),3)
        self.assertEqual(len(s.ports()),7)
        self.assertEqual(s.port(s.ports()[0].peer).device, 'sw-dist1')

    def test_good_policy(self):
        p = parse_policy(self.policy)
        self.assertEqual(p.protected_vlans,{10,20})

    def test_empty_policy_defaults(self):
        p = parse_policy({})
        self.assertFalse(p.require_access_bpdu_guard)

    def test_reject_snapshot_invalid(self):
        samples = [None,[],{}, {'schema_version':2,'devices':[]},
                   {'schema_version':True,'devices':[]},
                   {'schema_version':1,'devices':[]},
                   {'schema_version':1,'devices':'test'},
                   {'schema_version':1,'devices':[], 'surprise':'x'}]
        for s in samples:
            with self.subTest(s=s): self.assertBad(s)

    def test_reject_duplicate_device(self):
        self.assertBad(self.mutate(lambda x: x['devices'].append(copy.deepcopy(x['devices'][0]))))

    def test_reject_duplicate_port(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'].append(copy.deepcopy(x['devices'][0]['ports'][0]))))

    def test_reject_invalid_name(self):
        for n in ['', 'x'*81, '\nname', 9, None]:
            with self.subTest(n=n):
                self.assertBad(self.mutate(lambda x: x['devices'][0].update(id=n)))

    def test_reject_mode(self):
        for mode in ['route','TRUNK',None,1,{},[]]:
            with self.subTest(mode=mode):
                self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(mode=mode)))

    def test_reject_vlan(self):
        for v in [-1,0,4095,True,1.0,None,'10']:
            with self.subTest(v=v):
                self.assertBad(self.mutate(lambda x: x['devices'][1]['ports'][2].update(access_vlan=v)))

    def test_reject_mixed_mode(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(access_vlan=10)))
        self.assertBad(self.mutate(lambda x: x['devices'][1]['ports'][2].update(native_vlan=99)))

    def test_reject_duplicate_vlan(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(allowed_vlans=[10,10,20])))

    def test_reject_invalid_list(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(allowed_vlans='10')))
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(allowed_vlans=[True])))

    def test_reject_invalid_flags(self):
        for key in ['admin_up','bpdu_guard','port_security']:
            for v in [0,1,'true',None,[],{}]:
                with self.subTest(k=key,v=v):
                    self.assertBad(self.mutate(lambda x: x['devices'][1]['ports'][2].update({key:v})))

    def test_reject_stp_state(self):
        for v in ['down','forward',None,1]:
            with self.subTest(v=v):
                self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(stp={'10':v})))

    def test_reject_stp_key(self):
        for v in ['010','0','4095','abc','99999','2.0']:
            with self.subTest(v=v):
                self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(stp={v:'forwarding'})))

    def test_reject_stp_on_disallowed_vlan(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(stp={'42':'forwarding'})))

    def test_reject_bad_lldp(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(lldp={'device':'sw-dist1'})))
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(lldp={'device':'sw-core','port':'ge-0/0/1'})))

    def test_reject_bad_mac(self):
        for mac in ['00:00', 'GG:00:00:00:00:00', None, 3]:
            with self.subTest(mac=mac):
                self.assertBad(self.mutate(lambda x: x['devices'][1]['ports'][2].update(macs=[{'address':mac,'vlan':10}])))

    def test_reject_mac_outside_vlan(self):
        self.assertBad(self.mutate(lambda x: x['devices'][1]['ports'][2].update(macs=[{'address':'02:00:00:00:00:01','vlan':20}])))

    def test_reject_duplicate_mac(self):
        self.assertBad(self.mutate(lambda x: x['devices'][1]['ports'][2].update(macs=[{'address':'02:00:00:00:00:01','vlan':10}]*2)))

    def test_reject_unknown_port_property(self):
        self.assertBad(self.mutate(lambda x: x['devices'][0]['ports'][0].update(password='secret')))

    def test_reject_policy_unknown(self):
        with self.assertRaises(InputError):parse_policy({'not_known':True})

    def test_reject_policy_critical_devices_duplicate(self):
        with self.assertRaises(InputError):parse_policy({'critical_devices':['A','A']})

    def test_reject_policy_boolean(self):
        with self.assertRaises(InputError):parse_policy({'require_access_bpdu_guard':1})

    def test_casefold_mac_only(self):
        obj=self.mutate(lambda x: x['devices'][1]['ports'][2].update(macs=[{'address':'AA:BB:CC:DD:EE:FF','vlan':10}]))
        self.assertEqual(parse_snapshot(obj).devices['sw-dist1']['ge-0/0/3'].macs[0][0], 'aa:bb:cc:dd:ee:ff')

    def test_file_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.json';p.write_bytes(b'\xff')
            with self.assertRaises(InputError):load_json(p)

    def test_file_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.json';p.write_text('{')
            with self.assertRaises(InputError):load_json(p)

    def test_file_too_large(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.json';p.write_bytes(b'x'*2_000_001)
            with self.assertRaises(InputError):load_json(p)

    def test_empty_ports_allowed(self):
        obj = self.mutate(lambda x: x['devices'][0].update(ports=[]))
        self.assertEqual(len(parse_snapshot(obj).devices['sw-core']),0)

    def test_deterministic_device_iteration(self):
        obj=copy.deepcopy(self.sample); obj['devices'].reverse()
        self.assertEqual([p.key for p in parse_snapshot(obj).ports()], [p.key for p in parse_snapshot(self.sample).ports()])

    def test_out_of_scope_ip_field_rejected(self):
        self.assertBad(self.mutate(lambda x:x['devices'][0].update(management_ip='10.0.0.1')))


if __name__ == '__main__': unittest.main()
