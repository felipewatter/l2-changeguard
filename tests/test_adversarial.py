"""Adversarial/negative tests on malformed local content; no actual network access."""
import copy
import json
import random
import tempfile
import unittest
from pathlib import Path

from l2_changeguard.model import InputError, load_json, parse_policy, parse_snapshot

SAMPLE = Path(__file__).resolve().parents[1] / 'examples' / 'baseline.json'


class AdversarialTests(unittest.TestCase):
    def setUp(self):
        self.base=load_json(SAMPLE)

    def test_duplicate_json_properties_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'dupe.json'
            p.write_text('{"schema_version":1,"schema_version":2,"devices":[]}',encoding='utf-8')
            with self.assertRaises(InputError):load_json(p)

    def test_nested_duplicate_json_properties_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'dupe.json'
            p.write_text('{"schema_version":1,"devices":[{"id":"a","id":"b","ports":[]}]}' ,encoding='utf-8')
            with self.assertRaises(InputError):load_json(p)

    def test_unhashable_stp_state_rejected_without_crash(self):
        for state in [{},[],[1,2],{"x":1},False]:
            with self.subTest(state=state):
                x=copy.deepcopy(self.base)
                x['devices'][0]['ports'][0]['stp']={'10':state}
                with self.assertRaises(InputError):parse_snapshot(x)

    def test_very_long_stp_key_rejected_without_int_conversion(self):
        x=copy.deepcopy(self.base)
        x['devices'][0]['ports'][0]['stp']={'9'*10000:'forwarding'}
        with self.assertRaises(InputError):parse_snapshot(x)

    def test_oversized_cardinality_rejected(self):
        x=copy.deepcopy(self.base)
        x['devices']=[{'id':f'd-{i}','ports':[]} for i in range(257)]
        with self.assertRaises(InputError):parse_snapshot(x)

    def test_control_chars_rejected(self):
        x=copy.deepcopy(self.base)
        x['devices'][0]['ports'][0]['id']='foo\x00bar'
        with self.assertRaises(InputError):parse_snapshot(x)

    def test_policy_critical_devices_unhashable_rejected(self):
        for d in [{},[],10,None,True]:
            with self.subTest(d=d):
                with self.assertRaises(InputError):parse_policy({'critical_devices':[d]})

    def test_many_mutations_never_crash(self):
        rand=random.Random(3517)
        raw=[None,0,1,True,False,[],{},'bad',-1,4095,'10',{'x':[]},[{}]]
        keys=['mode','id','native_vlan','access_vlan','allowed_vlans','stp','lldp','admin_up','macs','bpdu_guard','port_security']
        accepted=0
        for i in range(1200):
            x=copy.deepcopy(self.base)
            p=x['devices'][rand.randrange(3)]['ports'][0]
            p[rand.choice(keys)]=copy.deepcopy(rand.choice(raw))
            try:
                parse_snapshot(x)
            except InputError:
                accepted+=1
        self.assertGreater(accepted,1000)


if __name__ == '__main__':
    unittest.main()
