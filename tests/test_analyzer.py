import copy
import unittest
from pathlib import Path
from l2_changeguard.model import load_json, parse_snapshot, parse_policy
from l2_changeguard.analyzer import audit, compare, should_block, sarif, LEVELS

BASE = Path(__file__).resolve().parents[1] / 'examples'


class AnalyzerTest(unittest.TestCase):
    def setUp(self):
        self.sample=load_json(BASE/'baseline.json')
        self.risky=load_json(BASE/'candidate-risky.json')
        self.policy=parse_policy(load_json(BASE/'policy.json'))

    def scan(self,obj,policy=None):
        return audit(parse_snapshot(obj),policy or self.policy)

    def issues(self,obj,code):
        return [f for f in self.scan(obj) if f.rule_id==code]

    def test_clean_baseline(self):
        self.assertEqual(self.scan(self.sample),[])

    def test_risky_snapshot(self):
        ids={x.rule_id for x in self.scan(self.risky)}
        self.assertTrue({'L2C002','L2C003','L2C004','L2C005'} <= ids)

    def test_link_mode_mismatch(self):
        x=copy.deepcopy(self.sample)
        p=x['devices'][0]['ports'][0]
        p.update(mode='access', access_vlan=10)
        for key in ['native_vlan','allowed_vlans']:p.pop(key)
        p['stp']={'10':'forwarding'}
        self.assertEqual(len(self.issues(x,'L2C002')),1)

    def test_native_mismatch(self):
        x=copy.deepcopy(self.sample); x['devices'][0]['ports'][0]['native_vlan']=100
        self.assertIn('native',self.issues(x,'L2C002')[0].subject)

    def test_allowed_vlan_mismatch(self):
        x=copy.deepcopy(self.sample)
        x['devices'][0]['ports'][0]['allowed_vlans']=[10,999]
        x['devices'][0]['ports'][0]['stp']={'10':'forwarding'}
        self.assertEqual(len(self.issues(x,'L2C002')),1)

    def test_peer_missing(self):
        x=copy.deepcopy(self.sample);x['devices'][0]['ports'][0]['lldp']['device']='not-found'
        self.assertEqual(len(self.issues(x,'L2C001')),2)

    def test_peer_missing_link_state(self):
        x=copy.deepcopy(self.sample);x['devices'][0]['ports'][0]['admin_up']=False
        self.assertEqual(len(self.issues(x,'L2C001')),1)

    def test_peer_unknown_port(self):
        x=copy.deepcopy(self.sample);x['devices'][0]['ports'][0]['lldp']['port']='missing'
        self.assertEqual(len(self.issues(x,'L2C001')),2)

    def test_cycle_requires_three_distinct_devices(self):
        self.assertFalse(self.issues(self.sample,'L2C003'))
        self.assertTrue(self.issues(self.risky,'L2C003'))

    def test_cycle_fully_blocked_if_one_end_blocking(self):
        self.assertFalse(self.issues(self.sample,'L2C003'))

    def test_cycle_unknown_stp_is_not_claimed(self):
        x=copy.deepcopy(self.risky)
        x['devices'][2]['ports'][1]['stp'].pop('10')
        self.assertFalse(self.issues(x,'L2C003'))

    def test_cycle_both_vlans_when_forward(self):
        self.assertEqual(len(self.issues(self.risky,'L2C003')),1)  # 20 is pruned at one end

    def test_mac_flap_scoped_to_same_switch_vlan(self):
        self.assertEqual(len(self.issues(self.risky,'L2C004')),1)

    def test_mac_duplicate_across_switches_not_flagged(self):
        x=copy.deepcopy(self.sample)
        x['devices'][0]['ports'][0]['macs']=[{'address':'02:00:00:00:00:01','vlan':10}]
        self.assertEqual(self.issues(x,'L2C004'),[])

    def test_mac_not_flagged_on_admin_down(self):
        x=copy.deepcopy(self.risky); x['devices'][1]['ports'][3]['admin_up']=False
        self.assertFalse(self.issues(x,'L2C004'))

    def test_missing_bpdu_guard(self):
        self.assertEqual(len(self.issues(self.risky,'L2C005')),1)

    def test_missing_port_security(self):
        x=copy.deepcopy(self.sample);x['devices'][1]['ports'][2]['port_security']=False
        self.assertEqual(len(self.issues(x,'L2C005')),1)

    def test_access_requirements_optional(self):
        p=parse_policy({})
        self.assertFalse(any(x.rule_id=='L2C005' for x in self.scan(self.risky,p)))

    def test_unapproved_native(self):
        x=copy.deepcopy(self.sample);x['devices'][0]['ports'][0]['native_vlan']=100
        self.assertEqual(len(self.issues(x,'L2C006')),1)

    def test_native_policy_empty_means_no_check(self):
        self.assertFalse(any(x.rule_id=='L2C006' for x in self.scan(self.risky,parse_policy({}))))

    def test_critical_switch_single_neighbor(self):
        x=copy.deepcopy(self.sample)
        x['devices'][0]['ports'][1]['lldp']=None
        x['devices'][2]['ports'][0]['lldp']=None
        self.assertEqual(len(self.issues(x,'L2C007')),1)

    def test_no_critical_devices_default(self):
        self.assertFalse(any(x.rule_id=='L2C007' for x in self.scan(self.sample,parse_policy({}))))

    def test_protected_vlan_disabled_stp(self):
        x=copy.deepcopy(self.sample)
        x['devices'][0]['ports'][0]['stp']['10']='disabled'
        self.assertEqual(len(self.issues(x,'L2C008')),1)

    def test_disabled_unprotected_vlan_not_flagged(self):
        x=copy.deepcopy(self.sample)
        x['devices'][0]['ports'][0]['stp']['10']='disabled'
        self.assertFalse(any(f.rule_id=='L2C008' for f in self.scan(x,parse_policy({'protected_vlans':[20]}))))

    def test_admin_down_suppresses_local_findings(self):
        x=copy.deepcopy(self.risky); x['devices'][1]['ports'][2]['admin_up']=False
        self.assertFalse(self.issues(x,'L2C005'))

    def test_findings_have_stable_fingerprints(self):
        r=self.scan(self.risky)
        self.assertTrue(all(len(f.fingerprint)==20 for f in r))
        self.assertEqual(r,self.scan(copy.deepcopy(self.risky)))

    def test_compare_new_and_resolved(self):
        result=compare(self.scan(self.sample),self.scan(self.risky))
        self.assertGreater(len(result['introduced']),0)
        self.assertEqual(result['resolved'],[])
        reversed_result=compare(self.scan(self.risky),self.scan(self.sample))
        self.assertEqual(len(reversed_result['resolved']),len(result['introduced']))

    def test_compare_same_is_no_new(self):
        self.assertEqual(compare(self.scan(self.risky),self.scan(self.risky))['introduced'],[])

    def test_compare_only_new_gate(self):
        before=self.scan(self.risky)
        self.assertFalse(should_block(compare(before,before)['introduced'],'critical'))
        self.assertTrue(should_block(compare(self.scan(self.sample),before)['introduced'],'critical'))

    def test_thresholds(self):
        xs=[{'severity':'medium'}]
        for k in ['critical','high','none']:
            self.assertFalse(should_block(xs,k))
        for k in ['medium','low']:
            self.assertTrue(should_block(xs,k))

    def test_sarif(self):
        findings=[f.json() for f in self.scan(self.risky)]
        result=sarif(findings,'candidate-risky.json')
        self.assertEqual(result['version'],'2.1.0')
        self.assertEqual(len(result['runs'][0]['results']),len(findings))
        self.assertEqual(result['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'],'candidate-risky.json')
        self.assertEqual(len(result['runs'][0]['tool']['driver']['rules']),8)

    def test_metamorphic_input_order_invariant(self):
        a=self.scan(self.risky)
        x=copy.deepcopy(self.risky)
        x['devices'].reverse()
        for d in x['devices']:
            d['ports'].reverse()
        self.assertEqual(a,self.scan(x))

    def test_finding_json_format(self):
        for finding in self.scan(self.risky):
            self.assertEqual(set(finding.json()),{'rule_id','title','severity','subject','evidence','remediation','fingerprint'})


if __name__=='__main__':unittest.main()
