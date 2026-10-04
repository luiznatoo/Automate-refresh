import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path('outputs/fortigate-hardening').resolve()))
import hardening as h
class LegacyTests(unittest.TestCase):
 def snapshot(self,model='50E',version='6.2.16'):
  return {'Sistema':{'value':{'Version':f'FortiGate-{model} v{version},build1392','Serial-Number':'TEST','Hostname':'TEST','Current HA mode':'standalone','Virtual domain configuration':'disable'}},'Global':{'value':{'cfg-save':'automatic','admin-maintainer':'enable','security-rating-result-submission':'disable'}},'Interfaces':{'value':[{'id':n} for n in ('wan1','wan2','lan1','lan2','lan3','lan4','lan5')]}}
 def test_supported_pair(self):
  self.assertEqual(h.safety(self.snapshot()),'')
  for model,version in [('50E','7.4.9'),('50E','6.2.15'),('60F','6.2.16')]:self.assertTrue(h.safety(self.snapshot(model,version)))
 def test_legacy_ha_mode(self):
  s=self.snapshot();s['Sistema']['value']['Current HA mode']='a-p, master'
  s['HA']={'value':{'HA Health Status':'OK','member/TEST':'master','member/PEER':'slave','sync/TEST':'in-sync','sync/PEER':'in-sync'}}
  self.assertEqual(h.safety(s),'')
  s['HA']['value']['sync/PEER']='out-of-sync';self.assertTrue(h.safety(s))
 def test_mapping(self):
  p=h.effective_policy(self.snapshot(),h.DEFAULT_POLICY)
  self.assertEqual(p['mapa_interfaces'],{'wan':'wan1',**{f'lan{i}':f'lan{i}' for i in range(1,5)}})
 def test_legacy_controls(self):
  f={r['rule']:r for r in h.evaluate(self.snapshot(),h.DEFAULT_POLICY)}
  for rule in ('maintainer','telemetria_rating'):
   self.assertTrue(f[rule]['eligible']);self.assertEqual(f[rule]['status'],'Não conforme')
   for op in h.remediacao.propose(rule,self.snapshot(),h.DEFAULT_POLICY):h.remediacao.validate_op(op)
 def test_missing_no_guess(self):
  s=self.snapshot();s['Global']['value'].pop('admin-maintainer')
  f=next(r for r in h.evaluate(s,h.DEFAULT_POLICY) if r['rule']=='maintainer')
  self.assertFalse(f['eligible']);self.assertEqual(f['status'],h.UNKNOWN)
 def test_modern_maintainer(self):
  s=self.snapshot('60F','7.4.12')
  f=next(r for r in h.evaluate(s,h.DEFAULT_POLICY) if r['rule']=='maintainer')
  self.assertEqual(f['status'],'Não aplicável')
  with self.assertRaises(ValueError):h.remediacao.propose('maintainer',s,h.DEFAULT_POLICY)
if __name__=='__main__':unittest.main()
