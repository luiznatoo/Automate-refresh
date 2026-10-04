import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path('outputs/fortigate-hardening').resolve()))
import hardening as h
class Tests(unittest.TestCase):
 def test_only_script(self):
  self.assertEqual(len(h.LABELS),31);self.assertEqual(set(h.LABELS),h.SCRIPT_IDS)
  self.assertEqual({r['rule'] for r in h.evaluate({},h.DEFAULT_POLICY)},h.SCRIPT_IDS)
 def test_legacy_policy_migration(self):
  p=copy.deepcopy(h.DEFAULT_POLICY);p['enabled']=list(h.LEGACY_LABELS)
  self.assertEqual(set(h.migrate_policy(p)['enabled']),h.SCRIPT_IDS)
 def test_old_exceptions_removed(self):
  p=copy.deepcopy(h.DEFAULT_POLICY);p['exceptions']=[{'rule':'mfa','serial':'test','entry':'admin','reason':'legacy exception','expires':'2099-01-01'}]
  self.assertEqual(h.validate_policy(p)['exceptions'],[])
 def test_no_extra_queries(self):
  for k in ('Administradores','Senha','SNMP','Tokens','TokenUsers','Email'):self.assertNotIn(k,h.READS)
  self.assertNotIn('strong-crypto',h.GLOBAL_FIELDS);self.assertNotIn('admin-lockout-threshold',h.GLOBAL_FIELDS)
 def test_auth_message(self):
  from paramiko import AuthenticationException
  with patch.object(h,'SSH',side_effect=AuthenticationException('TOP_SECRET')) as ssh:
   result=h.audit_device({'nome':'lab','host':'192.0.2.1'},'TOP_SECRET',45,'',h.DEFAULT_POLICY)
  self.assertIn('Autenticação SSH recusada',result['snapshot']['Sistema']['error']);self.assertNotIn('TOP_SECRET',json.dumps(result))
  self.assertTrue(all('Autenticação SSH recusada' in r['evidence'] for r in result['findings']));ssh.assert_called_once()
 def test_partial_not_discarded(self):
  class Reader:
   def command(self,cmd):
    if cmd=='get system status':return 'Version: FortiGate-60F v7.4.12,build2902\nSerial-Number: TEST\nHostname: TEST\nVirtual domain configuration: disable\nCurrent HA mode: standalone'
    raise TimeoutError()
  s=h.snapshot(Reader());self.assertIn('value',s['Sistema']);self.assertIn('error',s['HA'])
 def test_removed_cannot_plan(self):
  with self.assertRaises(ValueError):h.make_plan({'policy':h.DEFAULT_POLICY,'devices':[]},{(0,'mfa')})
 def test_60f_mapping_and_custom_preserved(self):
  snap={'Sistema':{'value':{'Version':'FortiGate-60F v7.4.9,build1'}},'Interfaces':{'value':[{'id':n} for n in ('wan1','wan2','internal','internal3','internal4')]}}
  p=h.effective_policy(snap,h.DEFAULT_POLICY)
  self.assertEqual(p['mapa_interfaces'],{'wan':'wan1','lan1':'internal','lan2':'wan2','lan3':'internal3','lan4':'internal4'})
  custom=copy.deepcopy(h.DEFAULT_POLICY);custom['mapa_interfaces']['wan']='CUSTOM'
  self.assertEqual(h.effective_policy(snap,custom)['mapa_interfaces']['wan'],'CUSTOM')
 def test_rating_removed_not_conformity(self):
  snap={'Sistema':{'value':{'Version':'FortiGate-60F v7.4.9,build1'}}}
  f=next(f for f in h.evaluate(snap,h.DEFAULT_POLICY) if f['rule']=='telemetria_rating')
  self.assertEqual(f['status'],'Não aplicável');self.assertFalse(f['eligible'])
  snap['Sistema']['value']['Version']='FortiGate-60F v7.0.9,build1'
  f=next(f for f in h.evaluate(snap,h.DEFAULT_POLICY) if f['rule']=='telemetria_rating');self.assertEqual(f['status'],h.UNKNOWN)
 def test_filter_by_firewall(self):
  import tkinter as tk
  from hardening_ui import App
  root=tk.Tk();root.withdraw();app=App(root)
  try:
   findings=h.evaluate({},h.DEFAULT_POLICY)
   app.report={'policy':h.DEFAULT_POLICY,'devices':[{'device':{'nome':'Mesmo nome','host':host},'snapshot':{},'findings':copy.deepcopy(findings)} for host in ('192.0.2.1','192.0.2.2')]}
   app.result_filter.set('Todos');app.render();self.assertEqual(len(app.rows),62)
   labels=app.firewall_selector.cget('values');app.firewall_filter.set(labels[2]);app.filter_firewall()
   self.assertEqual(len(app.rows),31);self.assertTrue(all(key[0]==1 for key,f in app.rows.values()))
   app.marked.add((1,'timeout'));app.firewall_filter.set(labels[0]);app.filter_firewall()
   self.assertFalse(app.marked);self.assertEqual(len(app.rows),62)
  finally:app.close()
 def test_gui_scope(self):
  import tkinter as tk
  from hardening_ui import App
  root=tk.Tk();root.withdraw();app=App(root)
  try:
   self.assertEqual(set(app.rule_vars),h.SCRIPT_IDS)
   visible=[app.advanced_tabs.tab(t,'text') for t in app.advanced_tabs.tabs() if app.advanced_tabs.tab(t,'state')!='hidden']
   self.assertNotIn('Parâmetros de correção',visible);self.assertNotIn('FortiToken / compatibilidade',visible)
  finally:app.close()
if __name__=='__main__':unittest.main()
