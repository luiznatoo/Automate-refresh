import sys,copy,unittest,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path('outputs/localizador-mac').resolve()))
import localizar as m
import interface as ui
import fortigate
class Tests(unittest.TestCase):
 def device(self,name='SW',error=False,mode='access'):
  return {'name':name,'host':'192.0.2.1','aliases':[name],'at':'test','entries':[] if error else [{'mac':'aabbccddeeff','port':'ge-0/0/1','vlan':'200','instance':'','type':'dynamic','line':'test'}], 'ports':{'ge-0/0/1':{'mode':mode}},'lldp':[],'fdb_ok':not error,'errors':[{'command':'SSH','error':'timeout'}] if error else []}
 def tables(self,devices):return m.analyze([{'mac':'aabbccddeeff','nome':'PC','ip':'192.0.2.20'}],devices)
 def test_failure_elsewhere_does_not_taint_location(self):
  t=self.tables([self.device(),self.device('FAIL',True)])
  self.assertEqual(m.useful_rows(t)[0]['Resultado'],'Localizado')
 def test_ambiguity_remains_review(self):
  row=m.useful_rows(self.tables([self.device(),self.device('SW2')]))[0]
  self.assertIn('mais de uma porta',row['Resultado']);self.assertEqual(row['Porta'],'')
 def test_uplink_not_reported(self):
  row=m.useful_rows(self.tables([self.device(mode='trunk')]))[0];self.assertEqual(row['Porta'],'');self.assertIn('A revisar',row['Resultado'])
 def test_duplicate_vlan_consolidated(self):
  d=self.device();d['entries']+= [{**d['entries'][0],'vlan':'201'}]
  row=m.useful_rows(self.tables([d]))[0];self.assertEqual(row['Resultado'],'Localizado');self.assertEqual(row['VLAN'],'200, 201')
 def test_excel_only_useful(self):
  from modelo_excel import prepare_template
  t=self.tables([self.device(),self.device('FAIL',True)]);t['Localização'][0]['Dispositivo']='=1+1'
  book=prepare_template(t)
  self.assertEqual(book.sheetnames,['Dispositivos','Pendências']);self.assertEqual(book['Dispositivos'].max_column,7)
  self.assertEqual(book['Dispositivos']['A2'].data_type,'s');self.assertEqual(book['Pendências'].max_row,2)
 def test_optional_name_and_inferred_mode(self):
  project={'settings':copy.deepcopy(ui.SETTINGS),'switches':[{'nome':'','host':'192.0.2.1','plataforma':'juniper_junos'}],'firewalls':[],'macs':[{'nome':'','mac':'aabbccddeeff'}]}
  project['settings'].update(modo='lista',usuario='operator')
  jobs,fw,targets,args=ui.build_jobs(project,{'SW_PASSWORD':'test'})
  self.assertEqual(jobs[0][0]['nome'],'192.0.2.1');self.assertFalse(fw)
 def test_gui_clean_and_credentials_preserved(self):
  import tkinter as tk
  root=tk.Tk();root.withdraw()
  with patch.object(ui.App,'load_initial'),patch('refresh_core.inventory.preload'):
   app=ui.App(root)
  try:
   self.assertEqual(len(app.tabs.tabs()),3);self.assertEqual(app.options.state(),'withdrawn')
   app.credentials['SW_PASSWORD'].set('test');data=app.project();app.apply_project(data)
   self.assertEqual(app.credentials['SW_PASSWORD'].get(),'test');self.assertNotIn('test',str(app.project()))
   self.assertEqual(tuple(app.editors['switches'].table.cget('displaycolumns')),('nome','host','plataforma'))
  finally:app.close()
class SimpleScreenTests(unittest.TestCase):
 def test_single_screen_and_metadata(self):
  import tkinter as tk
  root=tk.Tk();root.withdraw()
  with patch.object(ui.App,'load_initial'),patch('refresh_core.inventory.preload'):
   app=ui.SimpleApp(root)
  try:
   self.assertFalse(app.tabs.winfo_ismapped());self.assertEqual(app.start_button.cget('text'),'Mapear rede')
   app.save_device('switches',{'nome':'SW01','host':'192.0.2.10','plataforma':'juniper_junos'})
   app.save_device('switches',{'nome':'SW02','host':'192.0.2.11','plataforma':'juniper_junos'})
   app.save_device('firewalls',{'nome':'FW01','host':'192.0.2.1'})
   self.assertEqual(app.device_table.item('firewalls:0','values')[1],'FW01')
   with self.assertRaises(ValueError):app.save_device('switches',{'nome':'SW03','host':'192.0.2.10','plataforma':'juniper_junos'})
   app.credentials['SW_PASSWORD'].set('session-test')
   data=app.project();self.assertEqual(len(data['switches']),2);self.assertEqual(data['settings']['modo'],'integrado')
   self.assertEqual(app.credentials['SW_PASSWORD'].get(),'session-test');self.assertNotIn('session-test',str(data))
   data['switches'][0].update(nome='CUSTOM',plataforma='cisco_ios',porta='2222')
   app.apply_project(data);self.assertEqual(app.project()['switches'][0]['porta'],'2222')
   app.save_device('switches',{**app.editors['switches'].rows()[0],'nome':'RENAMED'},0)
   self.assertEqual(app.project()['switches'][0]['nome'],'RENAMED');self.assertEqual(app.project()['switches'][0]['porta'],'2222')
   legacy={'schema':1,'tipo':'mapeamento-switches','settings':{'usuario':'operator'},'switches':app.project()['switches']}
   app.apply_project(legacy);self.assertEqual(app.project()['firewalls'][0]['nome'],'FW01')
   self.assertEqual(app.credentials['SW_PASSWORD'].get(),'session-test')
   app.device_table.selection_set('firewalls:0');app.remove_devices()
   app.mac_text.insert('1.0','aa:bb:cc:dd:ee:ff');data=app.project()
   self.assertEqual(data['settings']['modo'],'lista');self.assertEqual(data['macs'][0]['mac'],'aabbccddeeff')
  finally:app.close()
if __name__=='__main__':unittest.main()
