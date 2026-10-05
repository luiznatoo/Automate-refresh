import sys,unittest,tempfile,csv
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path('outputs/switch-mapper').resolve()))
import interface as ui
class Tests(unittest.TestCase):
 def setUp(self):
  self.root=ui.tk.Tk();self.root.withdraw()
  with patch.object(ui.App,'load_initial'),patch('refresh_core.inventory.preload'):self.app=ui.App(self.root)
 def tearDown(self):self.app.running=False;self.app.close()
 def test_single_screen(self):
  self.assertFalse(hasattr(self.app,'tabs'));self.assertEqual(self.app.options.state(),'withdrawn')
  self.assertEqual(self.app.start_button.cget('text'),'Mapear portas')
 def test_hostname_and_overrides_preserved(self):
  self.app.inventory.save_row({'nome':'SW01','host':'192.0.2.1','plataforma':'cisco_ios','porta':'2222','usuario':'specific'})
  self.app.inventory.save_row({'nome':'SW02'},0)
  row=self.app.inventory.rows()[0];self.assertEqual(row['porta'],'2222');self.assertEqual(row['usuario'],'specific')
  self.assertEqual(self.app.inventory.table.item('0','values')[0],'SW02')
 def test_duplicates_transactional(self):
  row={'nome':'SW01','host':'192.0.2.1','plataforma':'juniper_junos'};self.app.inventory.save_row(row)
  with self.assertRaises(ValueError):self.app.inventory.save_row({**row,'nome':'SW02'})
  self.assertEqual(len(self.app.inventory.rows()),1)
 def test_session_and_jobs(self):
  self.app.inventory.save_row({'nome':'SW01','host':'192.0.2.1','plataforma':'juniper_junos'})
  self.app.settings['usuario'].set('operator');self.app.credentials['SW_PASSWORD'].set('test-password')
  project=self.app.project();self.app.apply_project(project)
  self.assertEqual(self.app.credentials['SW_PASSWORD'].get(),'test-password');self.assertNotIn('test-password',str(project))
  jobs,args=ui.build_jobs(project,{'SW_PASSWORD':'test-password'});self.assertEqual(jobs[0][0]['nome'],'SW01');self.assertEqual(jobs[0][1]['username'],'operator')
 def test_csv_append_and_remove(self):
  import uuid
  folder=Path('work/switch-ui-tests/artifacts')/uuid.uuid4().hex;folder.mkdir(parents=True)
  path=folder/'switches.csv';path.write_text('hostname;ip;tipo\nSW01;192.0.2.1;Juniper\n',encoding='utf-8')
  with patch.object(ui.filedialog,'askopenfilename',return_value=str(path)):
   self.app.inventory.import_csv();self.app.inventory.import_csv()
  self.assertEqual(len(self.app.inventory.rows()),1)
  self.app.inventory.table.selection_set('0');self.app.inventory.remove();self.assertFalse(self.app.inventory.rows())
if __name__=='__main__':unittest.main()
