import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch,Mock
import uuid
import zipfile
sys.path.insert(0,str(Path('outputs').resolve()))
from refresh_core import inventory,storage,update
from refresh_core.runner import Tee,run

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.folder=Path('work/central-tests/artifacts')/uuid.uuid4().hex;self.folder.mkdir(parents=True)
        self.data={'schema':1,'units':['SP'],'groups':[{'nome':'Operacao','usuario':'operator','password_env':'TEST_PASS','secret_env':'TEST_ENABLE','key_file':''}],
                   'devices':[{'unidade':'SP','nome':'FW','host':'192.0.2.1','porta':'22','plataforma':'fortinet','grupo':'Operacao'},
                              {'unidade':'SP','nome':'SW','host':'192.0.2.2','porta':'22','plataforma':'juniper_junos','grupo':'Operacao'}]}

    def test_registry_atomic_and_no_password_fields(self):
        path=self.folder/'cadastro.json';inventory.save(path,self.data)
        data=copy.deepcopy(self.data);data['groups'][0]['password']='SECRET'
        with self.assertRaises(ValueError):inventory.save(path,data)
        self.assertEqual(inventory.read(path),self.data)
        self.assertNotIn('SECRET',path.read_text())

    def test_duplicate_invalid_group_and_port(self):
        for mutation in (lambda d:d['devices'].append(d['devices'][0].copy()),lambda d:d['devices'][0].update(grupo='missing'),lambda d:d['devices'][0].update(porta='70000')):
            data=copy.deepcopy(self.data);mutation(data)
            with self.assertRaises(ValueError):inventory.validate(data)

    def test_dispatch_filters_and_rdm_csv(self):
        for tool,expected in [('fortigate-hardening',1),('fortigate-auditoria',1),('switch-mapper',1),('localizador-mac',2)]:
            path=inventory.dispatch(self.folder/(tool+'.json'),self.data,'SP',tool)
            self.assertEqual(len(json.loads(path.read_text())['devices']),expected)
        path=inventory.dispatch(self.folder/'rdm.json',self.data,'SP','fortigate-rdm')
        self.assertEqual(path.suffix,'.csv');self.assertNotIn('192.0.2.2',path.read_text(encoding='utf-8-sig'))

    def test_mixed_password_groups_not_silently_merged(self):
        data=copy.deepcopy(self.data);data['groups'].append({**data['groups'][0],'nome':'Outro','password_env':'OTHER'})
        data['devices'].append({**data['devices'][0],'nome':'FW2','host':'192.0.2.3','grupo':'Outro'})
        with self.assertRaises(ValueError):inventory.dispatch(self.folder/'mixed.json',data,'SP','fortigate-hardening')

    def test_tee_keeps_console_and_masks_session_secrets(self):
        import threading
        visible=io.StringIO();log=io.StringIO()
        with patch.dict(os.environ,{'REFRESH_SECRET_NAMES':'["TEST_PASS"]','TEST_PASS':'VERY_SECRET'}):
            Tee(visible,log,threading.RLock()).write('Error VERY_SECRET')
        self.assertEqual(log.getvalue(),'Error [OCULTO]');self.assertEqual(log.getvalue(),visible.getvalue())

    def test_runner_records_lifecycle_and_artifact(self):
        script=self.folder/'script.py';script.write_text("print('coleta concluida')\nfrom refresh_core.storage import event\nevent('Relatório','example.xlsx')\n",encoding='utf-8')
        folder=self.folder/'history';log=self.folder/'console.log'
        with patch.dict(os.environ,{'REFRESH_HISTORY':str(folder),'REFRESH_RUN_ID':'test','REFRESH_RUN_LOG':str(log),'REFRESH_TOOL':'test'}):run(script)
        rows=storage.history(folder)
        self.assertEqual(len(rows),2);self.assertIn('coleta concluida',log.read_text(encoding='utf-8'))
        self.assertEqual(json.loads((folder/'run_test.json').read_text())['exit_code'],0)

    def archive(self,corrupt=False):
        payload={'CentralRefresh.exe':b'exe','ferramentas/a/inventario.csv':b'default','code.py':b'new code'}
        meta={'schema':1,'version':'2.0.0','files':{k:hashlib.sha256(v).hexdigest() for k,v in payload.items()}}
        path=self.folder/'release.zip'
        with zipfile.ZipFile(path,'w') as z:
            for name,content in payload.items():z.writestr('CentralRefresh/'+name,content+b'bad' if corrupt else content)
            z.writestr('CentralRefresh/release.json',json.dumps(meta))
        return path

    def test_update_preserves_data_and_old_code(self):
        source=self.folder/'old';(source/'ferramentas/a').mkdir(parents=True)
        (source/'code.py').write_text('old code');(source/'ferramentas/a/inventario.csv').write_text('USER DATA')
        (source/'release.json').write_text('old manifest')
        target,count=update.install(self.archive(),source,self.folder/'new')
        self.assertEqual((target/'ferramentas/a/inventario.csv').read_text(),'USER DATA')
        self.assertEqual((target/'code.py').read_text(),'new code');self.assertEqual((source/'code.py').read_text(),'old code')
        self.assertEqual(json.loads((target/'release.json').read_text())['version'],'2.0.0')
        self.assertGreater(count,0)

    def test_update_rejects_corruption_and_traversal(self):
        with self.assertRaises(ValueError):update.inspect(self.archive(True))
        path=self.archive()
        with zipfile.ZipFile(path,'a') as z:z.writestr('CentralRefresh/../../escape','x')
        with self.assertRaises(ValueError):update.inspect(path)

    def test_update_rejects_source_as_destination(self):
        source=self.folder/'old';source.mkdir()
        with self.assertRaises(ValueError):update.install(self.archive(),source,source)

    def test_import_previous_preserves_both_conflicting_policies(self):
        old=self.folder/'old';new=self.folder/'new';old.mkdir();new.mkdir()
        (old/'politica_hardening.json').write_text('old user policy')
        (new/'politica_hardening.json').write_text('current user policy')
        copied=update.migrate(old,new,{'files':{}},preserve_existing=True)
        self.assertEqual((new/'politica_hardening.json').read_text(),'current user policy')
        self.assertEqual((new/copied[0]).read_text(),'old user policy')

    def test_common_switch_factory_enforces_host_key_verification(self):
        from refresh_core.ssh import connect_switch
        with patch('netmiko.ConnectHandler') as connector:
            connect_switch(host='192.0.2.1',ssh_strict=False)
            self.assertTrue(connector.call_args.kwargs['ssh_strict'])

    def test_central_gui_and_registry(self):
        import importlib.util
        import tkinter as tk
        from refresh_core.registry_ui import Registry
        spec=importlib.util.spec_from_file_location('central_test','outputs/central-refresh/central.py');central=importlib.util.module_from_spec(spec);spec.loader.exec_module(central)
        root=tk.Tk();root.withdraw();app=central.App(root)
        try:
            self.assertEqual(app.module_version('fortigate-config'),'2.0.0')
            registry=Registry(root,self.folder/'registry.json',lambda:None);root.update_idletasks();registry.window.destroy()
        finally:app.close()
