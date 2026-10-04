"""Entrada compartilhada dos executáveis portáteis da Central de Refresh."""
import os
from pathlib import Path
import runpy
import sys
import json

TOOLS={'fortigate-hardening':'interface.py','fortigate-auditoria':'interface.py','switch-mapper':'interface.py','localizador-mac':'interface.py','fortigate-rdm':'fortigate_rdm.py',
       'fortigate-config':'gerar.py','fortiswitch-config':'gerar.py'}


def runtime_check():
    import tkinter, tkinter.ttk, tkinter.filedialog, tkinter.messagebox
    import csv,ipaddress,xml.etree.ElementTree,datetime,re,shlex,getpass,importlib,hashlib,argparse
    import queue,threading,concurrent.futures,types,copy,textwrap,uuid,zipfile,shutil
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import tkinter.simpledialog
    import netmiko,ntc_templates,openpyxl,paramiko
    from netmiko.utilities import get_structured_data_textfsm
    sample=get_structured_data_textfsm('Vlan Mac Address Type Ports\n10 aabb.ccdd.eeff DYNAMIC Gi1/0/2',platform='cisco_ios',command='show mac address-table')
    if not isinstance(sample,list): raise RuntimeError('Templates NTC não encontrados no pacote')
    if getattr(sys,'frozen',False):
        for module in (netmiko,ntc_templates,openpyxl,paramiko):
            if not Path(module.__file__).resolve().is_relative_to(Path(sys._MEIPASS).resolve()):
                raise RuntimeError('Dependência carregada fora do pacote: '+module.__name__)
    root=tkinter.Tk(); root.withdraw(); root.update_idletasks(); root.destroy()


def main():
    home=Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[1]
    args=sys.argv[1:]
    if args and args[0]=='--smoke-central':
        import tkinter as tk
        namespace=runpy.run_path(str(home/'central.py'),run_name='smoke_central')
        root=tk.Tk(); root.withdraw(); app=namespace['App'](root); root.update_idletasks(); app.close()
        Path(args[1]).write_text(json.dumps({'ok':True}),encoding='utf-8')
        return
    if args and args[0]=='--self-test':
        report=Path(args[1])
        try:
            runtime_check(); report.write_text(json.dumps({'ok':True}),encoding='utf-8')
        except Exception as exc:
            report.write_text(json.dumps({'ok':False,'error':str(exc)}),encoding='utf-8'); raise
        return
    if args and args[0] in ('--tool','--smoke-tool'):
        mode=args[0]; identifier=args[1]
        if identifier not in TOOLS: raise ValueError('Ferramenta desconhecida')
        folder=home/'ferramentas'/identifier; script=folder/TOOLS[identifier]
        sys.path.insert(0,str(home));sys.path.insert(0,str(folder)); os.chdir(folder)
        if mode=='--smoke-tool':
            report=Path(args[2]); namespace=runpy.run_path(str(script),run_name='smoke_tool')
            if identifier!='fortigate-rdm':
                import tkinter as tk
                root=tk.Tk(); root.withdraw(); app=namespace['App'](root); root.update_idletasks()
                if hasattr(app,'close'): app.close()
                else: root.destroy()
            report.write_text(json.dumps({'ok':True,'tool':identifier}),encoding='utf-8')
            return
        sys.argv=[str(script)]
        from refresh_core.runner import run
        run(script)
        return
    sys.path.insert(0,str(home)); sys.argv=[str(home/'central.py')]
    runpy.run_path(str(home/'central.py'),run_name='__main__')


if __name__=='__main__': main()
