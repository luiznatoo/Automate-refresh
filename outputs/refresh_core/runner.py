"""Lifecycle and console tee; input and getpass are never intercepted."""
import os
import json
import sys
import runpy
import uuid
import traceback
import threading
from pathlib import Path
from .storage import now,write_json,event

class Tee:
    def __init__(self,stream,log,lock):self.stream=stream;self.log=log;self.lock=lock
    def write(self,text):
        for name in json.loads(os.getenv('REFRESH_SECRET_NAMES','[]')):
            secret=os.getenv(name,'')
            if secret:text=text.replace(secret,'[OCULTO]')
        with self.lock:
            if self.stream:self.stream.write(text)
            self.log.write(text);self.log.flush()
        return len(text)
    def flush(self):
        if self.stream:self.stream.flush()
        self.log.flush()
    def isatty(self):return bool(self.stream and self.stream.isatty())
    def fileno(self):return self.stream.fileno()
    @property
    def encoding(self):return getattr(self.stream,'encoding','utf-8')

def run(script):
    folder=os.getenv('REFRESH_HISTORY');rid=os.getenv('REFRESH_RUN_ID')
    if not folder or not rid:return runpy.run_path(str(script),run_name='__main__')
    path=Path(folder)/('run_'+rid+'.json')
    record={'at':now(),'run':rid,'tool':os.getenv('REFRESH_TOOL',''),'kind':'Sessão','status':'Em execução','pid':os.getpid(),'path':os.getenv('REFRESH_RUN_LOG',''),'unit':os.getenv('REFRESH_UNIT','')}
    write_json(path,record)
    original=(sys.stdout,sys.stderr);lock=threading.RLock();code=0
    with open(record['path'],'a',encoding='utf-8',buffering=1) as log:
        sys.stdout=Tee(original[0],log,lock);sys.stderr=Tee(original[1],log,lock)
        try:
            print('Início:',record['at'],'| Ferramenta:',record['tool'])
            import tkinter as tk
            from tkinter import messagebox
            original_callback=tk.Tk.report_callback_exception;original_error=messagebox.showerror
            def tracked_error(title=None,message=None,**options):
                event('Erro exibido',status='Falha',detail=str(title or 'Operação')[:160])
                return original_error(title,message,**options)
            messagebox.showerror=tracked_error
            def callback_error(self,kind,value,tb):
                event('Falha de interface',status='Falha',detail=kind.__name__)
                traceback.print_exception(kind,value,tb)
                from tkinter import messagebox
                messagebox.showerror('Falha de interface','A operação falhou. Consulte o histórico da Central.')
            tk.Tk.report_callback_exception=callback_error
            runpy.run_path(str(script),run_name='__main__')
        except SystemExit as exc:
            code=exc.code if isinstance(exc.code,int) else 0 if exc.code is None else 1
        except BaseException:
            code=1;traceback.print_exc()
        finally:
            record.update(finished=now(),status='Sessão encerrada' if code==0 else 'Encerrada com pendências' if code==2 else 'Falha',exit_code=code)
            write_json(path,record);print('Fim:',record['finished'],'|',record['status'])
            if 'original_callback' in locals():tk.Tk.report_callback_exception=original_callback;messagebox.showerror=original_error
            sys.stdout,sys.stderr=original
    if code:raise SystemExit(code)
