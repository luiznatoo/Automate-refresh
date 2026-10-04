import json
import os
import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
import auditoria as motor
from firewall_inventory import Inventory

BASE=Path(__file__).resolve().parent

class App:
    def __init__(self,root,devices=None):
        self.root=root; self.events=queue.Queue(); self.busy=False; self.result=None
        root.title('Auditoria de Firewall • somente leitura'); root.geometry('1050x720'); root.minsize(800,560)
        root.columnconfigure(0,weight=1); root.rowconfigure(1,weight=1)
        ttk.Label(root,text='Auditoria de Firewall',font=('Segoe UI',20,'bold')).grid(row=0,column=0,sticky='w',padx=18,pady=12)
        tabs=ttk.Notebook(root); tabs.grid(row=1,column=0,sticky='nsew',padx=18)
        group=ttk.Notebook(tabs); tabs.add(group,text='Coleta em lote')
        inv=ttk.Frame(group,padding=8); group.add(inv,text='Firewalls')
        self.inventory=Inventory(inv,lambda:None,lambda:not self.busy)
        if devices:self.inventory.set_rows(devices)
        form=ttk.Frame(group,padding=12); group.add(form,text='Acesso SSH'); form.columnconfigure(1,weight=1)
        self.values={}
        fields=[('usuario','Usuário SSH padrão',''),('senha','Senha SSH (não salva)',''),('known_hosts','Arquivo known_hosts (opcional)',''),('workers','Conexões simultâneas','4'),('timeout','Timeout por comando (segundos)','45')]
        for i,(key,label,value) in enumerate(fields):
            ttk.Label(form,text=label).grid(row=i,column=0,sticky='w',pady=7)
            var=tk.StringVar(value=value); self.values[key]=var
            ttk.Entry(form,textvariable=var,show='*' if key=='senha' else '').grid(row=i,column=1,sticky='ew',padx=8)
            if key in ('csv','known_hosts'): ttk.Button(form,text='Selecionar',command=lambda k=key:self.browse(k)).grid(row=i,column=2)
        ttk.Button(form,text='Validar inventário',command=self.validate).grid(row=6,column=0,pady=10)
        ttk.Label(form,text='Sem VDOM • somente leitura • CSV sem senhas\nMais de 100 equipamentos, processados em lotes limitados pela concorrência.',wraplength=700).grid(row=7,column=0,columnspan=3,sticky='w',pady=10)
        self.log=tk.Text(form,height=8,wrap='word',state='disabled'); self.log.grid(row=8,column=0,columnspan=3,sticky='nsew'); form.rowconfigure(8,weight=1)
        rules=ttk.Frame(tabs,padding=12); tabs.add(rules,text='Regras configuráveis'); rules.columnconfigure(0,weight=1); rules.rowconfigure(1,weight=1)
        ttk.Label(rules,text='true habilita; false desabilita. Valores esperados de cada unidade ficam no CSV.').grid(row=0,column=0,sticky='w',pady=8)
        self.editor=tk.Text(rules,wrap='none'); self.editor.grid(row=1,column=0,sticky='nsew')
        saved=BASE/'regras.json'; self.editor.insert('1.0',saved.read_text(encoding='utf-8') if saved.exists() else json.dumps(motor.DEFAULTS,indent=2))
        ttk.Button(rules,text='Salvar regras',command=self.save_rules).grid(row=2,column=0,sticky='w',pady=8)
        bar=ttk.Frame(root,padding=12); bar.grid(row=2,column=0,sticky='ew')
        self.start_button=ttk.Button(bar,text='Iniciar auditoria',command=self.start); self.start_button.pack(side='left',padx=6)
        ttk.Button(bar,text='Abrir último Excel',command=self.open_result).pack(side='left',padx=6)
        self.status=tk.StringVar(value='Pronto'); ttk.Label(bar,textvariable=self.status).pack(side='left',padx=12)
        root.protocol('WM_DELETE_WINDOW',self.close); self.timer=root.after(100,self.poll)
        from refresh_core.inventory import preload
        preload(self,'fortigate-auditoria')

    def browse(self,key):
        path=filedialog.askopenfilename()
        if path: self.values[key].set(path)
    def get_rules(self): return motor.policy(json.loads(self.editor.get('1.0','end')))
    def save_rules(self):
        try: (BASE/'regras.json').write_text(json.dumps(self.get_rules(),indent=2),encoding='utf-8'); self.status.set('Regras salvas')
        except Exception as exc: messagebox.showerror('Regras',str(exc))
    def validate(self):
        try:
            devices=self.inventory.rows(); self.status.set(f'{len(devices)} equipamentos válidos')
        except Exception as exc: messagebox.showerror('Inventário',str(exc))
    def start(self):
        if self.busy: return
        try:
            devices=self.inventory.rows(); rules=self.get_rules()
            workers=int(self.values['workers'].get()); timeout=int(self.values['timeout'].get())
            if not 1<=workers<=16 or not 5<=timeout<=600: raise ValueError('Concorrência: 1–16; timeout: 5–600 segundos')
            for device in devices:
                device['usuario']=device['usuario'] or self.values['usuario'].get().strip()
                if not device['usuario']: raise ValueError('Informe o usuário SSH')
            known=self.values['known_hosts'].get().strip()
            if known and not Path(known).is_file(): raise ValueError('Arquivo known_hosts não encontrado')
            password=self.values['senha'].get()
        except Exception as exc: messagebox.showerror('Verifique os dados',str(exc)); return
        self.busy=True; self.start_button.configure(state='disabled'); self.status.set('Coletando…'); self.done=0; self.total=len(devices)
        def work():
            try: self.events.put(('done',motor.run(devices,password,rules,workers,timeout,known,lambda name:self.events.put(('progress',name)))))
            except Exception as exc: self.events.put(('error',type(exc).__name__))
        threading.Thread(target=work,daemon=True).start()
    def poll(self):
        while not self.events.empty():
            kind,value=self.events.get()
            if kind=='progress':
                self.done+=1; self.status.set(f'{self.done}/{self.total} concluídos')
                self.log.configure(state='normal'); self.log.insert('end',value+' — consulta concluída; resultado no Excel\n'); self.log.see('end'); self.log.configure(state='disabled')
            else:
                self.busy=False; self.start_button.configure(state='normal'); self.values['senha'].set('')
                if kind=='done': self.result=value; self.status.set('Excel gerado'); messagebox.showinfo('Auditoria concluída',str(value))
                else: self.status.set('Falha'); messagebox.showerror('Auditoria','Não foi possível concluir: '+value)
        self.timer=self.root.after(100,self.poll)
    def open_result(self):
        if self.result: os.startfile(str(self.result))
    def close(self):
        if self.busy: messagebox.showinfo('Coleta em andamento','Aguarde a conclusão antes de fechar.'); return
        self.root.after_cancel(self.timer); self.root.destroy()

if __name__=='__main__':
    root=tk.Tk(); App(root); root.mainloop()
