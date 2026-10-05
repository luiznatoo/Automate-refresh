"""Interface local para mapeamento completo de portas Cisco e Juniper."""
import copy
import csv
import json
import os
from pathlib import Path
import queue
import threading
from types import SimpleNamespace
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import mapear as motor
BASE=Path(__file__).resolve().parent

SW_FIELDS=[('nome','Nome'),('host','IP / DNS'),('plataforma','Plataforma'),('porta','Porta SSH'),('usuario','Usuário específico'),('password_env','Grupo de senha'),('secret_env','Grupo enable'),('key_file','Chave SSH opcional')]
SETTINGS={'usuario':'','timeout':'90','workers':'4','known_hosts':'','diagnostico':False}


def arrange_buttons(frame,buttons):
    """Wrap actions rather than allowing Windows DPI/short windows to clip them."""
    def layout(event=None):
        width=event.width if event else frame.winfo_width()
        unit=max(button.winfo_reqwidth()+10 for button in buttons)
        columns=max(1,width//unit)
        for index,button in enumerate(buttons):
            row,column=divmod(index,columns)
            button.grid(row=row,column=column,sticky='w',padx=4,pady=4)
    frame.bind('<Configure>',layout)
    layout()


class Inventory:
    TYPES={'Juniper':'juniper_junos','Cisco IOS':'cisco_ios','Cisco Nexus':'cisco_nxos'}
    def __init__(self,parent,fields,defaults,changed,available=lambda:True):
        self.fields=fields;self.defaults=defaults;self.changed=changed;self.available=available;self.data=[];self.parent=parent
        self.vars={k:tk.StringVar(value=defaults.get(k,'')) for k,_ in fields}
        bar=ttk.Frame(parent);bar.pack(fill='x',pady=(0,6))
        buttons=[ttk.Button(bar,text=label,command=fn) for label,fn in [('Adicionar switch',lambda:self.open_editor()),('Editar',lambda:self.open_editor(True)),('Remover',self.remove),('Importar CSV',self.import_csv)]]
        arrange_buttons(bar,buttons)
        frame=ttk.Frame(parent);frame.pack(fill='both',expand=True)
        self.table=ttk.Treeview(frame,columns=('nome','host','plataforma'),show='headings',selectmode='extended',height=8)
        for key,title,width in [('nome','Hostname',230),('host','IP / DNS',210),('plataforma','Tipo',150)]:
            self.table.heading(key,text=title);self.table.column(key,width=width,minwidth=90)
        self.table.grid(row=0,column=0,sticky='nsew');frame.rowconfigure(0,weight=1);frame.columnconfigure(0,weight=1)
        scroll=ttk.Scrollbar(frame,orient='vertical',command=self.table.yview);scroll.grid(row=0,column=1,sticky='ns');self.table.configure(yscrollcommand=scroll.set)
        self.table.bind('<Double-1>',lambda e:self.open_editor(True))

    def rows(self):return copy.deepcopy(self.data)
    def set_rows(self,rows):
        validated=[];names=set();endpoints=set()
        for row in rows:
            item={k:str(row.get(k,self.defaults.get(k,''))).strip() for k,_ in self.fields}
            item['nome']=item['nome'] or item['host'];item['porta']=item['porta'] or '22'
            if not item['host'] or any(c.isspace() for c in item['host']):raise ValueError('Informe IP ou DNS sem espaços.')
            if item['plataforma'] not in motor.PLATFORMS:raise ValueError('Tipo de switch inválido: '+item['nome'])
            if not item['porta'].isdigit() or not 1<=int(item['porta'])<=65535:raise ValueError('Porta SSH inválida.')
            key=(item['host'].casefold(),int(item['porta']))
            if key in endpoints or item['nome'].casefold() in names:raise ValueError('Switch duplicado: '+item['nome'])
            names.add(item['nome'].casefold());endpoints.add(key);validated.append(item)
        self.data=validated;self.table.delete(*self.table.get_children())
        for i,row in enumerate(validated):
            platform=next((k for k,v in self.TYPES.items() if v==row['plataforma']),row['plataforma'])
            self.table.insert('','end',iid=str(i),values=[row['nome'],row['host'],platform])
        self.changed()

    def save_row(self,row,index=None):
        if not self.available():return
        rows=self.rows()
        if index is None:rows.append(row)
        else:rows[index]={**rows[index],**row}
        self.set_rows(rows)

    def open_editor(self,editing=False):
        if not self.available():return
        selected=self.table.selection()
        if editing and len(selected)!=1:messagebox.showinfo('Switch','Selecione um switch para editar.');return
        index=int(selected[0]) if editing else None;current=self.data[index] if editing else self.defaults
        win=tk.Toplevel(self.parent);win.title('Editar switch' if editing else 'Adicionar switch');win.transient(self.parent.winfo_toplevel());win.grab_set();win.resizable(False,False)
        body=ttk.Frame(win,padding=18);body.pack(fill='both',expand=True)
        values={key:tk.StringVar(value=current.get(key,self.defaults.get(key,''))) for key,_ in self.fields}
        for i,(key,label) in enumerate([('nome','Hostname (opcional)'),('host','IP / DNS')]):
            ttk.Label(body,text=label).grid(row=i*2,column=0,sticky='w',pady=(6,2));ttk.Entry(body,textvariable=values[key],width=42).grid(row=i*2+1,column=0,sticky='ew')
        platform=tk.StringVar(value=next((k for k,v in self.TYPES.items() if v==current.get('plataforma')),'Juniper'))
        ttk.Label(body,text='Tipo do switch').grid(row=4,column=0,sticky='w',pady=(8,2))
        ttk.Combobox(body,textvariable=platform,values=list(self.TYPES),state='readonly',width=39).grid(row=5,column=0,sticky='ew')
        extra=ttk.Frame(body)
        for i,(key,label) in enumerate([('porta','Porta SSH'),('usuario','Usuário específico'),('password_env','Grupo de senha'),('secret_env','Grupo enable'),('key_file','Chave SSH')]):
            ttk.Label(extra,text=label).grid(row=i,column=0,sticky='w');ttk.Entry(extra,textvariable=values[key],width=26).grid(row=i,column=1,pady=3)
        def toggle():
            if extra.winfo_ismapped():extra.grid_remove()
            else:extra.grid(row=7,column=0,sticky='ew')
        ttk.Button(body,text='Acesso específico (opcional)',command=toggle).grid(row=6,column=0,sticky='w',pady=8)
        def save():
            try:
                row={k:v.get() for k,v in values.items()};row['plataforma']=self.TYPES[platform.get()]
                self.save_row(row,index);win.destroy()
            except ValueError as exc:messagebox.showerror('Cadastro',str(exc),parent=win)
        ttk.Button(body,text='Salvar' if editing else 'Adicionar',command=save).grid(row=8,column=0,sticky='e',pady=10)

    def remove(self):
        if not self.available():return
        selected={int(i) for i in self.table.selection()};self.set_rows([r for i,r in enumerate(self.data) if i not in selected])

    def import_csv(self):
        if not self.available():return
        path=filedialog.askopenfilename(filetypes=[('Inventário CSV','*.csv')])
        if not path:return
        try:
            incoming=motor.read_inventory(path)
            # Append new equipment, ignore identical entries, reject conflicting duplicates.
            merged=self.rows()
            for row in incoming:
                normalized={k:str(row.get(k,self.defaults.get(k,''))).strip() for k,_ in self.fields}
                normalized['nome']=normalized['nome'] or normalized['host'];normalized['porta']=normalized['porta'] or '22'
                if normalized not in merged:merged.append(normalized)
            self.set_rows(merged)
        except (ValueError,OSError) as exc:messagebox.showerror('Erro no CSV',str(exc))


def build_jobs(project,passwords):
    settings=project['settings']; devices=copy.deepcopy(project['switches'])
    timeout=int(settings['timeout']); workers=int(settings['workers'])
    if not 1<=workers<=32 or not 1<=timeout<=600: raise ValueError('Use 1 a 32 switches simultâneos e tempo de espera de 1 a 600 segundos.')
    known=settings['known_hosts'].strip()
    if known and not Path(known).is_file(): raise ValueError('Arquivo known_hosts não encontrado.')
    if not devices: raise ValueError('Adicione pelo menos um switch.')
    names=set(); endpoints=set(); jobs=[]
    def credential(group):
        if not group: return ''
        value=passwords.get(group,'') or os.getenv(group,'')
        if not value: raise ValueError('Preencha a senha do grupo '+group+'.')
        return value
    for device in devices:
        if not device['nome'] or not device['host'] or device['plataforma'] not in motor.PLATFORMS: raise ValueError('Confira nome, IP/DNS e plataforma de cada switch.')
        port=int(device.get('porta') or 22)
        if not 1<=port<=65535: raise ValueError('Porta SSH inválida: '+device['nome'])
        endpoint=(device['host'].casefold(),port)
        if device['nome'].casefold() in names or endpoint in endpoints: raise ValueError('Switch duplicado: '+device['nome'])
        names.add(device['nome'].casefold()); endpoints.add(endpoint); device['porta']=str(port)
        user=device.get('usuario') or settings['usuario'].strip()
        if not user: raise ValueError('Informe o usuário SSH para '+device['nome'])
        key=device.get('key_file','')
        if key:
            key_path=Path(key).expanduser()
            if not key_path.is_absolute(): key_path=BASE/key_path
            if not key_path.is_file(): raise ValueError('Chave SSH não encontrada: '+device['nome'])
            device['key_file']=str(key_path)
        jobs.append((device,{'username':user,'password':'' if key else credential(device.get('password_env') or 'SW_PASSWORD'),
                             'secret':credential(device.get('secret_env',''))}))
    args=SimpleNamespace(timeout=timeout,workers=workers,known_hosts=Path(known) if known else None,
                         modelo=BASE/'modelo_fixo.xlsx',saida=None,diagnostico=settings['diagnostico'])
    return jobs,args


class App:
    def __init__(self,root):
        self.root=root; self.running=False; self.events=queue.Queue(); self.credentials={}; self.last_path=None
        root.title('Mapeamento de portas');root.geometry(f'{min(800,root.winfo_screenwidth()-60)}x{min(660,root.winfo_screenheight()-100)}');root.minsize(650,540)
        root.columnconfigure(0,weight=1);root.rowconfigure(0,weight=1)
        page=ttk.Frame(root,padding=20);page.grid(row=0,column=0,sticky='nsew');page.columnconfigure(0,weight=1);page.rowconfigure(1,weight=1)
        ttk.Label(page,text='Mapeamento de portas',font=('Segoe UI',18,'bold')).grid(row=0,column=0,sticky='w',pady=(0,12))
        self.settings={k:(tk.BooleanVar(value=v) if isinstance(v,bool) else tk.StringVar(value=v)) for k,v in SETTINGS.items()}
        self.credentials['SW_PASSWORD']=tk.StringVar()
        self.options=tk.Toplevel(root);self.options.title('Opções');self.options.withdraw();self.options.protocol('WM_DELETE_WINDOW',self.options.withdraw)
        for i,(key,label) in enumerate([('timeout','Tempo de espera (s)'),('workers','Consultas simultâneas'),('known_hosts','Arquivo known_hosts (opcional)')]):
            ttk.Label(self.options,text=label).grid(row=i,column=0,padx=10,pady=7,sticky='w');ttk.Entry(self.options,textvariable=self.settings[key],width=40).grid(row=i,column=1,padx=10,pady=7)
        ttk.Button(self.options,text='Selecionar known_hosts',command=self.pick_known_hosts).grid(row=3,column=1,pady=5)
        ttk.Checkbutton(self.options,text='Salvar diagnóstico técnico',variable=self.settings['diagnostico']).grid(row=4,column=0,columnspan=2,padx=10,sticky='w')
        self.auth_body=ttk.Frame(self.options);self.auth_body.grid(row=5,column=0,columnspan=2,sticky='ew');self.auth_body.columnconfigure(1,weight=1)
        inventory_frame=ttk.Frame(page);inventory_frame.grid(row=1,column=0,sticky='nsew')
        self.inventory=Inventory(inventory_frame,SW_FIELDS,{'porta':'22','plataforma':'juniper_junos','password_env':'SW_PASSWORD'},self.refresh_credentials,lambda:not self.running)
        auth=ttk.Frame(page);auth.grid(row=2,column=0,sticky='ew',pady=(14,4));auth.columnconfigure(1,weight=1);auth.columnconfigure(3,weight=1)
        ttk.Label(auth,text='Usuário').grid(row=0,column=0);ttk.Entry(auth,textvariable=self.settings['usuario']).grid(row=0,column=1,sticky='ew',padx=(8,16))
        ttk.Label(auth,text='Senha').grid(row=0,column=2);ttk.Entry(auth,textvariable=self.credentials['SW_PASSWORD'],show='•').grid(row=0,column=3,sticky='ew',padx=(8,0))
        ttk.Label(page,text='A senha fica somente nesta sessão.').grid(row=3,column=0,sticky='w',pady=(0,12))
        bar=ttk.Frame(page);bar.grid(row=4,column=0,sticky='ew')
        self.start_button=ttk.Button(bar,text='Mapear portas',command=lambda:self.safe(self.start));self.start_button.pack(side='left')
        self.excel_button=ttk.Button(bar,text='Abrir Excel',state='disabled',command=lambda:self.safe(lambda:self.open_result(False)));self.excel_button.pack(side='left',padx=8)
        ttk.Button(bar,text='Opções',command=self.options.deiconify).pack(side='right')
        self.progress=ttk.Progressbar(page,mode='determinate');self.progress.grid(row=5,column=0,sticky='ew',pady=(15,6))
        self.status=tk.StringVar(value='Adicione switches, informe o acesso SSH e clique em Mapear portas.')
        self.summary=tk.StringVar(value='')
        ttk.Label(page,textvariable=self.status,wraplength=690).grid(row=6,column=0,sticky='w')
        ttk.Label(page,textvariable=self.summary,wraplength=690).grid(row=7,column=0,sticky='w',pady=5)
        self.details=tk.Toplevel(root);self.details.title('Detalhes do mapeamento');self.details.withdraw();self.details.protocol('WM_DELETE_WINDOW',self.details.withdraw)
        self.results=ttk.Treeview(self.details,columns=('switch','status','ports','vlans','issues'),show='headings',height=6);self.results.pack(fill='both',expand=True)
        for key,label in [('switch','Switch'),('status','Status'),('ports','Portas'),('vlans','VLANs'),('issues','Ocorrências')]:self.results.heading(key,text=label)
        self.log=tk.Text(self.details,height=10,state='disabled',wrap='word');self.log.pack(fill='both',expand=True)
        self.folder_button=ttk.Button(self.options,text='Abrir pasta do resultado',state='disabled',command=lambda:self.safe(lambda:self.open_result(True)));self.folder_button.grid(row=9,column=0,columnspan=2,pady=5)
        for i,(label,fn) in enumerate([('Abrir cadastro',self.load_project),('Salvar cadastro',self.save_project),('Detalhes da coleta',self.details.deiconify)]):
            ttk.Button(self.options,text=label,command=lambda f=fn:self.safe(f)).grid(row=6+i,column=0,columnspan=2,pady=5)
        self.load_initial();self.refresh_credentials();self.poll_id=root.after(100,self.poll);root.protocol('WM_DELETE_WINDOW',self.close)
        from refresh_core.inventory import preload
        preload(self,'switch-mapper')

    def refresh_credentials(self):
        groups=set()
        if hasattr(self,'inventory'):
            for row in self.inventory.rows():
                if not row.get('key_file'): groups.add(row.get('password_env') or 'SW_PASSWORD')
                if row.get('secret_env'): groups.add(row['secret_env'])
        if not groups: groups.add('SW_PASSWORD')
        for child in self.auth_body.winfo_children(): child.destroy()
        for index,group in enumerate(sorted(groups)):
            if group=='SW_PASSWORD':continue
            if group not in self.credentials: self.credentials[group]=tk.StringVar()
            ttk.Label(self.auth_body,text='Senha / enable ('+group+')').grid(row=index,column=0,sticky='w',padx=5,pady=6)
            ttk.Entry(self.auth_body,textvariable=self.credentials[group],show='•').grid(row=index,column=1,sticky='ew',padx=5,pady=6)

    def project(self):
        return {'schema':1,'tipo':'mapeamento-switches','settings':{k:v.get() for k,v in self.settings.items()},'switches':self.inventory.rows()}

    def apply_project(self,data):
        if not isinstance(data,dict) or data.get('schema')!=1 or data.get('tipo')!='mapeamento-switches': raise ValueError('Este arquivo não é um projeto do mapeador de switches.')
        if not isinstance(data.get('settings'),dict) or not isinstance(data.get('switches'),list): raise ValueError('Projeto inválido.')
        settings={**SETTINGS,**{k:v for k,v in data['settings'].items() if k in SETTINGS}}
        for key,default in SETTINGS.items():
            if isinstance(default,bool):
                if not isinstance(settings[key],bool): raise ValueError('Opção inválida: '+key)
            elif not isinstance(settings[key],(str,int)): raise ValueError('Campo inválido: '+key)
        if any(not isinstance(row,dict) or any(not isinstance(v,(str,int)) for v in row.values()) for row in data['switches']): raise ValueError('Cadastro inválido.')
        for key,var in self.settings.items(): var.set(settings[key])
        self.inventory.set_rows(data['switches'])

    def load_initial(self):
        try:
            project=BASE/'projeto_mapeamento.json'
            if project.exists(): self.apply_project(json.loads(project.read_text(encoding='utf-8-sig')))
            elif (BASE/'inventario.csv').exists(): self.inventory.set_rows(motor.read_inventory(BASE/'inventario.csv'))
        except (ValueError,OSError) as exc: self.status.set('Confira o cadastro: '+str(exc))

    def save_project(self):
        path=filedialog.asksaveasfilename(initialdir=BASE,initialfile='projeto_mapeamento.json',defaultextension='.json',filetypes=[('Projeto','*.json')])
        if path:
            Path(path).write_text(json.dumps(self.project(),ensure_ascii=False,indent=2),encoding='utf-8'); self.status.set('Projeto salvo sem senhas: '+path)

    def load_project(self):
        path=filedialog.askopenfilename(filetypes=[('Projeto','*.json')])
        if path:
            self.apply_project(json.loads(Path(path).read_text(encoding='utf-8-sig'))); self.status.set('Cadastro carregado. Credenciais da sessão preservadas.')

    def pick_known_hosts(self):
        path=filedialog.askopenfilename(title='Arquivo known_hosts')
        if path: self.settings['known_hosts'].set(path)

    def safe(self,fn):
        try: fn()
        except (ValueError,OSError,KeyError,TypeError,ImportError) as exc: messagebox.showerror('Verifique os dados',str(exc))

    def start(self):
        if self.running: return
        jobs,args=build_jobs(self.project(),{k:v.get() for k,v in self.credentials.items()})
        self.running=True; self.last_path=None; self.start_button.configure(state='disabled')
        self.excel_button.configure(state='disabled'); self.folder_button.configure(state='disabled')
        self.results.delete(*self.results.get_children()); self.log.configure(state='normal'); self.log.delete('1.0','end'); self.log.configure(state='disabled')
        self.progress.configure(value=0,maximum=len(jobs)); self.summary.set('Mapeamento em andamento. Aguarde a geração do Excel.')
        self.status.set('Consultando switches…')
        threading.Thread(target=self.worker,args=(jobs,args),daemon=True).start()

    def worker(self,jobs,args):
        try:
            import netmiko,ntc_templates,openpyxl
            from modelo_excel import load_model
            load_model(args.modelo).close()
            result=motor.run_mapping(jobs,args,on_event=lambda value:self.events.put(('progress',value)))
            self.events.put(('done',result))
        except Exception as exc:
            message=str(exc)
            for _,credentials in jobs:
                for field in ('password','secret'):
                    if credentials[field]: message=message.replace(credentials[field],'[oculto]')
            if isinstance(exc,ImportError): message+='\nInstale requirements.txt com o mesmo Python usado para abrir a interface.'
            self.events.put(('error',message))

    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='progress':
                    self.progress.configure(value=value['completed'],maximum=max(1,value['total']))
                    self.status.set(value['message']); self.log.configure(state='normal'); self.log.insert('end',value['message']+'\n'); self.log.see('end'); self.log.configure(state='disabled')
                else:
                    self.running=False; self.start_button.configure(state='normal')
                    if kind=='error':
                        self.status.set('Mapeamento não concluído.'); self.summary.set(value); messagebox.showerror('Erro no mapeamento',value)
                    else: self.show_result(value)
        except queue.Empty: pass
        self.poll_id=self.root.after(100,self.poll)

    def show_result(self,result):
        self.last_path=Path(result['path']); tables=result['tables']
        for row in tables.get('Resumo',[]):
            self.results.insert('','end',values=[row.get('equipamento',''),row.get('status',''),row.get('interfaces_config',0),row.get('vlans_config',0),row.get('ocorrencias',0)],tags=('ok' if row.get('status')=='OK' else 'review',))
        self.summary.set(f"{len(tables.get('Resumo',[]))} switches • {len(tables.get('Ocorrencias',[]))} ocorrências. Confira as portas, VLANs, LLDP e falhas no Excel.")
        self.status.set('Excel salvo: '+str(self.last_path)); self.excel_button.configure(state='normal'); self.folder_button.configure(state='normal')

    def open_result(self,folder):
        if self.last_path: os.startfile(str(self.last_path.parent if folder else self.last_path))

    def close(self):
        if self.running: messagebox.showinfo('Mapeamento em andamento','Aguarde a conclusão antes de fechar.'); return
        self.root.after_cancel(self.poll_id); self.root.destroy()


def main():
    root=tk.Tk(); App(root); root.mainloop()


if __name__=='__main__': main()
