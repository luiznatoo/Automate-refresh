"""Interface local para descoberta FortiGate e localização de MACs."""
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
import localizar as motor
import rede

SW_FIELDS=[('nome','Nome'),('host','IP / DNS'),('plataforma','Plataforma'),('porta','Porta SSH'),('usuario','Usuário específico'),('password_env','Grupo de senha'),('secret_env','Grupo enable'),('key_file','Chave SSH opcional')]
FW_FIELDS=[('nome','Nome'),('host','IP / DNS do cluster'),('porta','Porta SSH'),('usuario','Usuário específico'),('password_env','Grupo de senha')]
MAC_FIELDS=[('nome','Nome do dispositivo'),('mac','MAC address'),('ip','IP opcional')]
SETTINGS={'modo':'integrado','usuario':'','timeout':'90','workers':'4','known_hosts':'','incluir_macs':False,'mesma_senha':True,'rapido':False}


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


def build_jobs(project,passwords):
    """Validate a snapshot, keeping credentials out of persistent project data."""
    settings=project['settings']; mode=settings['modo']
    if mode not in ('integrado','lista'): raise ValueError('Modo de coleta inválido')
    timeout=int(settings['timeout']); workers=int(settings['workers'])
    if not 5<=timeout<=600 or not 1<=workers<=16: raise ValueError('Tempo de espera: 5 a 600 segundos. Consultas simultâneas: 1 a 16.')
    known=settings['known_hosts'].strip()
    if known and not Path(known).is_file(): raise ValueError('Arquivo known_hosts não encontrado')
    switches=copy.deepcopy(project['switches']); firewalls=copy.deepcopy(project['firewalls']) if mode=='integrado' and not settings.get('rapido') else []
    if not switches: raise ValueError('Adicione pelo menos um switch em Equipamentos.')
    if mode=='integrado' and not settings.get('rapido') and not firewalls: raise ValueError('Adicione o FortiGate em Equipamentos.')
    targets=copy.deepcopy(project['macs']) if mode=='lista' or settings['incluir_macs'] else []
    if settings.get('rapido') and not targets: raise ValueError('Adicione os MACs que deseja pesquisar na aba MACs opcionais.')
    seen_macs=set()
    for row in targets:
        row['mac']=motor.mac(row['mac'])
        if row['mac'] in seen_macs: raise ValueError('MAC duplicado na lista: '+motor.display(row['mac']))
        seen_macs.add(row['mac'])
        if not row['nome']: row['nome']='Nome não informado'
    def password(group):
        key='SW_PASSWORD' if group=='FG_PASSWORD' and settings['mesma_senha'] else group
        value=passwords.get(key,'') or os.getenv(key,'')
        if not value: raise ValueError('Preencha a senha do grupo '+key+' em Acesso SSH.')
        return value
    jobs=[]; fw_jobs=[]
    for devices,is_fw in ((switches,False),(firewalls,True)):
        names=set(); endpoints=set()
        for row in devices:
            host=row['host'].strip(); name=row.get('nome','').strip() or host; row['nome']=name; port=int(row.get('porta') or 22)
            if not name or not host or not 1<=port<=65535: raise ValueError('Confira nome, IP/DNS e porta SSH dos equipamentos.')
            if name.casefold() in names or (host.casefold(),port) in endpoints: raise ValueError('Equipamento duplicado: '+name)
            names.add(name.casefold()); endpoints.add((host.casefold(),port))
            if not is_fw and row['plataforma'] not in ('cisco_ios','cisco_nxos','juniper_junos'): raise ValueError('Plataforma inválida: '+name)
            row['usuario']=row.get('usuario') or settings['usuario'].strip()
            if not row['usuario']: raise ValueError('Informe o usuário SSH para '+name)
            row['porta']=port
            pw='' if row.get('key_file') and not is_fw else password(row.get('password_env') or ('FG_PASSWORD' if is_fw else 'SW_PASSWORD'))
            if is_fw: fw_jobs.append((row,pw))
            else: jobs.append((row,pw,password(row['secret_env']) if row.get('secret_env') else ''))
    return jobs,fw_jobs,targets,SimpleNamespace(modo=mode,timeout=timeout,workers=workers,known_hosts=Path(known) if known else None,rapido=settings.get('rapido',False))


class Inventory:
    def __init__(self,parent,fields,defaults,changed):
        self.fields=fields; self.defaults=defaults; self.changed=changed
        frame=ttk.Frame(parent); frame.pack(fill='both',expand=True)
        self.table=ttk.Treeview(frame,columns=[k for k,_ in fields],show='headings',selectmode='extended',height=10)
        basic={'nome','host','plataforma','mac','ip'}
        self.table.configure(displaycolumns=[k for k,_ in fields if k in basic])
        for key,label in fields:
            self.table.heading(key,text=label); self.table.column(key,width=145,minwidth=95)
        self.table.grid(row=0,column=0,sticky='nsew')
        vertical=ttk.Scrollbar(frame,orient='vertical',command=self.table.yview); vertical.grid(row=0,column=1,sticky='ns')
        horizontal=ttk.Scrollbar(frame,orient='horizontal',command=self.table.xview); horizontal.grid(row=1,column=0,sticky='ew')
        self.table.configure(yscrollcommand=vertical.set,xscrollcommand=horizontal.set)
        frame.rowconfigure(0,weight=1); frame.columnconfigure(0,weight=1)
        form=ttk.LabelFrame(parent,text='Adicionar ou editar item',padding=10); form.pack(fill='x',pady=10)
        self.vars={}; self.extra_widgets=[]
        ordered=[f for f in fields if f[0] in basic]+[f for f in fields if f[0] not in basic]
        for index,(key,label) in enumerate(ordered):
            row=index//3; col=(index%3)*2
            caption=ttk.Label(form,text=label+(' (opcional)' if key=='nome' else '')); caption.grid(row=row,column=col,sticky='w',padx=4,pady=5)
            var=tk.StringVar(value=defaults.get(key,'')); self.vars[key]=var
            entry=ttk.Combobox(form,textvariable=var,values=['juniper_junos','cisco_ios','cisco_nxos'],state='readonly',width=18) if key=='plataforma' else ttk.Entry(form,textvariable=var,width=18)
            entry.grid(row=row,column=col+1,sticky='ew',padx=4,pady=5); form.columnconfigure(col+1,weight=1)
            if key not in basic:
                self.extra_widgets.extend([caption,entry]); caption.grid_remove(); entry.grid_remove()
        if self.extra_widgets:
            self.advanced=tk.BooleanVar(value=False)
            ttk.Checkbutton(form,text='Acesso específico (opcional)',variable=self.advanced,command=self.toggle_extra).grid(row=10,column=0,columnspan=6,sticky='w')
        bar=ttk.Frame(parent)
        buttons=[]
        for label,callback in [('Adicionar',self.add),('Atualizar selecionado',self.update),('Remover selecionados',self.remove),('Limpar campos',self.clear),('Importar CSV',self.import_csv)]:
            buttons.append(ttk.Button(bar,text=label,command=callback))
        frame.pack_forget(); form.pack_forget()
        bar.pack(side='bottom',fill='x'); form.pack(side='bottom',fill='x',pady=10); frame.pack(fill='both',expand=True)
        arrange_buttons(bar,buttons)
        self.table.bind('<<TreeviewSelect>>',self.select)

    def toggle_extra(self):
        for widget in self.extra_widgets:
            widget.grid() if self.advanced.get() else widget.grid_remove()

    def rows(self): return [dict(zip((k for k,_ in self.fields),self.table.item(i,'values'))) for i in self.table.get_children()]
    def set_rows(self,rows):
        self.table.delete(*self.table.get_children())
        for row in rows: self.table.insert('','end',values=[row.get(k,self.defaults.get(k,'')) for k,_ in self.fields])
        self.clear(); self.changed()
    def values(self): return [self.vars[k].get().strip() for k,_ in self.fields]
    def add(self):
        values=self.values()
        if not any(values[index] for index,(key,_) in enumerate(self.fields) if key in ('nome','host','mac')): return
        self.table.insert('','end',values=values); self.clear(); self.changed()
    def update(self):
        selected=self.table.selection()
        if len(selected)!=1: messagebox.showinfo('Selecionar item','Selecione uma linha para atualizar.'); return
        self.table.item(selected[0],values=self.values()); self.changed()
    def remove(self):
        self.table.delete(*self.table.selection()); self.clear(); self.changed()
    def clear(self):
        for key,var in self.vars.items(): var.set(self.defaults.get(key,''))
    def select(self,*args):
        selected=self.table.selection()
        if len(selected)==1:
            for (key,_),value in zip(self.fields,self.table.item(selected[0],'values')): self.vars[key].set(value)
    def import_csv(self):
        path=filedialog.askopenfilename(filetypes=[('Inventário CSV','*.csv')])
        if not path: return
        try:
            required=['mac'] if 'mac' in self.vars else ['host']+(['plataforma'] if 'plataforma' in self.vars else [])
            if 'plataforma' in self.vars:
                from mapear import read_inventory
                rows=read_inventory(path)
            else:rows=motor.read_csv(path,required,allow_empty=True)
            if self.rows() and not messagebox.askyesno('Importar CSV','Substituir a lista desta aba pelo CSV selecionado?'): return
            self.set_rows(rows)
        except (ValueError,OSError) as exc: messagebox.showerror('Erro no CSV',str(exc))
    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension='.csv',filetypes=[('Inventário CSV','*.csv')])
        if not path: return
        try:
            with Path(path).open('w',encoding='utf-8-sig',newline='') as file:
                writer=csv.DictWriter(file,fieldnames=[k for k,_ in self.fields]); writer.writeheader(); writer.writerows(self.rows())
        except OSError as exc: messagebox.showerror('Erro ao salvar',str(exc))


class App:
    def __init__(self,root):
        self.root=root; self.events=queue.Queue(); self.running=False; self.last_path=None; self.credentials={}; self.editors={}
        root.title('Mapeamento de Rede')
        root.geometry(f'{min(1220,root.winfo_screenwidth()-60)}x{min(850,root.winfo_screenheight()-100)}'); root.minsize(900,560)
        root.columnconfigure(0,weight=1); root.rowconfigure(2,weight=1)
        ttk.Label(root,text='Descoberta e localização de dispositivos',font=('Segoe UI',18,'bold')).grid(row=0,column=0,sticky='w',padx=18,pady=(14,5))
        ttk.Label(root,text='FortiGate + switches por SSH • dispositivos e pendências no Excel').grid(row=1,column=0,sticky='w',padx=18)
        self.tabs=ttk.Notebook(root); self.tabs.grid(row=2,column=0,sticky='nsew',padx=18,pady=12)
        pages={name:ttk.Frame(self.tabs,padding=10) for name in ('Equipamentos','MACs opcionais','Resultados')}
        for name,frame in pages.items(): self.tabs.add(frame,text=name)
        self.pages=pages; self.settings={k:(tk.BooleanVar(value=v) if isinstance(v,bool) else tk.StringVar(value=v)) for k,v in SETTINGS.items()}
        panel=pages['Equipamentos']
        access=ttk.LabelFrame(panel,text='Acesso SSH — reutilizado até fechar',padding=8); access.pack(side='bottom',fill='x',pady=6)
        ttk.Label(access,text='Usuário').grid(row=0,column=0,sticky='w')
        ttk.Entry(access,textvariable=self.settings['usuario']).grid(row=0,column=1,sticky='ew',padx=8)
        ttk.Checkbutton(access,text='Mesma senha no FortiGate e switches',variable=self.settings['mesma_senha']).grid(row=0,column=2,sticky='w')
        self.auth_body=ttk.Frame(access); self.auth_body.grid(row=1,column=0,columnspan=3,sticky='ew'); self.auth_body.columnconfigure(1,weight=1)
        access.columnconfigure(1,weight=1)
        ttk.Label(panel,text='Adicione os switches. O FortiGate é opcional para descobrir IPs e nomes. Sem FortiGate, informe os MACs na próxima aba.',wraplength=1000).pack(anchor='w',pady=5)
        equipment=ttk.Notebook(panel);equipment.pack(fill='both',expand=True)
        for key,title,fields,defaults in [
            ('switches','Switches',SW_FIELDS,{'porta':'22','plataforma':'juniper_junos','password_env':'SW_PASSWORD'}),
            ('firewalls','FortiGate (opcional)',FW_FIELDS,{'porta':'22','password_env':'FG_PASSWORD'})]:
            page=ttk.Frame(equipment,padding=6);equipment.add(page,text=title)
            self.editors[key]=Inventory(page,fields,defaults,self.refresh_credentials)
        ttk.Label(pages['MACs opcionais'],text='Informe somente os MACs que deseja acrescentar. Nome e IP são opcionais. Com FortiGate, a descoberta é automática.',wraplength=1000).pack(anchor='w')
        self.editors['macs']=Inventory(pages['MACs opcionais'],MAC_FIELDS,{},self.refresh_credentials)
        self.options=tk.Toplevel(root);self.options.title('Opções de conexão');self.options.withdraw();self.options.protocol('WM_DELETE_WINDOW',self.options.withdraw)
        for i,(key,label) in enumerate([('timeout','Tempo de espera (s)'),('workers','Consultas simultâneas'),('known_hosts','Arquivo known_hosts (opcional)')]):
            ttk.Label(self.options,text=label).grid(row=i,column=0,padx=10,pady=8,sticky='w')
            ttk.Entry(self.options,textvariable=self.settings[key],width=45).grid(row=i,column=1,padx=10,pady=8)
        ttk.Button(self.options,text='Selecionar known_hosts',command=self.pick_known_hosts).grid(row=3,column=1,pady=8)
        result=pages['Resultados']
        self.summary=tk.StringVar(value='Nenhuma coleta executada nesta sessão.')
        ttk.Label(result,textvariable=self.summary,wraplength=1050).pack(anchor='w',pady=5)
        self.progress=ttk.Progressbar(result,mode='determinate'); self.progress.pack(fill='x',pady=8)
        columns=('mac','ip','switch','port','status')
        result_grid=ttk.Frame(result); result_grid.pack(fill='both',expand=True)
        self.results=ttk.Treeview(result_grid,columns=columns,show='headings',height=9)
        for key,title,width in zip(columns,['MAC','IP','Switch','Porta','Resultado'],[150,130,160,160,420]):
            self.results.heading(key,text=title); self.results.column(key,width=width,minwidth=90)
        self.results.grid(row=0,column=0,sticky='nsew')
        result_scroll=ttk.Scrollbar(result_grid,orient='vertical',command=self.results.yview); result_scroll.grid(row=0,column=1,sticky='ns')
        result_horizontal=ttk.Scrollbar(result_grid,orient='horizontal',command=self.results.xview); result_horizontal.grid(row=1,column=0,sticky='ew')
        self.results.configure(yscrollcommand=result_scroll.set,xscrollcommand=result_horizontal.set)
        result_grid.rowconfigure(0,weight=1); result_grid.columnconfigure(0,weight=1)
        self.results.tag_configure('review',foreground='#9A3412'); self.results.tag_configure('found',foreground='#166534')

        self.details=tk.Toplevel(root);self.details.title('Detalhes da coleta');self.details.withdraw();self.details.protocol('WM_DELETE_WINDOW',self.details.withdraw)
        log_frame=ttk.Frame(self.details); log_frame.pack(fill='both',expand=True)
        ttk.Button(result,text='Detalhes da coleta',command=self.details.deiconify).pack(anchor='w')
        self.log=tk.Text(log_frame,height=7,wrap='word',state='disabled',font=('Consolas',10)); self.log.pack(side='left',fill='both',expand=True)
        log_scroll=ttk.Scrollbar(log_frame,orient='vertical',command=self.log.yview); log_scroll.pack(side='right',fill='y'); self.log.configure(yscrollcommand=log_scroll.set)
        self.status=tk.StringVar(value='Adicione switches, informe o acesso SSH e clique em Iniciar coleta.')
        status_label=ttk.Label(root,textvariable=self.status,wraplength=850)
        status_label.grid(row=3,column=0,sticky='ew',padx=18)
        status_label.bind('<Configure>',lambda e:status_label.configure(wraplength=max(100,e.width)))
        bar=ttk.Frame(root); bar.grid(row=4,column=0,sticky='ew',padx=18,pady=(4,10))
        open_button=ttk.Button(bar,text='Abrir projeto',command=lambda:self.safe(self.load_project))
        save_button=ttk.Button(bar,text='Salvar projeto',command=lambda:self.safe(self.save_project))
        self.start_button=ttk.Button(bar,text='Iniciar coleta',command=lambda:self.safe(self.start))
        self.excel_button=ttk.Button(bar,text='Abrir Excel',command=lambda:self.safe(lambda:self.open_result(False)),state='disabled')
        self.folder_button=ttk.Button(bar,text='Abrir pasta do resultado',command=lambda:self.safe(lambda:self.open_result(True)),state='disabled')
        arrange_buttons(bar,[self.start_button,self.excel_button,open_button,save_button,ttk.Button(bar,text='Opções',command=self.options.deiconify)])
        self.settings['modo'].trace_add('write',lambda *args:self.refresh_credentials())
        self.settings['mesma_senha'].trace_add('write',lambda *args:self.refresh_credentials())
        self.load_initial(); self.refresh_credentials()
        self.poll_id=root.after(100,self.poll); root.protocol('WM_DELETE_WINDOW',self.close)

        from refresh_core.inventory import preload
        preload(self,'localizador-mac')

    def refresh_credentials(self):
        if not hasattr(self,'auth_body'): return
        groups=set()
        for key,editor in self.editors.items():
            if key=='macs' or (key=='firewalls' and not editor.rows()): continue
            for row in editor.rows():
                if not row.get('key_file'):groups.add(row.get('password_env') or ('FG_PASSWORD' if key=='firewalls' else 'SW_PASSWORD'))
                if row.get('secret_env'): groups.add(row['secret_env'])
        groups.add('SW_PASSWORD')
        if self.editors.get('firewalls') and self.editors['firewalls'].rows(): groups.add('FG_PASSWORD')
        if self.settings['mesma_senha'].get(): groups.discard('FG_PASSWORD')
        for child in self.auth_body.winfo_children(): child.destroy()
        for index,group in enumerate(sorted(groups)):
            if getattr(self,'simple_layout',False) and group=='SW_PASSWORD': continue
            if group not in self.credentials: self.credentials[group]=tk.StringVar()
            label={'SW_PASSWORD':'Senha dos switches','FG_PASSWORD':'Senha do FortiGate'}.get(group,'Senha / enable')
            ttk.Label(self.auth_body,text=label+(' ('+group+')' if group not in ('SW_PASSWORD','FG_PASSWORD') else '')).grid(row=index,column=0,sticky='w',padx=5,pady=6)
            ttk.Entry(self.auth_body,textvariable=self.credentials[group],show='•').grid(row=index,column=1,sticky='ew',padx=5,pady=6)

    def project(self):
        self.settings['modo'].set('integrado' if self.editors['firewalls'].rows() else 'lista')
        self.settings['incluir_macs'].set(bool(self.editors['macs'].rows()))
        return {'schema':1,'settings':{k:v.get() for k,v in self.settings.items()},**{k:e.rows() for k,e in self.editors.items()}}

    def apply_project(self,data):
        if isinstance(data,dict) and data.get('tipo')=='mapeamento-switches':
            data={'schema':1,'settings':{**SETTINGS,**{k:v for k,v in data.get('settings',{}).items() if k in SETTINGS}},'switches':data.get('switches',[]),'firewalls':self.editors['firewalls'].rows(),'macs':self.editors['macs'].rows()}
        if not isinstance(data,dict) or data.get('schema')!=1 or not isinstance(data.get('settings',{}),dict): raise ValueError('Formato de projeto não reconhecido')
        settings={**SETTINGS,**{k:v for k,v in data.get('settings',{}).items() if k in SETTINGS}}
        for key,default in SETTINGS.items():
            if isinstance(default,bool):
                if not isinstance(settings[key],bool): raise ValueError('Opção inválida no projeto: '+key)
            elif not isinstance(settings[key],(str,int)): raise ValueError('Campo inválido no projeto: '+key)
            else: settings[key]=str(settings[key])
        if settings['modo'] not in ('integrado','lista'): raise ValueError('Modo inválido no projeto')
        for key in ('switches','firewalls','macs'):
            if not isinstance(data.get(key),list) or any(not isinstance(row,dict) or any(not isinstance(v,(str,int)) for v in row.values()) for row in data[key]): raise ValueError('Lista inválida no projeto: '+key)
        for key,var in self.settings.items(): var.set(settings[key])
        for key,editor in self.editors.items(): editor.set_rows(data[key])

    def load_initial(self):
        path=motor.BASE/'projeto_coleta.json'
        try:
            if path.exists(): self.apply_project(json.loads(path.read_text(encoding='utf-8-sig')))
            else:
                for key in self.editors:
                    source=motor.BASE/(key+'.csv')
                    if source.exists(): self.editors[key].set_rows(motor.read_csv(source,['nome'],allow_empty=True))
            legacy=motor.BASE/'inventario_portas.csv'
            if not self.editors['switches'].rows() and legacy.exists():
                from mapear import read_inventory
                self.editors['switches'].set_rows(read_inventory(legacy))
        except (ValueError,OSError,TypeError) as exc: self.status.set('Cadastro não carregado: '+str(exc))

    def save_project(self):
        path=filedialog.asksaveasfilename(initialdir=motor.BASE,initialfile='projeto_coleta.json',defaultextension='.json',filetypes=[('Projeto','*.json')])
        if path:
            Path(path).write_text(json.dumps(self.project(),ensure_ascii=False,indent=2),encoding='utf-8')
            self.status.set('Projeto salvo sem senhas: '+path)

    def load_project(self):
        path=filedialog.askopenfilename(filetypes=[('Projeto','*.json')])
        if path:
            self.apply_project(json.loads(Path(path).read_text(encoding='utf-8-sig'))); self.status.set('Projeto carregado. Preencha as senhas desta sessão.')

    def pick_known_hosts(self):
        path=filedialog.askopenfilename(title='Arquivo known_hosts')
        if path: self.settings['known_hosts'].set(path)

    def safe(self,fn):
        try: fn()
        except (ValueError,OSError,TypeError,KeyError,ImportError) as exc: messagebox.showerror('Verifique os dados',str(exc))

    def start(self):
        if self.running: return
        passwords={k:v.get() for k,v in self.credentials.items()}
        jobs,fw_jobs,targets,args=build_jobs(self.project(),passwords)
        self.running=True; self.start_button.configure(state='disabled'); self.last_path=None
        self.excel_button.configure(state='disabled'); self.folder_button.configure(state='disabled')
        self.results.delete(*self.results.get_children()); self.log.configure(state='normal'); self.log.delete('1.0','end'); self.log.configure(state='disabled')
        self.progress.configure(value=0,maximum=len(jobs)+len(fw_jobs))
        self.summary.set('Coleta em andamento. Aguarde as consultas e a geração do Excel.'); self.status.set('Consultando equipamentos…')
        self.tabs.select(self.pages['Resultados'])
        threading.Thread(target=self.worker,args=(jobs,fw_jobs,targets,args),daemon=True).start()

    def worker(self,jobs,fw_jobs,targets,args):
        try:
            import netmiko,openpyxl,paramiko
            result=rede.run_collection(jobs,fw_jobs,targets,args,on_event=lambda e:self.events.put(('progress',e)))
            self.events.put(('done',result))
        except Exception as exc:
            message=str(exc)
            for job in jobs+fw_jobs:
                for secret in job[1:]:
                    if secret: message=message.replace(secret,'[oculto]')
            if isinstance(exc,ImportError): message+='\nInstale as dependências de requirements.txt usando o mesmo Python que abre esta janela.'
            self.events.put(('error',message))

    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='progress':
                    self.progress.configure(value=value['completed'],maximum=max(1,value['total']))
                    self.log.configure(state='normal'); self.log.insert('end',value['message']+'\n'); self.log.see('end'); self.log.configure(state='disabled')
                    self.status.set(value['message'])
                else:
                    self.running=False; self.start_button.configure(state='normal')
                    if kind=='error':
                        self.status.set('Coleta não concluída.'); self.summary.set(value); messagebox.showerror('Erro na coleta',value)
                    else: self.show_result(value)
        except queue.Empty: pass
        self.poll_id=self.root.after(100,self.poll)

    def show_result(self,result):
        self.last_path=Path(result['path']); tables=result['tables']; rows=tables['Localização']
        useful=motor.useful_rows(tables)
        for row in useful[:500]:
            self.results.insert('','end',values=[row['MAC'],row['IP'],row['Switch'],row['Porta'],row['Resultado']],tags=('review' if row['Resultado']!='Localizado' else 'found',))
        pending=sum(r['Resultado']!='Localizado' for r in useful)
        self.summary.set(f"{len(rows)} dispositivos • {pending} a revisar. "+('Há consultas com falha: consulte Pendências no Excel. ' if result['code'] else '')+'Prévia de até 500 registros.')
        self.status.set('Excel salvo: '+str(self.last_path)); self.excel_button.configure(state='normal'); self.folder_button.configure(state='normal')

    def open_result(self,folder):
        if self.last_path: os.startfile(str(self.last_path.parent if folder else self.last_path))

    def close(self):
        if self.running:
            messagebox.showinfo('Coleta em andamento','Aguarde a conclusão das consultas antes de fechar a janela.'); return
        self.root.after_cancel(self.poll_id); self.root.destroy()



class SimpleApp(App):
    """One screen for daily collection; legacy inventory preserves imported overrides."""
    def __init__(self,root):
        super().__init__(root)
        self.simple_layout=True
        for widget in root.winfo_children():
            if not isinstance(widget,tk.Toplevel):widget.grid_remove()
        root.geometry(f'{min(780,root.winfo_screenwidth()-60)}x{min(680,root.winfo_screenheight()-100)}');root.minsize(650,560)
        root.rowconfigure(2,weight=0);root.rowconfigure(0,weight=1)
        page=ttk.Frame(root,padding=20);page.grid(row=0,column=0,sticky='nsew');page.columnconfigure(0,weight=1)
        ttk.Label(page,text='Mapeamento de Rede',font=('Segoe UI',18,'bold')).grid(row=0,column=0,sticky='w',pady=(0,12))
        toolbar=ttk.Frame(page);toolbar.grid(row=1,column=0,sticky='ew',pady=(0,6))
        buttons=[]
        for label,action in [('Adicionar firewall',lambda:self.open_device('firewalls')),('Adicionar switch',lambda:self.open_device('switches')),('Editar',self.edit_device),('Remover',self.remove_devices),('Importar CSV',self.choose_import)]:
            buttons.append(ttk.Button(toolbar,text=label,command=lambda f=action:self.safe(f)))
        arrange_buttons(toolbar,buttons)
        grid=ttk.Frame(page);grid.grid(row=2,column=0,sticky='nsew',pady=(0,12));grid.columnconfigure(0,weight=1);grid.rowconfigure(0,weight=1);page.rowconfigure(2,weight=1)
        self.device_table=ttk.Treeview(grid,columns=('tipo','nome','host'),show='headings',height=8,selectmode='extended')
        for key,label,width in [('tipo','Tipo',120),('nome','Hostname',220),('host','IP / DNS',210)]:
            self.device_table.heading(key,text=label);self.device_table.column(key,width=width,minwidth=90)
        self.device_table.grid(row=0,column=0,sticky='nsew')
        scroll=ttk.Scrollbar(grid,orient='vertical',command=self.device_table.yview);scroll.grid(row=0,column=1,sticky='ns');self.device_table.configure(yscrollcommand=scroll.set)
        self.device_table.bind('<Double-1>',lambda e:self.safe(self.edit_device))
        self.platform_map={'Juniper':'juniper_junos','Cisco IOS':'cisco_ios','Cisco Nexus':'cisco_nxos'}
        auth=ttk.Frame(page);auth.grid(row=6,column=0,sticky='ew');auth.columnconfigure(1,weight=1);auth.columnconfigure(3,weight=1)
        ttk.Label(auth,text='Usuário').grid(row=0,column=0)
        ttk.Entry(auth,textvariable=self.settings['usuario']).grid(row=0,column=1,sticky='ew',padx=(8,15))
        ttk.Label(auth,text='Senha').grid(row=0,column=2)
        self.credentials.setdefault('SW_PASSWORD',tk.StringVar())
        ttk.Entry(auth,textvariable=self.credentials['SW_PASSWORD'],show='•').grid(row=0,column=3,sticky='ew',padx=(8,0))
        ttk.Label(page,text='A senha fica somente nesta sessão.').grid(row=7,column=0,sticky='w',pady=(4,12))
        self.mac_window=tk.Toplevel(root);self.mac_window.title('MACs opcionais');self.mac_window.withdraw();self.mac_window.protocol('WM_DELETE_WINDOW',self.mac_window.withdraw)
        ttk.Label(self.mac_window,text='Cole MACs para acrescentar ao mapeamento ou pesquisar no modo rápido.').pack(padx=15,pady=10)
        self.mac_text=tk.Text(self.mac_window,height=12,width=55);self.mac_text.pack(fill='both',expand=True,padx=15)
        ttk.Checkbutton(self.mac_window,text='Somente localizar estes MACs (consulta rápida)',variable=self.settings['rapido']).pack(anchor='w',padx=15,pady=8)
        ttk.Button(self.mac_window,text='Pronto',command=self.mac_window.withdraw).pack(pady=10)
        actions=ttk.Frame(page);actions.grid(row=8,column=0,sticky='ew')
        self.start_button=ttk.Button(actions,text='Mapear rede',command=lambda:self.safe(self.start));self.start_button.pack(side='left')
        self.excel_button=ttk.Button(actions,text='Abrir Excel',state='disabled',command=lambda:self.safe(lambda:self.open_result(False)));self.excel_button.pack(side='left',padx=8)
        ttk.Button(actions,text='MACs opcionais',command=self.mac_window.deiconify).pack(side='left',padx=4)
        ttk.Button(actions,text='Opções',command=self.options.deiconify).pack(side='right')
        self.progress=ttk.Progressbar(page,mode='determinate');self.progress.grid(row=9,column=0,sticky='ew',pady=(15,6))
        ttk.Label(page,textvariable=self.status,wraplength=690).grid(row=10,column=0,sticky='w')
        ttk.Label(page,textvariable=self.summary,wraplength=690).grid(row=11,column=0,sticky='w',pady=6)
        ttk.Checkbutton(self.options,text='Mesma senha no firewall e switches',variable=self.settings['mesma_senha']).grid(row=4,column=0,columnspan=2,sticky='w',padx=10)
        self.auth_body=ttk.Frame(self.options);self.auth_body.grid(row=5,column=0,columnspan=2,sticky='ew');self.auth_body.columnconfigure(1,weight=1)
        for i,(label,fn) in enumerate([('Abrir cadastro',self.load_project),('Salvar cadastro',self.save_project),('Detalhes da coleta',self.details.deiconify)]):
            ttk.Button(self.options,text=label,command=lambda f=fn:self.safe(f)).grid(row=6+i,column=0,columnspan=2,pady=5)
        self.fill_simple();self.refresh_credentials()
        self.status.set('Informe os equipamentos e clique em Mapear rede.')

    def fill_simple(self):
        if not hasattr(self,'device_table') or not hasattr(self,'mac_text'):return
        self.device_table.delete(*self.device_table.get_children())
        for key in ('firewalls','switches'):
            for i,row in enumerate(self.editors[key].rows()):
                kind='FortiGate' if key=='firewalls' else next((label for label,value in self.platform_map.items() if value==row.get('plataforma')),row.get('plataforma','Switch'))
                self.device_table.insert('','end',iid=f'{key}:{i}',values=[kind,row['nome'] or row['host'],row['host']])
        self.mac_text.delete('1.0','end');self.mac_text.insert('1.0','\n'.join(r['mac'] for r in self.editors['macs'].rows()))

    def save_device(self,key,row,index=None):
        if self.running:return
        row=dict(row);row['host']=row.get('host','').strip();row['nome']=row.get('nome','').strip() or row['host']
        if not row['host'] or any(c.isspace() for c in row['host']):raise ValueError('Informe um IP ou DNS válido, sem espaços.')
        rows=self.editors[key].rows()
        if any(i!=index and r['host'].casefold()==row['host'].casefold() and str(r.get('porta') or 22)==str(row.get('porta') or 22) for i,r in enumerate(rows)):raise ValueError('Este equipamento já está na lista.')
        if any(i!=index and r['nome'].casefold()==row['nome'].casefold() for i,r in enumerate(rows)):raise ValueError('Hostname já cadastrado nesta lista.')
        if index is None:rows.append(row)
        else:rows[index]=row
        self.project();self.editors[key].set_rows(rows);self.fill_simple()

    def open_device(self,key,index=None):
        if self.running:return
        current=self.editors[key].rows()[index] if index is not None else {}
        win=tk.Toplevel(self.root);win.title(('Editar ' if index is not None else 'Adicionar ')+('firewall' if key=='firewalls' else 'switch'));win.transient(self.root);win.grab_set();win.resizable(False,False)
        body=ttk.Frame(win,padding=18);body.pack(fill='both',expand=True)
        values={k:tk.StringVar(value=current.get(k,'')) for k in ('nome','host')}
        for i,(keyfield,label) in enumerate([('nome','Hostname (opcional)'),('host','IP / DNS')]):
            ttk.Label(body,text=label).grid(row=i*2,column=0,sticky='w',pady=(6,2))
            ttk.Entry(body,textvariable=values[keyfield],width=42).grid(row=i*2+1,column=0,sticky='ew')
        platform=tk.StringVar(value=next((label for label,value in self.platform_map.items() if value==current.get('plataforma')),'Juniper'))
        if key=='switches':
            ttk.Label(body,text='Tipo do switch').grid(row=4,column=0,sticky='w',pady=(8,2))
            ttk.Combobox(body,textvariable=platform,values=list(self.platform_map),state='readonly',width=39).grid(row=5,column=0,sticky='ew')
        def save():
            try:
                row={**current,**{k:v.get() for k,v in values.items()}}
                if key=='switches':row['plataforma']=self.platform_map[platform.get()]
                self.save_device(key,row,index);win.destroy()
            except ValueError as exc:messagebox.showerror('Cadastro',str(exc),parent=win)
        ttk.Button(body,text='Salvar' if index is not None else 'Adicionar',command=save).grid(row=6,column=0,sticky='e',pady=(14,0))

    def edit_device(self):
        selected=self.device_table.selection()
        if len(selected)!=1:messagebox.showinfo('Cadastro','Selecione um equipamento para editar.');return
        key,index=selected[0].split(':');self.open_device(key,int(index))

    def remove_devices(self):
        if self.running:return
        selected=set(self.device_table.selection());self.project()
        for key in ('switches','firewalls'):
            self.editors[key].set_rows([r for i,r in enumerate(self.editors[key].rows()) if f'{key}:{i}' not in selected])
        self.fill_simple()

    def choose_import(self):
        if self.running:return
        win=tk.Toplevel(self.root);win.title('Importar CSV');win.transient(self.root);win.grab_set()
        for key,label in [('firewalls','Firewalls'),('switches','Switches')]:
            ttk.Button(win,text=label,command=lambda k=key:(win.destroy(),self.safe(lambda:self.import_devices(k)))).pack(padx=20,pady=10,fill='x')

    def import_devices(self,key):
        self.project();self.editors[key].import_csv();self.fill_simple()

    def apply_project(self,data):
        super().apply_project(data);self.fill_simple()

    def project(self):
        if hasattr(self,'mac_text'):
            old={motor.mac(r['mac']):r for r in self.editors['macs'].rows() if r.get('mac')}
            addresses=[motor.mac(a.strip()) for a in self.mac_text.get('1.0','end').splitlines() if a.strip()]
            self.editors['macs'].set_rows([old.get(a,{'mac':a,'nome':'','ip':''}) for a in addresses])
        return super().project()

    def start(self):
        if self.running:return
        # Sync visible inputs before collecting credentials for newly imported groups.
        self.project()
        super().start()


App=SimpleApp

def main():
    root=tk.Tk(); SimpleApp(root); root.mainloop()


if __name__=='__main__': main()
