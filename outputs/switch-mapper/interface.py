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
    def __init__(self,parent,fields,defaults,changed):
        self.fields=fields; self.defaults=defaults; self.changed=changed
        frame=ttk.Frame(parent); frame.pack(fill='both',expand=True)
        self.table=ttk.Treeview(frame,columns=[k for k,_ in fields],show='headings',selectmode='extended',height=10)
        for key,label in fields:
            self.table.heading(key,text=label); self.table.column(key,width=145,minwidth=95)
        self.table.grid(row=0,column=0,sticky='nsew')
        vertical=ttk.Scrollbar(frame,orient='vertical',command=self.table.yview); vertical.grid(row=0,column=1,sticky='ns')
        horizontal=ttk.Scrollbar(frame,orient='horizontal',command=self.table.xview); horizontal.grid(row=1,column=0,sticky='ew')
        self.table.configure(yscrollcommand=vertical.set,xscrollcommand=horizontal.set)
        frame.rowconfigure(0,weight=1); frame.columnconfigure(0,weight=1)
        form=ttk.LabelFrame(parent,text='Adicionar ou editar item',padding=10); form.pack(fill='x',pady=10)
        self.vars={}
        for index,(key,label) in enumerate(fields):
            row=index//3; col=(index%3)*2
            ttk.Label(form,text=label).grid(row=row,column=col,sticky='w',padx=4,pady=5)
            var=tk.StringVar(value=defaults.get(key,'')); self.vars[key]=var
            entry=ttk.Combobox(form,textvariable=var,values=['juniper_junos','cisco_ios','cisco_nxos'],state='readonly',width=18) if key=='plataforma' else ttk.Entry(form,textvariable=var,width=18)
            entry.grid(row=row,column=col+1,sticky='ew',padx=4,pady=5); form.columnconfigure(col+1,weight=1)
        bar=ttk.Frame(parent)
        buttons=[]
        for label,callback in [('Adicionar',self.add),('Atualizar selecionado',self.update),('Remover selecionados',self.remove),('Limpar campos',self.clear),('Importar CSV',self.import_csv),('Exportar CSV',self.export_csv)]:
            buttons.append(ttk.Button(bar,text=label,command=callback))
        frame.pack_forget(); form.pack_forget()
        bar.pack(side='bottom',fill='x'); form.pack(side='bottom',fill='x',pady=10); frame.pack(fill='both',expand=True)
        arrange_buttons(bar,buttons)
        self.table.bind('<<TreeviewSelect>>',self.select)

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
            required=['nome','mac'] if 'mac' in self.vars else ['nome','host']+(['plataforma'] if 'plataforma' in self.vars else [])
            rows=motor.read_inventory(path)
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


def build_jobs(project,passwords):
    settings=project['settings']; devices=copy.deepcopy(project['switches'])
    timeout=int(settings['timeout']); workers=int(settings['workers'])
    if not 1<=workers<=32 or not 1<=timeout<=600: raise ValueError('Use 1 a 32 switches simultâneos e tempo de espera de 1 a 600 segundos.')
    known=settings['known_hosts'].strip()
    if known and not Path(known).is_file(): raise ValueError('Arquivo known_hosts não encontrado.')
    if not devices: raise ValueError('Adicione os switches na aba Switches.')
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
        root.title('Mapeamento de portas • Cisco e Juniper')
        root.geometry(f'{min(1220,root.winfo_screenwidth()-60)}x{min(850,root.winfo_screenheight()-100)}'); root.minsize(900,560)
        root.columnconfigure(0,weight=1); root.rowconfigure(2,weight=1)
        ttk.Label(root,text='Mapeamento de portas dos switches',font=('Segoe UI',18,'bold')).grid(row=0,column=0,sticky='w',padx=18,pady=(14,5))
        ttk.Label(root,text='Interfaces, VLANs, trunks, agregações e LLDP • relatório no modelo Excel fixo').grid(row=1,column=0,sticky='w',padx=18)
        self.tabs=ttk.Notebook(root); self.tabs.grid(row=2,column=0,sticky='nsew',padx=18,pady=12)
        self.pages={name:ttk.Frame(self.tabs,padding=12) for name in ('Coleta','Switches','Resultados')}
        for index,(name,page) in enumerate(self.pages.items(),1): self.tabs.add(page,text=f'{index}. {name}')
        self.settings={key:(tk.BooleanVar(value=value) if isinstance(value,bool) else tk.StringVar(value=value)) for key,value in SETTINGS.items()}
        page=self.pages['Coleta']; config=ttk.LabelFrame(page,text='Opções da coleta',padding=12); config.pack(fill='x')
        for row,(key,label) in enumerate([('usuario','Usuário SSH padrão'),('timeout','Tempo de espera (segundos)'),('workers','Switches simultâneos'),('known_hosts','Arquivo known_hosts (opcional)')]):
            ttk.Label(config,text=label).grid(row=row,column=0,sticky='w',padx=5,pady=6)
            ttk.Entry(config,textvariable=self.settings[key]).grid(row=row,column=1,sticky='ew',padx=5,pady=6)
        config.columnconfigure(1,weight=1)
        ttk.Button(config,text='Procurar',command=self.pick_known_hosts).grid(row=3,column=2,padx=5)
        ttk.Checkbutton(config,text='Salvar também diagnóstico JSON com respostas operacionais',variable=self.settings['diagnostico']).grid(row=4,column=0,columnspan=3,sticky='w',pady=8)
        ttk.Label(page,text='O mapeamento completo inclui portas de acesso e trunk. Senhas ficam somente nesta sessão; o projeto guarda os cadastros e opções.',wraplength=850).pack(anchor='w',pady=10)
        auth=ttk.LabelFrame(page,text='Senhas da sessão',padding=10); auth.pack(fill='both',expand=True)
        canvas=tk.Canvas(auth,highlightthickness=0); scroll=ttk.Scrollbar(auth,orient='vertical',command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set); scroll.pack(side='right',fill='y'); canvas.pack(fill='both',expand=True)
        self.auth_body=ttk.Frame(canvas); window=canvas.create_window((0,0),window=self.auth_body,anchor='nw'); self.auth_body.columnconfigure(1,weight=1)
        self.auth_body.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(window,width=e.width))
        page=self.pages['Switches']
        ttk.Label(page,text='Preencha e clique em Adicionar. Para editar, selecione uma linha e clique em Atualizar selecionado. Grupo enable e chave SSH são opcionais.',wraplength=1000).pack(anchor='w',pady=(0,10))
        self.inventory=Inventory(page,SW_FIELDS,{'porta':'22','plataforma':'juniper_junos','password_env':'SW_PASSWORD'},self.refresh_credentials)
        page=self.pages['Resultados']; self.summary=tk.StringVar(value='Nenhuma coleta executada nesta sessão.')
        ttk.Label(page,textvariable=self.summary,wraplength=950).pack(anchor='w',pady=5)
        self.progress=ttk.Progressbar(page,mode='determinate'); self.progress.pack(fill='x',pady=8)
        grid=ttk.Frame(page); grid.pack(fill='both',expand=True)
        columns=('switch','status','ports','vlans','issues')
        self.results=ttk.Treeview(grid,columns=columns,show='headings',height=8)
        for key,label,width in zip(columns,['Switch','Status','Interfaces na configuração','VLANs na configuração','Ocorrências'],[260,130,210,190,120]):
            self.results.heading(key,text=label); self.results.column(key,width=width,minwidth=100)
        self.results.grid(row=0,column=0,sticky='nsew'); grid.rowconfigure(0,weight=1); grid.columnconfigure(0,weight=1)
        vs=ttk.Scrollbar(grid,orient='vertical',command=self.results.yview); vs.grid(row=0,column=1,sticky='ns')
        hs=ttk.Scrollbar(grid,orient='horizontal',command=self.results.xview); hs.grid(row=1,column=0,sticky='ew')
        self.results.configure(yscrollcommand=vs.set,xscrollcommand=hs.set)
        self.results.tag_configure('review',foreground='#9A3412'); self.results.tag_configure('ok',foreground='#166534')
        ttk.Label(page,text='Andamento e falhas').pack(anchor='w',pady=(10,3))
        logs=ttk.Frame(page); logs.pack(fill='both',expand=True)
        self.log=tk.Text(logs,height=7,state='disabled',wrap='word',font=('Consolas',10)); self.log.pack(side='left',fill='both',expand=True)
        scroll=ttk.Scrollbar(logs,orient='vertical',command=self.log.yview); scroll.pack(side='right',fill='y'); self.log.configure(yscrollcommand=scroll.set)
        self.status=tk.StringVar(value='Confira os switches, informe as senhas e inicie o mapeamento.')
        label=ttk.Label(root,textvariable=self.status,wraplength=850); label.grid(row=3,column=0,sticky='ew',padx=18)
        label.bind('<Configure>',lambda e:label.configure(wraplength=max(100,e.width)))
        bar=ttk.Frame(root); bar.grid(row=4,column=0,sticky='ew',padx=18,pady=(4,10))
        open_button=ttk.Button(bar,text='Abrir projeto',command=lambda:self.safe(self.load_project))
        save_button=ttk.Button(bar,text='Salvar projeto',command=lambda:self.safe(self.save_project))
        self.start_button=ttk.Button(bar,text='Iniciar mapeamento',command=lambda:self.safe(self.start))
        self.excel_button=ttk.Button(bar,text='Abrir Excel',state='disabled',command=lambda:self.safe(lambda:self.open_result(False)))
        self.folder_button=ttk.Button(bar,text='Abrir pasta do resultado',state='disabled',command=lambda:self.safe(lambda:self.open_result(True)))
        arrange_buttons(bar,[open_button,save_button,self.start_button,self.excel_button,self.folder_button])
        self.load_initial(); self.refresh_credentials()
        self.poll_id=root.after(100,self.poll); root.protocol('WM_DELETE_WINDOW',self.close)

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
        for var in self.credentials.values(): var.set('')
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
            self.apply_project(json.loads(Path(path).read_text(encoding='utf-8-sig'))); self.status.set('Projeto carregado. Informe as senhas desta sessão.')

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
        self.status.set('Consultando switches…'); self.tabs.select(self.pages['Resultados'])
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
