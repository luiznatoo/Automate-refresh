"""Central desktop das ferramentas de refresh de rede."""
from pathlib import Path
from datetime import datetime
import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk,messagebox

import json
import uuid
import threading
import queue
from tkinter import filedialog
for core_parent in Path(__file__).resolve().parents:
    if (core_parent/'refresh_core').is_dir():
        sys.path.insert(0,str(core_parent));break
from refresh_core import VERSION
from refresh_core import inventory,storage
from refresh_core.registry_ui import Registry
from refresh_core.update import install,migrate

BASE=Path(__file__).resolve().parent
TOOLS=[
    ('fortigate-auditoria','Auditoria de Firewall','Somente leitura: versão, modelo, HA, BGP, VPNs e relatório Excel.','interface.py',False,'resultados'),
    ('fortigate-hardening','Hardening FortiGate','Controles de segurança, recomendações e correções mediante aprovação.','interface.py',False,'resultados'),
    ('switch-mapper','Mapeamento de portas','Interfaces, VLANs, trunks, agregações, LLDP e Excel.','interface.py',False,'relatorios'),
    ('localizador-mac','Localização de dispositivos','FortiGate + switches: IP, MAC e porta de acesso.','interface.py',False,'resultados'),
    ('fortigate-rdm','Pré e pós-RDM','Coleta e comparação de BGP, VPN, ARP, DHCP e HA. Assistente no terminal.','fortigate_rdm.py',True,'coletas'),
    ('fortigate-config','Gerador FortiGate','Bases 60F 7.4.9 e 40F 7.4.12, com prévia das alterações.','gerar.py',False,''),
    ('fortiswitch-config','Gerador FortiSwitch','Configuração standalone com a base 148E cadastrada.','gerar.py',False,''),
]


def tool_folder(identifier):
    if identifier not in {t[0] for t in TOOLS}: raise ValueError('Ferramenta desconhecida')
    bundled=BASE/'ferramentas'/identifier
    return bundled if bundled.is_dir() else BASE.parent/identifier


def launch_command(tool):
    identifier,_,_,script,console,_=tool
    folder=tool_folder(identifier); target=folder/script
    if not target.is_file(): raise FileNotFoundError('Ferramenta não encontrada: '+str(target))
    if getattr(sys,'frozen',False):
        executable=Path(sys.executable).parent/('AssistenteRDM.exe' if console else 'CentralRefresh.exe')
        if not executable.is_file(): raise FileNotFoundError('Executável não encontrado: '+str(executable))
        return [str(executable),'--tool',identifier],folder
    executable=Path(sys.executable)
    if console and executable.name.lower()=='pythonw.exe': executable=executable.with_name('python.exe')
    if not console and os.name=='nt' and executable.with_name('pythonw.exe').is_file(): executable=executable.with_name('pythonw.exe')
    return [str(executable),str(BASE/'launch.py'),str(target)],folder


class App:
    def __init__(self,root):
        self.root=root; self.running={}; self.messages={}; self.buttons={};self.update_events=queue.Queue();self.updating=False;self.session_credentials={}
        self.registry_path=BASE/'dados/cadastro.json';self.history_dir=BASE/'dados/historico'
        root.title('Central de Refresh')
        root.geometry(f'{min(1000,root.winfo_screenwidth()-60)}x{min(760,root.winfo_screenheight()-100)}');root.minsize(760,520)
        root.columnconfigure(0,weight=1);root.rowconfigure(1,weight=1)
        heading=ttk.Frame(root,padding=(22,18));heading.grid(row=0,column=0,sticky='ew');heading.columnconfigure(0,weight=1)
        ttk.Label(heading,text='Central de Refresh',font=('Segoe UI',22,'bold')).grid(row=0,column=0,sticky='w')
        ttk.Label(heading,text='Escolha o que deseja fazer.').grid(row=1,column=0,sticky='w',pady=(4,0))
        ttk.Button(heading,text='Opções',command=self.open_options).grid(row=0,column=1,rowspan=2)
        self.options=tk.Toplevel(root);self.options.title('Opções da Central');self.options.geometry('980x690');self.options.withdraw();self.options.protocol('WM_DELETE_WINDOW',self.options.withdraw)
        tabs=ttk.Notebook(self.options);tabs.pack(fill='both',expand=True,padx=12,pady=12);self.options_tabs=tabs
        setup=ttk.Frame(tabs,padding=18);tabs.add(setup,text='Equipamentos e acesso')
        ttk.Label(setup,text='Reutilizar um cadastro nas ferramentas',font=('Segoe UI',12,'bold')).grid(row=0,column=0,columnspan=2,sticky='w',pady=(0,10))
        ttk.Label(setup,text='Opcional. Use Cadastro local para cadastrar os equipamentos dentro de cada ferramenta.',wraplength=800).grid(row=1,column=0,columnspan=2,sticky='w',pady=(0,14))
        self.unit=tk.StringVar(value='Cadastro local');self.group=tk.StringVar(value='Todos os grupos')
        ttk.Label(setup,text='Unidade').grid(row=2,column=0,sticky='w',pady=6)
        self.unit_box=ttk.Combobox(setup,textvariable=self.unit,state='readonly',width=35);self.unit_box.grid(row=2,column=1,sticky='w',padx=12)
        ttk.Label(setup,text='Grupo de acesso').grid(row=3,column=0,sticky='w',pady=6)
        self.group_box=ttk.Combobox(setup,textvariable=self.group,state='readonly',width=35);self.group_box.grid(row=3,column=1,sticky='w',padx=12)
        ttk.Button(setup,text='Gerenciar equipamentos',command=lambda:self.safe(lambda:Registry(self.options,self.registry_path,self.refresh_registry))).grid(row=4,column=0,sticky='w',pady=15)
        ttk.Button(setup,text='Informar senhas da sessão',command=lambda:self.safe(self.credentials)).grid(row=4,column=1,sticky='w',padx=12)
        self.context=tk.StringVar();self.unit.trace_add('write',lambda *args:self.refresh_context());self.group.trace_add('write',lambda *args:self.refresh_context())
        self.refresh_registry();self.refresh_context()
        container=ttk.Frame(root);container.grid(row=1,column=0,sticky='nsew',padx=22)
        canvas=tk.Canvas(container,highlightthickness=0);scroll=ttk.Scrollbar(container,orient='vertical',command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');canvas.pack(side='left',fill='both',expand=True)
        body=ttk.Frame(canvas);window=canvas.create_window((0,0),window=body,anchor='nw');body.columnconfigure(0,weight=1)
        body.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(window,width=e.width))
        def wheel(event):canvas.yview_scroll(-1 if event.delta>0 else 1,'units')
        canvas.bind('<MouseWheel>',wheel)
        descriptions={'fortigate-auditoria':'Verificar o funcionamento dos firewalls.',
          'fortigate-hardening':'Verificar e corrigir os controles do seu script de segurança.',
          'switch-mapper':'Ver portas, VLANs e conexões dos switches.',
          'localizador-mac':'Encontrar o switch e a porta de um dispositivo.',
          'fortigate-rdm':'Comparar a rede antes e depois da mudança. Abre no terminal.',
          'fortigate-config':'Preparar configurações de firewall.',
          'fortiswitch-config':'Preparar configurações de switch.'}
        sections=[('Verificar a rede',TOOLS[:4]),('Comparar uma mudança',[TOOLS[4]]),('Gerar configurações',TOOLS[5:])]
        row=0
        for title,tools in sections:
            ttk.Label(body,text=title,font=('Segoe UI',11,'bold')).grid(row=row,column=0,sticky='w',pady=(10,5));row+=1
            for tool in tools:
                identifier,title,_,_,_,_=tool
                card=ttk.Frame(body,padding=(12,7));card.grid(row=row,column=0,sticky='ew',pady=2);card.columnconfigure(0,weight=1);row+=1
                ttk.Label(card,text=title,font=('Segoe UI',11,'bold')).grid(row=0,column=0,sticky='w')
                ttk.Label(card,text=descriptions[identifier],wraplength=510).grid(row=1,column=0,sticky='w',pady=(2,0))
                button=ttk.Button(card,text='Abrir',command=lambda t=tool:self.safe(lambda:self.launch(t)));button.grid(row=0,column=2,rowspan=2,padx=(10,0));self.buttons[identifier]=button
                message=tk.StringVar(value='' if (tool_folder(identifier)/tool[3]).is_file() else 'Indisponível');self.messages[identifier]=message
                ttk.Label(card,textvariable=message).grid(row=0,column=1,rowspan=2,padx=8)
                for widget in [card,*card.winfo_children()]:widget.bind('<MouseWheel>',wheel)
        self.history_page(tabs);self.history_tab=tabs.tabs()[-1]
        maintenance=ttk.Frame(tabs,padding=18);tabs.add(maintenance,text='Atualização')
        ttk.Label(maintenance,text='Central de Refresh '+VERSION,font=('Segoe UI',12,'bold')).pack(anchor='w',pady=(0,12))
        self.update_button=ttk.Button(maintenance,text='Instalar atualização ZIP',command=lambda:self.safe(self.update_package));self.update_button.pack(anchor='w')
        ttk.Button(maintenance,text='Trazer dados da versão anterior',command=lambda:self.safe(self.import_previous)).pack(anchor='w',pady=10)
        self.update_status=tk.StringVar(value='A atualização preserva os dados e mantém a instalação anterior.');ttk.Label(maintenance,textvariable=self.update_status,wraplength=820).pack(anchor='w',pady=12)
        help_page=ttk.Frame(tabs,padding=18);tabs.add(help_page,text='Arquivos e ajuda')
        self.help_tool=tk.StringVar(value=TOOLS[0][1]);choice=ttk.Combobox(help_page,textvariable=self.help_tool,values=[t[1] for t in TOOLS],state='readonly',width=40);choice.pack(anchor='w',pady=8)
        self.help_version=tk.StringVar();ttk.Label(help_page,textvariable=self.help_version).pack(anchor='w',pady=8)
        def selected():return next(t for t in TOOLS if t[1]==self.help_tool.get())
        def show_version(event=None):self.help_version.set('Versão da ferramenta: '+self.module_version(selected()[0]))
        choice.bind('<<ComboboxSelected>>',show_version);show_version()
        ttk.Button(help_page,text='Abrir resultados / pasta',command=lambda:self.safe(lambda:self.open_folder(selected()))).pack(anchor='w',pady=6)
        ttk.Button(help_page,text='Ler instruções',command=lambda:self.safe(lambda:os.startfile(str(tool_folder(selected()[0])/'LEIA-ME.md')))).pack(anchor='w',pady=6)
        footer=ttk.Frame(root,padding=(22,10));footer.grid(row=2,column=0,sticky='ew');footer.columnconfigure(0,weight=1)
        ttk.Label(footer,textvariable=self.context).grid(row=0,column=0,sticky='w')
        ttk.Button(footer,text='Histórico',command=self.open_history_page).grid(row=0,column=1)
        self.poll_id=root.after(600,self.poll);root.protocol('WM_DELETE_WINDOW',self.close)

    def refresh_context(self):
        self.context.set('Cadastro em cada ferramenta' if self.unit.get()=='Cadastro local' else 'Unidade: '+self.unit.get()+(' • '+self.group.get() if self.group.get()!='Todos os grupos' else ''))

    def open_options(self):
        self.options.deiconify();self.options.lift()

    def open_history_page(self):
        self.refresh_history();self.options_tabs.select(self.history_tab);self.open_options()

    def safe(self,fn):
        try: fn()
        except (OSError,ValueError,KeyError,TypeError) as exc: messagebox.showerror('Central de Refresh',str(exc))

    def launch(self,tool):
        identifier=tool[0]
        if identifier in self.running and self.running[identifier][0].poll() is None:
            messagebox.showinfo('Ferramenta aberta','Essa ferramenta já foi aberta por esta central. Confira sua janela.'); return
        command,folder=launch_command(tool)
        logs=BASE/'logs';logs.mkdir(exist_ok=True)
        rid=uuid.uuid4().hex;path=logs/(identifier+'_'+rid+'.txt')
        env=os.environ.copy();env.update(REFRESH_HISTORY=str(self.history_dir),REFRESH_RUN_ID=rid,REFRESH_RUN_LOG=str(path),REFRESH_TOOL=identifier,REFRESH_UNIT=self.unit.get())
        env.pop('REFRESH_INVENTORY',None)
        secret_names=[]
        for group in inventory.read(self.registry_path)['groups']:
            stored=self.session_credentials.get(group['nome'],{})
            for key,value in [(inventory.password_key(group),stored.get('password','')),(group['secret_env'],stored.get('enable',''))]:
                if key and value:env[key]=value;secret_names.append(key)
                elif key and env.get(key):secret_names.append(key)
        env['REFRESH_SECRET_NAMES']=json.dumps(secret_names)
        if self.unit.get()!='Cadastro local':
            data=inventory.read(self.registry_path)
            if self.group.get()!='Todos os grupos':data['devices']=[d for d in data['devices'] if d['grupo']==self.group.get()]
            supplied=inventory.dispatch(BASE/'dados/despachos'/ (rid+'.json'),data,self.unit.get(),identifier)
            if supplied:env['REFRESH_INVENTORY']=str(supplied)
        console=tool[4]
        flags=(getattr(subprocess,'CREATE_NEW_CONSOLE',0) if console else getattr(subprocess,'CREATE_NO_WINDOW',0)) if os.name=='nt' else 0
        storage.write_json(self.history_dir/('run_'+rid+'.json'),{'at':storage.now(),'run':rid,'tool':identifier,'kind':'Sessão','status':'Iniciando','path':str(path),'unit':self.unit.get()})
        try:
            process=subprocess.Popen(command,cwd=folder,shell=False,creationflags=flags,env=env)
        except Exception as exc:
            storage.write_json(self.history_dir/('run_'+rid+'.json'),{'at':storage.now(),'run':rid,'tool':identifier,'kind':'Sessão','status':'Falha ao abrir','detail':type(exc).__name__,'path':str(path)})
            raise
        self.running[identifier]=(process,path); self.messages[identifier].set('Aberto'); self.buttons[identifier].configure(state='disabled')

    def open_folder(self,tool):
        folder=tool_folder(tool[0]); result=folder/tool[5] if tool[5] else folder
        os.startfile(str(result if result.is_dir() else folder))

    def poll(self):
        for identifier,(process,path) in list(self.running.items()):
            code=process.poll()
            if code is None: continue
            rid=path.stem.rsplit('_',1)[-1];record_path=self.history_dir/('run_'+rid+'.json')
            if record_path.exists():
                record=json.loads(record_path.read_text(encoding='utf-8'))
                if record.get('status') in ('Iniciando','Em execução'):
                    record.update(status='Encerramento sem registro final',exit_code=code,finished=storage.now());storage.write_json(record_path,record)
            del self.running[identifier]; self.buttons[identifier].configure(state='normal')
            self.messages[identifier].set('' if code==0 else 'Confira o histórico')
            if code not in (0,2): messagebox.showerror('Falha ao abrir ferramenta','Confira as dependências e o registro em:\n'+str(path))
        while not self.update_events.empty():
            success,value=self.update_events.get();self.updating=False;self.update_button.configure(state='normal')
            self.update_status.set(value)
            if not success:messagebox.showerror('Atualização',value)
        self.poll_id=self.root.after(600,self.poll)

    def credentials(self):
        groups=inventory.read(self.registry_path)['groups']
        if not groups:raise ValueError('Cadastre um grupo de credenciais primeiro')
        dialog=tk.Toplevel(self.root);dialog.title('Senhas somente em memória');dialog.geometry('650x520')
        ttk.Label(dialog,text='Não são salvas no cadastro, inventário ou histórico. Fechar a Central limpa sua cópia; ferramentas já abertas mantêm a própria sessão.',wraplength=610).pack(padx=10,pady=10)
        canvas=tk.Canvas(dialog);scroll=ttk.Scrollbar(dialog,orient='vertical',command=canvas.yview);canvas.configure(yscrollcommand=scroll.set);scroll.pack(side='right',fill='y');canvas.pack(fill='both',expand=True)
        body=ttk.Frame(canvas);canvas.create_window((0,0),window=body,anchor='nw');body.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        variables={}
        for i,g in enumerate(groups):
            ttk.Label(body,text=g['nome']).grid(row=i*2,column=0,padx=10)
            fields=[('password','Senha SSH')]+([('enable','Senha enable')] if g.get('secret_env') else [])
            for j,(key,label) in enumerate(fields):
                var=tk.StringVar(value=self.session_credentials.get(g['nome'],{}).get(key,''));variables[(g['nome'],key)]=var
                ttk.Label(body,text=label).grid(row=i*2,column=j+1);ttk.Entry(body,textvariable=var,show='*').grid(row=i*2+1,column=j+1,padx=8,pady=8)
        def save():
            for (name,key),var in variables.items():self.session_credentials.setdefault(name,{})[key]=var.get();var.set('')
            dialog.destroy()
        ttk.Button(body,text='Usar nesta sessão',command=save).grid(row=len(groups)*2,column=1,pady=12)

    def module_version(self,identifier):
        try:return json.loads((tool_folder(identifier)/'version.json').read_text(encoding='utf-8'))['version']
        except (OSError,ValueError,KeyError):return 'não identificada'

    def refresh_registry(self):
        data=inventory.read(self.registry_path)
        self.unit_box.configure(values=['Cadastro local']+data['units']);self.group_box.configure(values=['Todos os grupos']+[g['nome'] for g in data['groups']])
        if self.unit.get() not in ['Cadastro local']+data['units']:self.unit.set('Cadastro local')
        if self.group.get() not in ['Todos os grupos']+[g['nome'] for g in data['groups']]:self.group.set('Todos os grupos')

    def history_page(self,tabs):
        page=ttk.Frame(tabs,padding=10);tabs.add(page,text='Histórico')
        bar=ttk.Frame(page);bar.pack(fill='x')
        ttk.Button(bar,text='Atualizar histórico',command=self.refresh_history).pack(side='left',padx=4)
        ttk.Button(bar,text='Abrir log / artefato selecionado',command=lambda:self.safe(self.open_history)).pack(side='left',padx=4)
        ttk.Label(page,text='Sessão encerrada não significa coleta aprovada. Consulte os eventos de relatório/aplicação e suas evidências.',wraplength=850).pack(anchor='w',pady=8)
        self.history_tree=ttk.Treeview(page,columns=('at','tool','kind','status','detail'),show='headings')
        for key,label in [('at','Data UTC'),('tool','Ferramenta'),('kind','Evento'),('status','Resultado'),('detail','Detalhe')]:self.history_tree.heading(key,text=label);self.history_tree.column(key,width=170)
        self.history_tree.pack(fill='both',expand=True)
        self.history_tree.bind('<Double-1>',lambda e:self.safe(self.open_history))
        self.history_paths={};self.refresh_history()

    def refresh_history(self):
        self.history_tree.delete(*self.history_tree.get_children());self.history_paths={}
        for i,row in enumerate(storage.history(self.history_dir)):
            iid=str(i);self.history_tree.insert('','end',iid=iid,values=[(dict((t[0],t[1]) for t in TOOLS).get(row.get(k,''),row.get(k,'')) if k=='tool' else row.get(k,'')) for k in ('at','tool','kind','status','detail')]);self.history_paths[iid]=row.get('path','')

    def open_history(self):
        selected=self.history_tree.selection()
        if not selected:return
        path=self.history_paths[selected[0]]
        if not path or not Path(path).exists():raise ValueError('Arquivo não está mais disponível')
        os.startfile(path)

    def import_previous(self):
        if self.updating:return
        if any(process.poll() is None for process,_ in self.running.values()):raise ValueError('Feche as ferramentas abertas antes de importar dados')
        source=filedialog.askdirectory(title='Selecione a pasta CentralRefresh da instalação anterior')
        if not source:return
        if not (Path(source)/'central.py').is_file():raise ValueError('Pasta não contém uma instalação da Central')
        manifest=json.loads((BASE/'release.json').read_text(encoding='utf-8')) if (BASE/'release.json').exists() else {'files':{}}
        self.updating=True;self.update_button.configure(state='disabled');self.update_status.set('Copiando dados da instalação anterior…')
        def work():
            try:
                copied=migrate(source,BASE,manifest,preserve_existing=True)
                conflicts=sum(p.startswith('dados/importados/') for p in copied)
                self.update_events.put((True,f'{len(copied)} arquivos importados. {conflicts} conflitos preservados em dados/importados; arquivos atuais modificados não foram sobrescritos. Reabra a Central para carregar o cadastro importado.'))
            except Exception as exc:self.update_events.put((False,'Importação não concluída: '+str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def update_package(self):
        if self.updating:return
        if any(process.poll() is None for process,_ in self.running.values()):raise ValueError('Feche as ferramentas abertas antes de atualizar')
        archive=filedialog.askopenfilename(filetypes=[('Pacote Central','*.zip')])
        if not archive:return
        parent=filedialog.askdirectory(title='Pasta para criar a nova instalação (fora da pasta atual)')
        if not parent:return
        self.updating=True;self.update_button.configure(state='disabled');self.update_status.set('Verificando integridade, extraindo e preservando os dados…')
        def work():
            try:
                target,count=install(archive,BASE,parent)
                self.update_events.put((True,f'Atualização pronta em {target}. {count} arquivos de dados preservados. Abra CentralRefresh.exe nessa pasta. A instalação anterior foi mantida.'))
            except Exception as exc:self.update_events.put((False,'Atualização não concluída: '+str(exc)))
        threading.Thread(target=work,daemon=True).start()

    def close(self):
        if self.updating:messagebox.showinfo('Atualização','Aguarde o término da atualização antes de fechar.');return
        self.session_credentials.clear();self.root.after_cancel(self.poll_id); self.root.destroy()


def main():
    root=tk.Tk(); App(root); root.mainloop()


if __name__=='__main__': main()
