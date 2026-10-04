"""Interface para auditar e aprovar um plano concreto de correções."""
import copy
import json
import os
import queue
import threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import inventario as auditoria
import hardening as engine
from firewall_inventory import Inventory
from hardening_ext_ui import Extras,InteractiveAuth
from tkinter import simpledialog

BASE=Path(__file__).resolve().parent

class App(Extras):
    def __init__(self,root):
        self.root=root;self.busy=False;self.events=queue.Queue();self.report=None;self.result=None
        self.marked=set();self.rows={};self.pilot_rules=set();self.cancel=threading.Event()
        root.title('FortiGate • Hardening e correções SSH')
        root.geometry(f'{min(1320,root.winfo_screenwidth()-60)}x{min(850,root.winfo_screenheight()-100)}');root.minsize(950,600)
        root.columnconfigure(0,weight=1);root.rowconfigure(1,weight=1)
        heading=ttk.Frame(root,padding=(16,12));heading.grid(row=0,column=0,sticky='ew');heading.columnconfigure(0,weight=1)
        ttk.Label(heading,text='Hardening FortiGate',font=('Segoe UI',17,'bold')).grid(row=0,column=0,sticky='w')
        ttk.Button(heading,text='Opções avançadas',command=self.open_advanced).grid(row=0,column=1)
        self.advanced=tk.Toplevel(root);self.advanced.title('Opções avançadas');self.advanced.geometry('1080x740');self.advanced.withdraw();self.advanced.protocol('WM_DELETE_WINDOW',self.advanced.withdraw)
        policy_tabs=ttk.Notebook(self.advanced);policy_tabs.pack(fill='both',expand=True,padx=10,pady=10)
        self.advanced_tabs=policy_tabs
        advanced_ssh=ttk.Frame(policy_tabs,padding=15);policy_tabs.add(advanced_ssh,text='Conexão')

        self.tabs=ttk.Notebook(root);self.tabs.grid(row=1,column=0,sticky='nsew',padx=16)
        equipment=ttk.Frame(self.tabs);self.tabs.add(equipment,text='1. Firewalls')
        equipment_canvas=tk.Canvas(equipment,highlightthickness=0)
        equipment_scroll=ttk.Scrollbar(equipment,orient='vertical',command=equipment_canvas.yview)
        equipment_scroll.pack(side='right',fill='y');equipment_canvas.pack(side='left',fill='both',expand=True)
        equipment_canvas.configure(yscrollcommand=equipment_scroll.set)
        group=ttk.Frame(equipment_canvas);equipment_window=equipment_canvas.create_window((0,0),window=group,anchor='nw')
        group.bind('<Configure>',lambda e:equipment_canvas.configure(scrollregion=equipment_canvas.bbox('all')))
        equipment_canvas.bind('<Configure>',lambda e:equipment_canvas.itemconfigure(equipment_window,width=e.width))
        group.columnconfigure(0,weight=1)
        inventory_page=ttk.Frame(group,padding=8);inventory_page.grid(row=0,column=0,sticky='nsew')
        self.inventory=Inventory(inventory_page,self.inventory_changed,lambda:not self.busy)
        self.inventory.tree.configure(height=5)
        connection=ttk.LabelFrame(group,text='Acesso SSH — credencial mantida nesta sessão',padding=10);connection.grid(row=1,column=0,sticky='ew',padx=8,pady=8)
        for col in range(3):connection.columnconfigure(col,weight=1)
        self.values={}
        for index,(key,label,value) in enumerate([('usuario','Usuário SSH',''),('senha','Senha SSH','')]):
            var=tk.StringVar(value=value);self.values[key]=var
            ttk.Label(connection,text=label).grid(row=0,column=index,sticky='w',padx=6)
            ttk.Entry(connection,textvariable=var,show='*' if key=='senha' else '').grid(row=1,column=index,sticky='ew',padx=6,pady=5)
        ttk.Label(connection,text='Usado em todos os firewalls. A senha fica nesta sessão.',wraplength=650).grid(row=2,column=0,columnspan=2,sticky='w',padx=6,pady=3)
        for index,(key,label,value) in enumerate([('known_hosts','Arquivo de chaves SSH (opcional)',''),('workers','Consultas simultâneas','4'),('timeout','Tempo limite por comando (segundos)','45')]):
            var=tk.StringVar(value=value);self.values[key]=var
            ttk.Label(advanced_ssh,text=label).grid(row=index,column=0,sticky='w',pady=5)
            ttk.Entry(advanced_ssh,textvariable=var,width=45).grid(row=index,column=1,sticky='ew',padx=8)
            if key=='known_hosts':ttk.Button(advanced_ssh,text='Selecionar',command=lambda:self.browse('known_hosts')).grid(row=index,column=2)
        ttk.Button(advanced_ssh,text='Exportar lista de firewalls',command=self.inventory.export_csv).grid(row=3,column=0,sticky='w',pady=8)
        rules_outer=ttk.Frame(policy_tabs);policy_tabs.add(rules_outer,text='Controles')
        canvas=tk.Canvas(rules_outer,highlightthickness=0);scroll=ttk.Scrollbar(rules_outer,orient='vertical',command=canvas.yview)
        scroll.pack(side='right',fill='y');canvas.pack(side='left',fill='both',expand=True);canvas.configure(yscrollcommand=scroll.set)
        rules=ttk.Frame(canvas,padding=12);window=canvas.create_window((0,0),window=rules,anchor='nw')
        rules.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(window,width=e.width))
        self.rule_vars={};policy=copy.deepcopy(engine.DEFAULT_POLICY);saved=BASE/'politica_hardening.json'
        if saved.exists():
            try:policy=engine.migrate_policy(json.loads(saved.read_text(encoding='utf-8')))
            except Exception:messagebox.showwarning('Política','Arquivo inválido. Carregados valores iniciais; revise antes de auditar.')
        for i,(key,label) in enumerate(engine.LABELS.items()):
            var=tk.BooleanVar(value=key in policy['enabled']);self.rule_vars[key]=var
            ttk.Checkbutton(rules,text=label,variable=var).grid(row=i//2,column=i%2,sticky='w',padx=12,pady=5)
        base_row=(len(engine.LABELS)+1)//2+1
        self.limit_vars={}
        for i,(key,label) in enumerate([('timeout_max','Timeout máximo (min)'),('tentativas_max','Máximo de tentativas'),('bloqueio_min','Bloqueio mínimo (s)'),('senha_min','Tamanho mínimo da senha local')],base_row):
            var=tk.StringVar(value=str(policy[key]));self.limit_vars[key]=var
            if key in ('timeout_max','bloqueio_min'):
                ttk.Label(rules,text=label).grid(row=i,column=0,sticky='w',padx=12,pady=5);ttk.Entry(rules,textvariable=var,width=12).grid(row=i,column=1,sticky='w')
        ttk.Label(rules,text='Regras técnicas iniciais; não é certificação CIS.\nCorreções disponíveis para todos os controles aplicáveis com estado coletado.\nSomente os 31 controles do script fornecido. Mudar a política exige nova verificação.',wraplength=850).grid(row=base_row+5,column=0,columnspan=2,sticky='w',padx=12,pady=8)
        maps=ttk.Frame(policy_tabs,padding=12);policy_tabs.add(maps,text='Interfaces / TLS')
        ttk.Label(maps,text='Mapeamento válido para este lote. Separe lotes quando a topologia for diferente.\nPortas presentes podem ser corrigidas após aprovação. Portas ausentes não serão criadas.',wraplength=800).grid(row=0,column=0,columnspan=2,pady=10)
        ttk.Button(maps,text='Sugerir mapeamento da última coleta',command=self.suggest_interfaces).grid(row=8,column=0,sticky='w',pady=12)
        self.map_vars={}
        for i,(logical,actual) in enumerate(policy['mapa_interfaces'].items(),1):
            ttk.Label(maps,text=logical+' do script → interface real').grid(row=i,column=0,sticky='w',pady=6)
            var=tk.StringVar(value=actual);self.map_vars[logical]=var;ttk.Entry(maps,textvariable=var).grid(row=i,column=1,padx=12)
        ttk.Label(maps,text='TLS administrativo esperado (separado por espaço)').grid(row=6,column=0,sticky='w',pady=12)
        self.tls_var=tk.StringVar(value=' '.join(policy['tls_permitidos']));ttk.Entry(maps,textvariable=self.tls_var).grid(row=6,column=1,padx=12)
        ttk.Label(maps,text='O script exige somente tlsv1-2. Você pode aprovar tlsv1-2 tlsv1-3 como padrão.\nTLS 1.3 adicional é divergência de padrão, não prova de vulnerabilidade.',wraplength=800).grid(row=7,column=0,columnspan=2,sticky='w')
        banners=ttk.Frame(policy_tabs,padding=10);policy_tabs.add(banners,text='Textos dos banners');banners.columnconfigure(0,weight=1)
        self.banner_text={}
        for i,key in enumerate(('pre','post')):
            ttk.Label(banners,text='Pré-login' if key=='pre' else 'Pós-login').grid(row=i*2,column=0,sticky='w')
            box=tk.Text(banners,height=7,wrap='word');box.grid(row=i*2+1,column=0,sticky='nsew',pady=6);banners.rowconfigure(i*2+1,weight=1)
            box.insert('1.0',policy['banners'][key]);self.banner_text[key]=box
        extra=ttk.Frame(policy_tabs,padding=12);policy_tabs.add(extra,text='Parâmetros de correção');extra.columnconfigure(1,weight=1)
        self.correction_vars={}
        for i,(key,label) in enumerate([('redes_gerencia','Redes IPv4 autorizadas (CIDR, separadas por espaço)'),('origem_ssh','IP de origem SSH visto pelo FortiGate (considerar NAT)'),('interface_gerencia','Interface de gerência preservada ao remover acesso WAN')]):
            value=policy['correcoes'][key]
            var=tk.StringVar(value=' '.join(value) if isinstance(value,list) else value);self.correction_vars[key]=var
            if key=='redes_gerencia':
                ttk.Label(extra,text=label).grid(row=0,column=0,sticky='w',pady=7);ttk.Entry(extra,textvariable=var).grid(row=0,column=1,sticky='ew',padx=8)
        ttk.Label(extra,text='Origem e interface SSH são identificadas automaticamente na coleta.').grid(row=1,column=0,columnspan=2,sticky='w',pady=6)
        ttk.Label(extra,text='MFA por e-mail: uma linha conta=email (todas as contas locais sem MFA)').grid(row=3,column=0,columnspan=2,sticky='w',pady=8)
        self.mfa_text=tk.Text(extra,height=6,wrap='none');self.mfa_text.grid(row=4,column=0,columnspan=2,sticky='ew')
        self.mfa_text.insert('1.0','\n'.join(k+'='+v for k,v in policy['correcoes']['mfa_email'].items()))
        self.smtp_var=tk.BooleanVar(value=policy['correcoes']['smtp_validado'])
        ttk.Checkbutton(extra,text='Confirmei o envio de e-mail pelo SMTP configurado nestes firewalls',variable=self.smtp_var).grid(row=5,column=0,columnspan=2,sticky='w',pady=8)
        ttk.Label(extra,text='Use lotes com o mesmo padrão. Trusted hosts só restringe contas ainda sem restrição IPv4.\nMFA exige uma conta executora distinta das contas a alterar. Não altera senhas nem configura SMTP.\nRemover SSH/HTTPS de WAN exige conexão pelo IP direto da interface de gerência preservada.\nSNMP v1/v2c será desativado; valide o monitoramento antes da aprovação.',wraplength=850).grid(row=6,column=0,columnspan=2,sticky='w',pady=10)
        policy_tabs.hide(extra)
        page=ttk.Frame(self.tabs,padding=8);self.tabs.add(page,text='2. Correções');self.results_page=page;page.columnconfigure(0,weight=1);page.rowconfigure(2,weight=1)
        bar=ttk.Frame(page);bar.grid(row=0,column=0,sticky='ew',pady=5)
        for label,callback in [('Selecionar correções',self.mark_all),('Limpar seleção',self.clear_marks)]:ttk.Button(bar,text=label,command=callback).pack(side='left',padx=4)
        filters=ttk.Frame(page);filters.grid(row=1,column=0,sticky='ew',pady=(0,6))
        ttk.Label(filters,text='Firewall:').pack(side='left',padx=(4,6))
        self.firewall_filter=tk.StringVar(value='Todos os firewalls')
        self.firewall_selector=ttk.Combobox(filters,textvariable=self.firewall_filter,values=['Todos os firewalls'],state='readonly',width=42);self.firewall_selector.pack(side='left',padx=(0,12));self.firewall_selector.bind('<<ComboboxSelected>>',self.filter_firewall)
        ttk.Label(filters,text='Resultado:').pack(side='left',padx=(0,6))
        self.result_filter=tk.StringVar(value='Correções disponíveis')
        selector=ttk.Combobox(filters,textvariable=self.result_filter,values=['Correções disponíveis','Pendências de dados','Já conformes','Todos'],state='readonly',width=23);selector.pack(side='left',padx=4);selector.bind('<<ComboboxSelected>>',lambda e:self.render() if self.report else None)
        self.tree=ttk.Treeview(page,columns=('mark','device','host','rule','status','proposal','mode'),show='headings',selectmode='extended')
        for key,label,width in [('mark','Aplicar',65),('device','Equipamento',150),('host','Host',125),('rule','Controle',250),('status','Resultado',195),('proposal','Antes → proposto',135),('mode','Aplicação',200)]:
            self.tree.heading(key,text=label);self.tree.column(key,width=width,minwidth=60,stretch=False)
        self.tree.configure(displaycolumns=('mark','device','rule','status','proposal'))
        self.tree.grid(row=2,column=0,sticky='nsew')
        y=ttk.Scrollbar(page,orient='vertical',command=self.tree.yview);y.grid(row=2,column=1,sticky='ns')
        x=ttk.Scrollbar(page,orient='horizontal',command=self.tree.xview);x.grid(row=3,column=0,sticky='ew');self.tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)
        self.tree.bind('<<TreeviewSelect>>',self.details);self.tree.bind('<ButtonRelease-1>',self.click_mark)
        self.tree.tag_configure('bad',foreground='#9C2828');self.tree.tag_configure('good',foreground='#166534')
        self.detail=tk.Text(page,height=6,wrap='word',state='disabled');self.detail.grid(row=4,column=0,sticky='ew',pady=6)
        self.result_summary=tk.StringVar(value='Audite os equipamentos para consultar as propostas.')
        ttk.Label(page,textvariable=self.result_summary,wraplength=900).grid(row=5,column=0,sticky='w',pady=5)
        history=ttk.Frame(policy_tabs,padding=8);policy_tabs.add(history,text='Registro de execução');history.columnconfigure(0,weight=1);history.rowconfigure(0,weight=1)
        self.log=tk.Text(history,state='disabled',wrap='word');self.log.grid(row=0,column=0,sticky='nsew')
        footer=ttk.Frame(root,padding=10);footer.grid(row=2,column=0,sticky='ew')
        self.audit_button=ttk.Button(footer,text='Verificar hardening',command=self.start);self.audit_button.pack(side='left',padx=4)
        self.apply_button=ttk.Button(footer,text='Revisar correções',command=self.prepare,state='disabled');self.apply_button.pack(side='left',padx=4)
        self.cancel_button=ttk.Button(footer,text='Parar',command=self.cancel.set,state='disabled');self.cancel_button.pack(side='left',padx=4)
        ttk.Button(footer,text='Abrir último Excel',command=self.open_result).pack(side='left',padx=4)
        self.status=tk.StringVar(value='Pronto. Nenhuma correção selecionada.');ttk.Label(root,textvariable=self.status,padding=8).grid(row=3,column=0,sticky='ew')
        root.protocol('WM_DELETE_WINDOW',self.close);self.timer=root.after(100,self.poll)

        self.install_extras(policy,policy_tabs,advanced_ssh)
        advanced_footer=ttk.Frame(self.advanced,padding=10);advanced_footer.pack(fill='x')
        ttk.Button(advanced_footer,text='Salvar preferências',command=self.save_policy).pack(side='left')
        ttk.Button(advanced_footer,text='Fechar',command=self.advanced.withdraw).pack(side='right')
        from refresh_core.inventory import preload
        preload(self,'fortigate-hardening')

    def open_advanced(self):
        if self.busy:return
        self.advanced.deiconify();self.advanced.lift()

    def inventory_changed(self):
        self.report=None;self.marked.clear();self.pilot_rules.clear()
        if hasattr(self,'tree'):self.tree.delete(*self.tree.get_children());self.rows={}
        if hasattr(self,'apply_button'):self.apply_button.configure(state='disabled')
        if hasattr(self,'status'):self.status.set('Lista alterada. Execute uma nova auditoria para preparar correções.')

    def browse(self,key):
        if self.busy:return
        path=filedialog.askopenfilename()
        if path:self.values[key].set(path)
    def policy(self):return engine.validate_policy({'enabled':[k for k,v in self.rule_vars.items() if v.get()],**{k:int(v.get()) for k,v in self.limit_vars.items()},'mapa_interfaces':{k:v.get().strip() for k,v in self.map_vars.items()},'banners':{k:v.get('1.0','end-1c') for k,v in self.banner_text.items()},'tls_permitidos':self.tls_var.get().split(),'correcoes':self.correction_policy(),'exceptions':self.exceptions})
    def suggest_interfaces(self):
        if not self.report:messagebox.showinfo('Interfaces','Faça uma verificação para carregar os nomes reais.');return
        if self.busy:return
        suggestions=[]
        for item in self.report['devices']:
            suggestions.append(engine.suggest_interfaces(item['snapshot'],self.policy()['mapa_interfaces']))
        if any(value!=suggestions[0] for value in suggestions[1:]):messagebox.showinfo('Interfaces','Os equipamentos têm mapas diferentes. Separe o inventário por modelo/topologia.');return
        for key,value in suggestions[0].items():self.map_vars[key].set(value)
        self.status.set('Mapeamento sugerido. Confira as portas e faça uma nova verificação; os destinos aparecerão nos comandos de aprovação.')
    def correction_policy(self):
        emails={}
        for line in self.mfa_text.get('1.0','end-1c').splitlines():
            if not line.strip():continue
            if '=' not in line:raise ValueError('MFA: use conta=email, uma conta por linha')
            account,email=(v.strip() for v in line.split('=',1))
            if account in emails:raise ValueError('Conta MFA repetida')
            emails[account]=email
        return {'redes_gerencia':self.correction_vars['redes_gerencia'].get().split(),'origem_ssh':self.correction_vars['origem_ssh'].get().strip(),'interface_gerencia':self.correction_vars['interface_gerencia'].get().strip(),'mfa_email':emails,'smtp_validado':self.smtp_var.get(),'mfa_tokens':self.token_map()}
    def save_policy(self):
        try:
            from refresh_core.storage import write_json
            write_json(BASE/'politica_hardening.json',self.policy());self.status.set('Política salva; audite novamente para utilizá-la.')
        except Exception as exc:messagebox.showerror('Política',str(exc))
    def validate_inventory(self):
        try:self.status.set(f"{len(self.inventory.rows())} equipamentos válidos")
        except Exception as exc:messagebox.showerror('Inventário',str(exc))
    def settings(self):
        timeout=int(self.values['timeout'].get());workers=int(self.values['workers'].get());known=self.values['known_hosts'].get().strip()
        if not 5<=timeout<=600 or not 1<=workers<=16:raise ValueError('Timeout: 5–600 s; concorrência: 1–16')
        if known and not Path(known).is_file():raise ValueError('known_hosts não encontrado')
        password=self.values['senha'].get()
        if not password:raise ValueError('Informe a senha SSH; ela será mantida apenas enquanto o programa estiver aberto')
        if self.otp_enabled.get():password=InteractiveAuth(password,self.ask_otp);workers=1
        return timeout,workers,known,password
    def set_busy(self,value):
        self.busy=value;self.firewall_selector.configure(state='disabled' if value else 'readonly');self.audit_button.configure(state='disabled' if value else 'normal')
        self.refresh_actions();self.cancel_button.configure(state='disabled')
    def start(self):
        if self.busy:return
        try:
            p=self.policy();timeout,workers,known,password=self.settings();devices=self.inventory.rows()
            for d in devices:
                d['usuario']=d['usuario'] or self.values['usuario'].get().strip()
                if not d['usuario']:raise ValueError('Informe o usuário SSH')
        except Exception as exc:messagebox.showerror('Dados',str(exc));return
        self.report=None;self.marked.clear();self.pilot_rules.clear();self.tree.delete(*self.tree.get_children());self.set_busy(True);self.status.set('Auditando, sem alterações…')
        def work():
            try:
                report=engine.audit(devices,password,p,workers,timeout,known,lambda name:self.events.put(('progress',name+' — auditado')))
                self.events.put(('audited',(report,engine.export(report))))
            except Exception as exc:self.events.put(('error',type(exc).__name__))
        threading.Thread(target=work,daemon=True).start()
    def filter_firewall(self,event=None):
        if self.busy:return
        self.marked.clear()
        if self.report:self.render()

    def render(self):
        labels=['Todos os firewalls']+[str(i+1)+'. '+d['device']['nome']+' — '+d['device']['host'] for i,d in enumerate(self.report['devices'])]
        self.firewall_selector.configure(values=labels)
        if self.firewall_filter.get() not in labels:self.firewall_filter.set(labels[0])
        firewall_index=labels.index(self.firewall_filter.get())-1
        selected=self.tree.selection();self.rows={};self.tree.delete(*self.tree.get_children());valid=set()
        for index,item in enumerate(self.report['devices']):
            if firewall_index>=0 and index!=firewall_index:continue
            for f in item['findings']:
                key=(index,f['rule']);iid=f'{index}:{f["rule"]}';
                if f['eligible']:valid.add(key)
                mode=self.result_filter.get()
                if mode=='Correções disponíveis' and not f['eligible']:continue
                if mode=='Pendências de dados' and (f['eligible'] or f['status'] in ('Conforme','Não aplicável')):continue
                if mode=='Já conformes' and f['status']!='Conforme':continue
                proposed=f"{f['before']} → {f['after']}" if f['after'] is not None else '—'
                proposed=' '.join(proposed.split());proposed=proposed if len(proposed)<160 else proposed[:157]+'…'
                self.rows[iid]=(key,f)
                self.tree.insert('','end',iid=iid,values=('☑' if key in self.marked and f['eligible'] else '☐' if f['eligible'] else '—',item['device']['nome'],item['device']['host'],f['title'],f['status'],proposed,engine.application_label(f)),tags=('good' if f['status']=='Conforme' else 'bad',))
        self.marked.intersection_update(valid)
        self.tree.selection_set([i for i in selected if i in self.rows]);self.refresh_actions()
        all_findings=[f for i,item in enumerate(self.report['devices']) if firewall_index<0 or i==firewall_index for f in item['findings']]
        good=sum(f['status']=='Conforme' for f in all_findings);pending=sum(not f['eligible'] and f['status'] not in ('Conforme','Não aplicável') for f in all_findings)
        self.result_summary.set(f'{len(valid)} correções disponíveis | {len(self.marked)} marcadas | {good} já conformes | {pending} pendências de dados. Use o filtro para consultar cada grupo.')
    def details(self,event=None):
        selected=self.tree.selection()
        if not selected or selected[0] not in self.rows:return
        _,f=self.rows[selected[0]];text=f"{f['title']}\nEvidência: {f['evidence']}\nRecomendação: {f['recommendation']}\nImpacto: {f['impact']}\nAntes: {f['before']}\nProposto: {f['after']}\nAplicação: {engine.application_reason(f)}"
        key,_=self.rows[selected[0]]
        session=self.report['devices'][key[0]]['snapshot'].get('Session',{})
        text+='\nSessão SSH: '+str(session.get('value',session.get('error','Não coletada')))
        self.detail.configure(state='normal');self.detail.delete('1.0','end');self.detail.insert('1.0',text);self.detail.configure(state='disabled')
    def refresh_actions(self):
        self.apply_button.configure(state='normal' if not self.busy and self.report and self.marked else 'disabled')
    def click_mark(self,event):
        if self.tree.identify_column(event.x)!='#1':return
        iid=self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid);self.toggle_selected()

    def toggle_selected(self):
        if self.busy:return
        for iid in self.tree.selection():
            key,f=self.rows[iid]
            if f['eligible']:
                if key in self.marked:self.marked.remove(key)
                else:self.marked.add(key)
        if self.report:self.render()
        chosen=self.tree.selection()
        if chosen and all(not self.rows[i][1]['eligible'] for i in chosen):
            messagebox.showinfo('Este item não gera aplicação',engine.application_reason(self.rows[chosen[0]][1]),parent=self.root)
    def mark_all(self):
        if self.busy:return
        self.marked={key for key,f in self.rows.values() if f['eligible']}
        if self.report:self.render()
    def clear_marks(self):
        if self.busy:return
        self.marked.clear()
        if self.report:self.render()
    def prepare(self):
        if self.busy or not self.report:return
        if not self.marked:
            messagebox.showinfo('Nenhuma correção marcada','Marque a caixa de um item com aplicação disponível. Os demais itens explicam o motivo no painel de detalhes.',parent=self.root);return
        try:
            if self.policy()!=self.report['policy']:raise ValueError('Política alterada; faça nova auditoria')
            timeout,_,known,password=self.settings();chosen=set(self.marked);plan=engine.make_plan(self.report,chosen)
            pilot=len(plan)>1 and not {r for _,r in chosen}<=self.pilot_rules
            if pilot:
                first=min(i for i,r in chosen);chosen={(i,r) for i,r in chosen if i==first};plan=engine.make_plan(self.report,chosen)
            self.approval(plan,chosen,pilot,password,timeout,known)
        except Exception as exc:messagebox.showerror('Revisão',str(exc))
    def approval(self,plan,chosen,pilot,password,timeout,known):
        dialog=tk.Toplevel(self.root);dialog.title('Aprovação do piloto' if pilot else 'Aprovação de alterações');dialog.geometry('850x620');dialog.transient(self.root);dialog.grab_set()
        ttk.Label(dialog,text=('PILOTO: somente o primeiro equipamento. O restante exigirá nova aprovação.' if pilot else f'Aplicação sequencial em {len(plan)} equipamento(s). Parada na primeira falha.'),wraplength=810,padding=10).pack(fill='x')
        text=tk.Text(dialog,wrap='word',font=('Consolas',10));text.pack(fill='both',expand=True,padx=10)
        for item in plan:
            text.insert('end',f"\n{item['device']['nome']} | {item['device']['host']}:{item['device']['porta']} | serial {item['identity']['serial']}\n")
            if any(c['rule'].startswith('if_') for c in item['changes']):text.insert('end','Correspondência das interfaces (confira a topologia): '+', '.join(k+' → '+v for k,v in item.get('interface_mapping',{}).items())+'\n')
            for c in item['changes']:text.insert('end',f"{c['title']}: {c['before']} → {c['after']}\nImpacto: {c['impact']}\n")
            text.insert('end',engine.commands(item['changes'])+'\n')
        text.insert('end','\nValores anteriores serão registrados. Backup SCP criptografado obrigatório antes de aplicar. Reversão tem revisão e aprovação próprias.\nFalha após envio pode deixar aplicação parcial; o lote para para revisão.\n');text.configure(state='disabled')
        bottom=ttk.Frame(dialog,padding=10);bottom.pack(fill='x');ttk.Label(bottom,text='Digite APLICAR:').pack(side='left')
        confirmation=tk.StringVar();ttk.Entry(bottom,textvariable=confirmation,width=15).pack(side='left',padx=8)
        def confirm():
            if confirmation.get()!='APLICAR':messagebox.showerror('Confirmação','Digite APLICAR exatamente.',parent=dialog);return
            if not self.ensure_backup_password(dialog):return
            token=engine.digest(plan);dialog.destroy();self.execute(chosen,token,password,timeout,known)
        ttk.Button(bottom,text='Aprovar e executar',command=confirm).pack(side='left',padx=5);ttk.Button(bottom,text='Não aplicar',command=dialog.destroy).pack(side='left',padx=5)
    def execute(self,chosen,token,password,timeout,known):
        if self.busy:return
        self.set_busy(True);self.cancel.clear();self.cancel_button.configure(state='normal');self.tabs.select(self.results_page);self.status.set('Aplicando plano aprovado…')
        report=copy.deepcopy(self.report);backup_password=self.backup_secret.get()
        def work():
            try:
                outcomes,journal=engine.apply(report,chosen,token,password,timeout,known,self.cancel,lambda r:self.events.put(('progress',r['device']['nome']+' — '+r['status'])),backup_password=backup_password)
                touched=[r['device'] for r in outcomes if r['status']=='Verificado']
                refreshed=engine.audit(touched,password,report['policy'],1,timeout,known) if touched else {'devices':[]}
                engine.evolucao.finish_reaudit(outcomes,refreshed,journal,engine.safety,engine.verify_changes)
                from refresh_core.storage import event
                event('Reauditoria após aplicação',journal,status='Confirmada' if all(r['status']=='Verificado' for r in outcomes) else 'Revisar',detail='Resultado da consulta independente')
                self.events.put(('applied',(outcomes,journal,refreshed,chosen)))
            except Exception as exc:
                try:
                    if 'journal' in locals():engine.evolucao.append_journal(journal,{'event':'reaudit_error','status':'Inconclusivo','detail':type(exc).__name__})
                except OSError:pass
                self.events.put(('error','Aplicação interrompida: '+type(exc).__name__+'; confira o diário em resultados antes de tentar novamente.'))
        threading.Thread(target=work,daemon=True).start()
    def poll(self):
        while not self.events.empty():
            kind,value=self.events.get()
            if kind=='otp':
                response,title=value
                code=simpledialog.askstring('OTP SSH',title+'\nCódigo do FortiToken (não será salvo):',show='*',parent=self.root);response.put(code)
            elif kind=='rollback':
                rows,journal=value;self.set_busy(False);self.report=None;self.marked.clear();self.refresh_actions();self.status.set('Reversão encerrada: '+str(journal));self.show_text('Resultado da reversão','\n'.join(str(r) for r in rows))
            elif kind=='progress':
                self.log.configure(state='normal');self.log.insert('end',value+'\n');self.log.see('end');self.log.configure(state='disabled');self.status.set(value)
            elif kind=='audited':
                self.report,self.result=value;self.render();self.set_busy(False);self.tabs.select(self.results_page);self.status.set('Verificação concluída. Marque as correções desejadas.')
                failed=[d for d in self.report['devices'] if 'value' not in d['snapshot'].get('Sistema',{})]
                if failed:
                    self.result_filter.set('Todos');self.render()
                    self.status.set(f'{len(failed)} firewall(s) sem coleta. Confira o diagnóstico SSH.')
                    messagebox.showerror('Falha na coleta SSH','\n\n'.join(d['device']['nome']+': '+d['snapshot'].get('Sistema',{}).get('error','Falha não identificada') for d in failed))
            elif kind=='applied':
                outcomes,journal,refreshed,chosen=value;success=all(r['status']=='Verificado' for r in outcomes)
                if success:self.pilot_rules.update(rule for _,rule in chosen)
                else:self.pilot_rules.clear();self.marked.clear()
                for fresh in refreshed['devices']:
                    for i,old in enumerate(self.report['devices']):
                        if old['device']==fresh['device']:self.report['devices'][i]=fresh
                self.marked.difference_update(chosen);self.render();self.set_busy(False)
                try:self.result=engine.export(self.report,execution=outcomes)
                except Exception:messagebox.showerror('Excel','Não foi possível salvar o Excel; o diário JSONL foi preservado.')
                self.status.set('Execução encerrada. Diário: '+str(journal))
                messagebox.showinfo('Execução','Confira Execução e Excel. '+('Piloto/lote verificado; itens restantes exigem nova aprovação.' if success else 'Lote interrompido. Audite novamente antes de outra aplicação.'))
                if not success:self.report=None;self.apply_button.configure(state='disabled')
            else:
                self.set_busy(False);self.pilot_rules.clear();self.report=None;self.apply_button.configure(state='disabled');messagebox.showerror('Operação',str(value))
        self.timer=self.root.after(100,self.poll)
    def open_result(self):
        if self.result:os.startfile(str(self.result))
    def close(self):
        if self.busy:messagebox.showinfo('Operação em andamento','Use Parar após equipamento atual e aguarde a conclusão.');return
        self.backup_secret.set('');self.values['senha'].set('');self.root.after_cancel(self.timer);self.root.destroy()

if __name__=='__main__':
    root=tk.Tk();App(root);root.mainloop()
