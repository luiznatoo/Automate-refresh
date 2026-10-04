"""Janela local para gerar a configuração completa do FortiGate 60F 7.4.9."""
import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent/'refresh_core').is_dir():
        _sys.path.insert(0,str(_parent));break

import copy
import json
from pathlib import Path
import tkinter as tk
from tkinter import ttk,filedialog,messagebox
import motor

class App:
    def __init__(self,root,identifier=None):
        self.root=root; self.initial=motor.defaults(identifier=identifier); self.vars={}
        root.title('FortiGate • Gerador de configuração'); root.geometry('1180x820'); root.minsize(850,620)
        ttk.Label(root,text='Gerador de configuração FortiGate',font=('Segoe UI',18,'bold')).pack(anchor='w',padx=18,pady=10)
        selector=ttk.Frame(root); selector.pack(fill='x',padx=18,pady=(0,8))
        ttk.Label(selector,text='Tipo de script / firewall:').pack(side='left',padx=(0,10))
        self.script_types={f"{m['model']} — FortiOS {m['version']} / build {m['build']}":motor.base_id(m) for m in motor.catalog()}
        self.script_type=tk.StringVar(value=next(k for k,v in self.script_types.items() if v==self.initial['base']))
        self.script_selector=ttk.Combobox(selector,textvariable=self.script_type,values=list(self.script_types),state='readonly',width=40)
        self.script_selector.pack(side='left')
        self.script_selector.bind('<<ComboboxSelected>>',lambda event:self.safe(self.select_base))
        ttk.Label(selector,text='  Outros modelos serão incluídos conforme o cadastro das bases.').pack(side='left')
        ttk.Label(root,text='Base completa incorporada. Senhas e valores ENC são preservados. Nenhuma conexão ao equipamento.').pack(anchor='w',padx=18)
        self.tabs=ttk.Notebook(root); self.tabs.pack(fill='both',expand=True,padx=18,pady=10)
        general=self.page('1. Unidade / HA'); ints=self.page('2. Interfaces'); links={x:self.page('3. '+x if x=='LINK1' else '4. '+x) for x in ('LINK1','LINK2')}
        dhcp=self.page('5. DHCP existente'); bgp=self.page('6. BGP'); addresses=self.page('7. Firewall address'); info=self.page('8. Dependências'); report=self.page('9. Revisão')
        self.report_page=report.master.master
        self.field(general,('hostname',),'Hostname')
        self.field(general,('location',),'Localização SNMP')
        for k,label in [('group-name','Nome do cluster HA'),('group-id','ID do cluster HA (0..255)'),('priority','Prioridade HA (0..255)')]: self.field(general,('ha',k),label)
        self.note(general,'A senha HA, modo, heartbeat e demais opções ficam como na base.\nHostname e nome do cluster são campos separados. A LAN alimenta automaticamente o router-id e as origens dos serviços.')
        self.note(ints,'IP/prefixo, por exemplo 10.10.20.254/24. Nomes, VLAN IDs, membros e portas não são renomeados nesta revisão.\nAs redes alimentam os objetos firewall address e os anúncios BGP existentes.')
        self.auto_networks=tk.BooleanVar(value=self.initial['auto_networks'])
        ttk.Checkbutton(ints,text='Automático: redes das interfaces → DHCP (primeiro IP até gateway − 2), BGP e firewall address',variable=self.auto_networks,command=self.toggle_automatic).grid(row=ints.grid_size()[1],column=0,columnspan=2,sticky='w',pady=8)
        self.auto_labels={}; self.manual_widgets=[]
        for name in self.initial['interfaces']:
            self.field(ints,('interfaces',name),name+' — IP / prefixo')
            if name in motor.LOCAL:
                label=tk.StringVar(); self.auto_labels[name]=label
                ttk.Label(ints,textvariable=label).grid(row=ints.grid_size()[1],column=0,columnspan=2,sticky='w',padx=5,pady=(0,8))
        self.note(ints,'Inclui interfaces auxiliares existentes. Túneis continuam /32. Não são criadas novas interfaces.')
        for link,parent in links.items():
            box=self.field(parent,('links',link,'operator'),'Perfil de peers',('BASE','VIVO','EMBRATEL','TERCEIRA'))
            box.bind('<<ComboboxSelected>>',lambda event,l=link:self.safe(lambda:self.select_profile(l)))
            for k,label in [('gateway','Gateway do link / SD-WAN'),('description','Descrição / designação'),('alias','Alias / operadora'),('bandwidth','Velocidade (Kbps)')]: self.field(parent,('links',link,k),label)
            self.note(parent,'VIVO / EMBRATEL / TERCEIRA preenchem endpoints, IDs e AS do MOP.\nNão mudam PSKs, criptografia ou propostas. Confira os campos antes de salvar.')
            for vpn in self.initial['links'][link]['vpns']:
                self.note(parent,vpn)
                self.field(parent,('interfaces',vpn),'IP local do túnel /32')
                for k,label in [('remote-gw','Peer público (phase1)'),('remote-ip','IP remoto do túnel / vizinho BGP'),('localid','Local ID'),('peerid','Peer ID'),('remote-as','AS remoto BGP')]: self.field(parent,('links',link,'vpns',vpn,k),label)
        _,tree=motor.load(self.initial["base"]); servers=motor.top(tree,'system dhcp server')
        self.bgp_base=tree
        self.note(addresses,'Objetos das redes LAN, voz, RDI, impressoras e TRUNK_SWAG.\nA rede prevista acompanha o IP/prefixo preenchido na aba Interfaces, inclusive com o modo automático desmarcado.\nObjetos alterados aparecem em verde. A validação completa ocorre ao revisar ou salvar a configuração.')
        self.address_table=ttk.Treeview(addresses,columns=('interface','object','original','effective'),show='headings',height=12)
        for key,title,width in [('interface','Rede / interface',180),('object','Firewall address',240),('original','Rede original',170),('effective','Rede prevista',210)]:
            self.address_table.heading(key,text=title); self.address_table.column(key,width=width,minwidth=100)
        self.address_table.grid(row=addresses.grid_size()[1],column=0,columnspan=2,sticky='ew')
        self.address_table.tag_configure('changed',foreground='#166534')
        self.address_table.tag_configure('invalid',foreground='#991B1B')
        self.address_rows=[]
        names=[('LAN',motor.LAN),('Voz','LAN_VLAN_290'),('RDI','LAN_VLAN_210'),('Impressoras','LAN_VLAN_500'),('TRUNK_SWAG','TRUNK_SWAG')]
        for label,name in names:
            if name not in self.initial["interfaces"]: continue
            network=motor.interface(self.initial['interfaces'][name]).network
            subnet=[str(network.network_address),str(network.netmask)]
            for obj in motor.edits(motor.top(tree,'firewall address')):
                if obj.get('subnet')==subnet:
                    row=self.address_table.insert('', 'end',values=(label+' / '+name,obj.key,str(network),str(network)))
                    self.address_rows.append((row,name,str(network)))
        self.note(bgp,'Neighbors — os mesmos IPs remotos das interfaces VPN. Alterações aqui e nas abas dos links são sincronizadas.\nO AS remoto também é compartilhado. Router-id continua acompanhando o IP da LAN.')
        for link,item in self.initial['links'].items():
            for vpn in item['vpns']:
                self.note(bgp,link+' / '+vpn)
                self.field(bgp,('links',link,'vpns',vpn,'remote-ip'),'Neighbor / IP remoto da VPN')
                self.field(bgp,('links',link,'vpns',vpn,'remote-as'),'AS remoto')
        self.note(bgp,'Networks — prefixos anunciados. Deixe o campo manual vazio para acompanhar a rede da interface.\nPara substituir somente o anúncio BGP, informe uma rede CIDR válida, por exemplo 10.20.30.0/24.\nNão altera a interface nem o firewall address. IDs de network existentes são preservados.')
        self.network_labels={}
        for nid,source,auto,effective in motor.bgp_network_rows(self.initial,tree):
            self.manual_widgets.append(self.field(bgp,('bgp_networks',nid),'Network '+nid+' — '+source+' (manual opcional)'))
            label=tk.StringVar(value=''); self.network_labels[nid]=label
            ttk.Label(bgp,textvariable=label).grid(row=bgp.grid_size()[1],column=0,columnspan=2,sticky='w',padx=5,pady=(0,7))
        self.note(dhcp,'Modo automático (aba Interfaces): primeiro IP utilizável até dois endereços antes do gateway nas redes principais.\nCampos manuais dessas redes ficam desabilitados. Desmarque o modo automático para usá-los; vazios preservam o deslocamento original.\nSomente servidores já existentes. Reservas mantêm posição na rede e MAC. RDI não recebe DHCP novo.')
        for key in self.initial['dhcp']:
            sid,rid=key.split('/'); server=servers.child('edit',sid); rr=server.child('config','ip-range').child('edit',rid)
            self.note(dhcp,f"Servidor {sid} — {motor.value(server,'interface')} — faixa {rid}: {motor.value(rr,'start-ip')} até {motor.value(rr,'end-ip')}")
            for part,label in [('start','Novo início (vazio = deslocamento original)'),('end','Novo fim (vazio = deslocamento original)')]:
                widget=self.field(dhcp,('dhcp',key,part),label)
                if motor.value(server,'interface') in motor.LOCAL: self.manual_widgets.append(widget)
        self.note(info,'DEPENDÊNCIAS AUTOMÁTICAS\n\nHostname → referências literais em hostname e descrições SNMP, incluindo switch-controller.\nLAN → router-id BGP, DNS source-ip, NetFlow, FortiManager, syslog, FortiAnalyzer, NTP e TACACS.\nRedes → objetos address e anúncios BGP com subnet/prefixo correspondente à base.\nDHCP → gateway, máscara, faixas e reservas somente dos servidores existentes.\nTRUNK_SWAG → registro local DNS fortiswitch pela posição na nova rede.\nLinks → gateways SD-WAN, descrição/alias e banda quando editados.\nVPNs → peer público, IDs, IP remoto, vizinho BGP/AS e SD-WAN neighbor.\n\nPRESERVADO\n\nTodas as credenciais, certificados, políticas, IDs de membros SD-WAN, phase2, propostas, regras e demais objetos.\n\nLIMITES\n\nSem LINK3 novo, sem renomear interfaces e sem migração de FortiSwitches gerenciados/seriais da unidade de origem.\nA base traz regras SD-WAN EQX usando o membro 57, que é HUB. Essas regras são preservadas para revisão separada.\nA restauração ainda precisa ser testada em equipamento real compatível.')
        self.highlight=tk.BooleanVar(value=True); self.last_review=None
        ttk.Checkbutton(report,text='Destacar alterações — vermelho: antes | verde: depois',variable=self.highlight,command=self.draw_review).grid(row=0,column=0,columnspan=2,sticky='w',pady=8)
        self.preview=tk.Text(report,height=28,wrap='word',font=('Consolas',10)); self.preview.grid(row=1,column=0,columnspan=2,sticky='nsew'); report.rowconfigure(1,weight=1)
        self.preview.tag_configure('before',foreground='#991B1B',background='#FEE2E2')
        self.preview.tag_configure('after',foreground='#166534',background='#DCFCE7')
        self.preview.tag_configure('path',foreground='#1E3A8A',font=('Consolas',10,'bold'))
        self.preview.configure(state='disabled')
        self.status=tk.StringVar(value='Preencha os campos. Prévia e relatório mostram apenas alterações, sem credenciais.')
        ttk.Label(root,textvariable=self.status,wraplength=1100).pack(anchor='w',padx=18)
        bar=ttk.Frame(root); bar.pack(fill='x',padx=18,pady=12)
        for label,func in [('Abrir projeto',self.load_project),('Salvar projeto',self.save_project),('Validar / revisar alterações',self.review),('Salvar relatório',self.save_report),('Salvar configuração completa',self.export)]: ttk.Button(bar,text=label,command=lambda f=func:self.safe(f)).pack(side='left',padx=5)
        for var in self.vars.values(): var.trace_add('write',self.fields_changed)
        self.toggle_automatic()

    def rebuild(self,identifier):
        motor.defaults(identifier=identifier)
        for child in self.root.winfo_children(): child.destroy()
        self.__init__(self.root,identifier)

    def select_base(self):
        identifier=self.script_types[self.script_type.get()]
        if identifier==self.initial['base']: return
        if self.data_without_base()!=self.initial:
            if not messagebox.askyesno('Trocar base','Trocar a base descarta os campos preenchidos ainda não salvos. Continuar?'):
                self.script_type.set(next(k for k,v in self.script_types.items() if v==self.initial['base']))
                return
        self.rebuild(identifier)

    def data_without_base(self):
        d=self.data(); d['base']=self.initial['base']; return d

    def toggle_automatic(self):
        for widget in self.manual_widgets: widget.configure(state='disabled' if self.auto_networks.get() else 'normal')
        self.fields_changed()

    def update_network_labels(self):
        for row,name,original in self.address_rows:
            try:
                effective=str(motor.interface(self.vars[('interfaces',name)].get().strip()).network)
                tags=('changed',) if effective!=original else ()
            except ValueError:
                effective='IP/prefixo inválido'; tags=('invalid',)
            self.address_table.set(row,'effective',effective)
            self.address_table.item(row,tags=tags)
        for name,label in self.auto_labels.items():
            try:
                cidr=self.vars[('interfaces',name)].get().strip()
                network=motor.interface(cidr).network
                suffix='DHCP não configurado na base' if name=='LAN_VLAN_210' else 'DHCP: '+' até '.join(motor.automatic_pool(cidr)) if self.auto_networks.get() else 'DHCP conforme aba DHCP'
                label.set('Rede: '+str(network)+' | '+suffix)
            except ValueError: label.set('Revise IP/máscara/gateway: não é possível calcular uma faixa válida.')
        try:
            for nid,source,auto,effective in motor.bgp_network_rows(self.data(),self.bgp_base):
                self.network_labels[nid].set('Automático: '+auto+'  |  Será anunciado: '+effective)
        except (ValueError,KeyError,TypeError):
            for var in self.network_labels.values(): var.set('Revise os IPs/prefixos: cálculo pendente de valores válidos.')

    def fields_changed(self,*args):
        self.update_network_labels()
        if self.last_review is not None:
            self.last_review=None
            self.preview.configure(state='normal'); self.preview.delete('1.0','end')
            self.preview.insert('1.0','Campos alterados. Clique em Validar / revisar alterações para atualizar a prévia.')
            self.preview.configure(state='disabled')
        self.status.set('Campos alterados. Valide novamente antes de conferir a prévia.')

    def draw_review(self):
        if self.last_review is None: return
        changes,warnings=self.last_review
        self.preview.configure(state='normal'); self.preview.delete('1.0','end')
        self.preview.insert('end',f'{self.script_type.get()}\n{len(changes)} alterações. Credenciais preservadas.\n\n')
        if not changes: self.preview.insert('end','Nenhuma alteração em relação à base.\n\n')
        for c in changes:
            self.preview.insert('end',c['path']+'\n','path' if self.highlight.get() else '')
            self.preview.insert('end','− Antes: '+c['before']+'\n','before' if self.highlight.get() else '')
            self.preview.insert('end','+ Depois: '+c['after']+'\n\n','after' if self.highlight.get() else '')
        self.preview.insert('end','Itens herdados e limites:\n'+'\n'.join('- '+w for w in warnings))
        self.preview.configure(state='disabled')

    def page(self,title):
        outer=ttk.Frame(self.tabs); self.tabs.add(outer,text=title)
        canvas=tk.Canvas(outer,highlightthickness=0); scroll=ttk.Scrollbar(outer,orient='vertical',command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set); scroll.pack(side='right',fill='y'); canvas.pack(side='left',fill='both',expand=True)
        inner=ttk.Frame(canvas,padding=12); inner.columnconfigure(1,weight=1)
        window=canvas.create_window((0,0),window=inner,anchor='nw')
        inner.bind('<Configure>',lambda e:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda e:canvas.itemconfigure(window,width=e.width))
        return inner

    def note(self,parent,text):
        row=parent.grid_size()[1]; ttk.Label(parent,text=text,wraplength=1000,justify='left').grid(row=row,column=0,columnspan=2,sticky='w',pady=10)

    def field(self,parent,path,label,choices=None):
        row=parent.grid_size()[1]; ttk.Label(parent,text=label).grid(row=row,column=0,sticky='w',padx=5,pady=4)
        if path not in self.vars:
            value=self.initial
            for key in path: value=value[key]
            self.vars[path]=tk.StringVar(value=str(value))
        w=ttk.Combobox(parent,textvariable=self.vars[path],values=choices,state='readonly') if choices else ttk.Entry(parent,textvariable=self.vars[path])
        w.grid(row=row,column=1,sticky='ew',padx=6,pady=4)
        return w

    def data(self):
        d=copy.deepcopy(self.initial)
        d['auto_networks']=self.auto_networks.get()
        d['base']=self.script_types[self.script_type.get()]
        for path,var in self.vars.items():
            target=d
            for key in path[:-1]: target=target[key]
            target[path[-1]]=var.get().strip()
        return d

    def select_profile(self,link):
        d=self.data(); motor.apply_profile(d,link,d['links'][link]['operator'])
        for path,var in self.vars.items():
            if path[:2]==('links',link) and (path[2]=='vpns' or path[2]=='alias'):
                value=d
                for key in path: value=value[key]
                var.set(value)
        self.status.set('Perfil aplicado aos peers de '+link+'. IPs locais e senhas permanecem como estavam.')

    def report(self,changes,warnings):
        lines=[self.script_type.get(),f'{len(changes)} alterações. Credenciais/certificados preservados literalmente.','']
        for c in changes: lines += [c['path'],'  Antes: '+c['before'],'  Depois: '+c['after'],'']
        lines += ['Itens herdados e limites:']+['- '+w for w in warnings]
        return '\n'.join(lines)

    def safe(self,fn):
        try: fn()
        except (ValueError,OSError,KeyError,TypeError,IndexError) as e: messagebox.showerror('Verifique os dados',str(e))

    def review(self):
        out,changes,warnings=motor.generate(self.data())
        self.last_review=(changes,warnings); self.draw_review(); self.tabs.select(self.report_page)
        self.status.set(f'Estrutura validada: {len(out.splitlines())} linhas. {len(changes)} alterações. Nenhuma credencial alterada.')

    def save_project(self):
        path=filedialog.asksaveasfilename(defaultextension='.json',initialfile=self.data()['hostname']+'.json',filetypes=[('Projeto','*.json')])
        if path:
            self.check_path(path); Path(path).write_text(json.dumps(self.data(),ensure_ascii=False,indent=2),encoding='utf-8')
            self.status.set('Projeto salvo sem as credenciais da base.')

    def save_report(self):
        _,changes,warnings=motor.generate(self.data())
        path=filedialog.asksaveasfilename(defaultextension='.txt',initialfile=self.data()['hostname']+'_alteracoes.txt',filetypes=[('Relatório','*.txt')])
        if path:
            self.check_path(path); Path(path).write_text(self.report(changes,warnings),encoding='utf-8')
            self.status.set('Relatório salvo sem credenciais.')

    def load_project(self):
        path=filedialog.askopenfilename(filetypes=[('Projeto','*.json')])
        if not path: return
        d=json.loads(Path(path).read_text(encoding='utf-8-sig'))
        d.setdefault('auto_networks',False)
        d.setdefault('bgp_networks',motor.defaults(identifier=d.get('base'))['bgp_networks'])
        motor.generate(d)
        self.rebuild(d['base'])
        self.auto_networks.set(d['auto_networks'])
        for p,var in self.vars.items():
            value=d
            for key in p: value=value[key]
            var.set(str(value))
        self.toggle_automatic()
        self.status.set('Projeto carregado; revise antes de exportar.')

    @staticmethod
    def check_path(path):
        if Path(path).resolve().is_relative_to((motor.BASE/'bases').resolve()): raise ValueError('Salve fora da pasta de bases.')

    def export(self):
        d=self.data(); out,changes,warnings=motor.generate(d)
        path=filedialog.asksaveasfilename(defaultextension='.conf',initialfile=d['hostname']+'_'+d['base']+'.conf',filetypes=[('Configuração completa','*.conf')])
        if not path: return
        self.check_path(path)
        Path(path).write_bytes(out.encode('utf-8'))
        from refresh_core.storage import event
        event('Configuração FortiGate',path,detail=str(len(changes))+' alterações; sem aplicação')
        # User can save the report separately; never overwrite an unrelated sibling file.
        self.last_review=(changes,warnings); self.draw_review(); self.tabs.select(self.report_page)
        self.status.set('Configuração salva: '+path+' — credenciais originais incluídas; restauração em hardware ainda não validada.')


if __name__=='__main__':
    root=tk.Tk()
    try: App(root)
    except (ValueError,OSError,KeyError) as e: messagebox.showerror('Erro ao carregar base',str(e)); root.destroy()
    else: root.mainloop()
