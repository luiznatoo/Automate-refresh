"""Gerador de restauração FortiSwitch standalone baseado em catálogo local."""
import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent/'refresh_core').is_dir():
        _sys.path.insert(0,str(_parent));break

import ipaddress as ip
import json
from pathlib import Path
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import restauracao

BASE = Path(__file__).resolve().parent
MODELS = {}
for family, copper, uplinks in [('108E',8,2),('108F',8,2),('124E',24,4),('124F',24,4),('148E',48,4),('148F',48,4)]:
    for suffix in ('','-POE','-FPOE'):
        if family=='148E' and suffix=='-FPOE': continue
        MODELS[family+suffix] = copper+uplinks
SECRET_FIELDS = {'tac_key','ise_key','community','admin_password'}
DEFAULTS = dict(model='148E',version='Base 7.04 / build 0929',admin_password='',hostname='SW-NOVA-UNIDADE',address='192.0.2.10/24',gateway='192.0.2.1',
    management_vlan='200',management_name='LAN_VLAN_200',location='PREENCHER_UNIDADE',
    vlans='1;NATIVA\n104;LINK1\n105;LINK2\n200;GERENCIA_LAN',
    access='1-46;200;ACESSO',trunks='47-52;1;104,105,200;UPLINK',
    tac_server='192.0.2.14',tac_key='',ise_server='192.0.2.21',ise_key='',
    active_group='ISE_GRP',remote_admin='ISE',override='não',community='',
    snmp_hosts='192.0.2.0/24',contact='noc@example.com',
    dns='192.0.2.53,198.51.100.53',domain='example.com',ntp='ntp1.fortinet.net',syslog='192.0.2.82')


def q(value):
    value=str(value)
    if any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError('Texto contém quebra de linha ou controle inválido.')
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def nums(value, maximum, label):
    found=set()
    for item in value.split(','):
        item=item.strip().lower().replace('port','')
        if not re.fullmatch(r'\d+(?:-\d+)?',item): raise ValueError(f'{label}: use 1-8,10,12.')
        pair=list(map(int,item.split('-'))); a=pair[0]; b=pair[-1]
        if not 1<=a<=b<=maximum: raise ValueError(f'{label}: intervalo deve estar entre 1 e {maximum}.')
        values=set(range(a,b+1))
        if found & values: raise ValueError(f'{label}: números repetidos.')
        found |= values
    return found


def records(text,count,label):
    for n,line in enumerate(text.splitlines(),1):
        if not line.strip(): continue
        parts=[x.strip() for x in line.split(';')]
        if len(parts)!=count: raise ValueError(f'{label}, linha {n}: esperado {count} campos separados por ponto e vírgula.')
        yield parts


def validate(d):
    if d['model'] not in MODELS: raise ValueError('Modelo não cadastrado.')
    if d['version'] not in ('7.6.6','7.4.6','Base 7.04 / build 0929'): raise ValueError('Versão não cadastrada.')
    if d['model'].startswith('108E') and d['version']=='7.6.6':
        raise ValueError('108E não é suportado em 7.6.6. Confirme o firmware real; há perfil 7.4.6, sem alterar firmware automaticamente.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,34}',d['hostname']): raise ValueError('Hostname: 1 a 35 letras, números, hífen ou sublinhado.')
    for key,limit in [('management_name',15),('remote_admin',35)]:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,'+str(limit)+'}',d[key]): raise ValueError(f'{key}: nome inválido ou muito longo.')
    if d['management_name']=='internal' or d['remote_admin'].lower()=='admin': raise ValueError('Não reutilize internal para a VLAN nem admin para o administrador remoto.')
    iface=ip.IPv4Interface(d['address']); gateway=ip.IPv4Address(d['gateway'])
    if iface.network.prefixlen>30: raise ValueError('Gerenciamento: use máscara entre /1 e /30.')
    if iface.network.prefixlen<1 or iface.ip in (iface.network.network_address,iface.network.broadcast_address): raise ValueError('IP de gerenciamento inválido para a rede.')
    if gateway not in iface.network or gateway in (iface.ip,iface.network.network_address,iface.network.broadcast_address): raise ValueError('Gateway precisa ser outro host válido na rede de gerenciamento.')
    vlans={}
    for value,desc in records(d['vlans'],2,'VLANs'):
        v=int(value)
        if not 1<=v<=4093 or v in vlans: raise ValueError('VLAN inválida/repetida; permitidas 1..4093 (4094 reservada neste gerador).')
        q(desc); vlans[v]=desc
    mgmt=int(d['management_vlan'])
    if mgmt not in vlans: raise ValueError('Cadastre a VLAN de gerenciamento na lista de VLANs.')
    ports={}; reach=False
    for mode,key,size in [('access','access',3),('trunk','trunks',4)]:
        for parts in records(d[key],size,key):
            numbers=nums(parts[0],MODELS[d['model']],'Portas'); native=int(parts[1]); desc=parts[-1]; q(desc)
            tagged=nums(parts[2],4093,'VLANs trunk') if mode=='trunk' else set()
            if native not in vlans or not tagged<=vlans.keys(): raise ValueError('Toda VLAN nativa/tagged precisa estar cadastrada.')
            if native in tagged: raise ValueError('VLAN nativa não pode ser também tagged na mesma porta.')
            if mode=='trunk' and (mgmt==native or mgmt in tagged): reach=True
            for p in numbers:
                if p in ports: raise ValueError(f'port{p} duplicada entre grupos de portas.')
                ports[p]=(mode,native,tagged,desc)
    if not ports or not reach: raise ValueError('Informe portas e ao menos um trunk que transporte a VLAN de gerenciamento.')
    if d['active_group'] not in ('ISE_GRP','TACACS_GRP'): raise ValueError('Grupo remoto inválido.')
    if d['override'] not in ('sim','não'): raise ValueError('Override precisa ser sim/não.')
    for server,key in [('tac_server','tac_key'),('ise_server','ise_key')]:
        if d[server]:
            ip.IPv4Address(d[server])
            if not d[key] or d[key].startswith('ENC '): raise ValueError(f'Preencha {key} com a chave real; não copie ENC do backup.')
            q(d[key])
    active='ise_server' if d['active_group']=='ISE_GRP' else 'tac_server'
    if not d[active]: raise ValueError('O servidor do grupo remoto escolhido precisa estar preenchido.')
    if not d['community']: raise ValueError('Preencha a comunidade SNMP v2c.')
    q(d['community'])
    hosts=[]
    for value in d['snmp_hosts'].split(','):
        net=ip.IPv4Network(value.strip(),strict=True)
        if net.prefixlen==0: raise ValueError('SNMP: informe hosts/redes específicos, não 0.0.0.0/0.')
        hosts.append(net)
    dns=[str(ip.IPv4Address(x.strip())) for x in d['dns'].split(',') if x.strip()]
    if len(dns)>2: raise ValueError('Informe no máximo dois servidores DNS.')
    if d['syslog']: ip.IPv4Address(d['syslog'])
    for key in ('ntp','domain','location','contact'): q(d[key])
    return iface,gateway,vlans,mgmt,ports,hosts,dns


def _render_cli(d, redact=False):
    iface,gateway,vlans,mgmt,ports,hosts,dns=validate(d)
    lines=[]
    def block(name,body): lines.extend(['config '+name]+['    '+x for x in body]+['end',''])
    def secret(key): return q('[OCULTO]' if redact else d[key])
    block('system global',['set hostname '+q(d['hostname']),'set strong-crypto enable','set admin-ssh-v1 disable','set admin-restrict-local disable'])
    block('switch auto-network',['set status disable'])
    block('switch global',['set auto-fortilink-discovery disable','set auto-isl disable'])
    # Create VLAN and L3 objects before referring to them elsewhere.
    body=[]
    for v,desc in sorted(vlans.items()): body += [f'edit {v}','    set description '+q(desc),'next']
    block('switch vlan',body)
    body=[]
    for p in sorted(ports): body += [f'edit "port{p}"','    set lldp-profile "default"','next']
    block('switch physical-port',body)
    body=[]
    for p,(mode,native,tagged,desc) in sorted(ports.items()):
        body += [f'edit "port{p}"','    set description '+q(desc),f'    set native-vlan {native}',
                 '    '+('set allowed-vlans '+','.join(map(str,sorted(tagged))) if tagged else 'unset allowed-vlans'),
                 '    unset untagged-vlans','    set stp-state enabled',
                 '    set edge-port '+('enabled' if mode=='access' else 'disabled'),
                 '    set stp-bpdu-guard '+('enabled' if mode=='access' else 'disabled'),
                 '    set loop-guard '+('enabled' if mode=='access' else 'disabled'),
                 '    set discard-mode '+('all-tagged' if mode=='access' else 'none'),'next']
    # Native VLAN 4094 isolates the CPU untagged path; management is a tagged SVI.
    body += ['edit "internal"','    set native-vlan 4094',f'    set allowed-vlans {mgmt}','    unset untagged-vlans','next']
    block('switch interface',body)
    block('system interface',['edit "internal"','    set mode static','    set ip 0.0.0.0 0.0.0.0','    set secondary-IP disable','    unset allowaccess','next',
        'edit '+q(d['management_name']),'    set mode static',f'    set ip {iface.ip} {iface.netmask}',
        '    set allowaccess ping https ssh snmp','    set alias "Interface Gerencia"',f'    set vlanid {mgmt}',
        '    set interface "internal"','next'])
    block('router static',['edit 1','    set dst 0.0.0.0 0.0.0.0',f'    set gateway {gateway}','    set device '+q(d['management_name']),'next'])
    profile=['admingrp','exec-alias-grp','loggrp','mntgrp','netgrp','pktmongrp','routegrp','swcoregrp','swmonguardgrp','sysgrp','utilgrp']
    block('system accprofile',['edit "prof_admin"']+['    set '+x+' read-write' for x in profile]+['next'])
    body=[]; groups=[]
    for field,key,name,group in [('tac_server','tac_key','TACACS_EMPRESA','TACACS_GRP'),('ise_server','ise_key','ISE_EMPRESA','ISE_GRP')]:
        if not d[field]: continue
        body += ['edit '+q(name),'    set server '+q(d[field]),'    set authen-type ascii',
                 '    set authorization '+('enable' if d['override']=='sim' else 'disable'),
                 '    set key '+secret(key),f'    set source-ip {iface.ip}','next']
        groups += ['edit '+q(group),'    set member '+q(name),'next']
    block('user tacacs+',body); block('user group',groups)
    block('system admin',['edit '+q(d['remote_admin']),'    set remote-auth enable','    set wildcard enable',
        '    set remote-group '+q(d['active_group']),
        '    set accprofile '+q('noaccess' if d['override']=='sim' else 'prof_admin'),
        '    set accprofile-override '+('enable' if d['override']=='sim' else 'disable'),'next'])
    block('system snmp sysinfo',['set status enable','set description '+q(d['hostname']),'set contact-info '+q(d['contact']),'set location '+q(d['location'])])
    body=['edit 1','    set name '+secret('community'),'    set status enable','    set query-v1-status disable',
          '    set query-v2c-status enable','    set trap-v1-status disable','    set trap-v2c-status disable','    config hosts']
    for n,net in enumerate(hosts,1): body += [f'        edit {n}',f'            set ip {net.network_address} {net.netmask}','        next']
    body += ['    end','next']; block('system snmp community',body)
    if dns:
        body=['set primary '+dns[0]]
        if len(dns)>1: body+=['set secondary '+dns[1]]
        body+=['set domain '+q(d['domain'])]; block('system dns',body)
    if d['ntp']: block('system ntp',['set ntpsync enable','config ntpserver','    edit 1','        set server '+q(d['ntp']),'    next','end'])
    if d['syslog']: block('log syslogd2 setting',['set status enable','set server '+q(d['syslog']),'set mode udp','set port 514','set facility local7'])
    block('switch lldp settings',['set status enable','set management-interface "internal"'])
    return '\n'.join(lines)


def render(d, redact=False):
    return restauracao.render(d,_render_cli(d),q,redact)


class App:
    def __init__(self,root):
        self.root=root; root.title('FortiSwitch • Gerador standalone'); root.geometry('1050x780')
        self.fields={}; self.texts={}
        ttk.Label(root,text='FortiSwitch 148E — arquivo completo para restauração',font=('Segoe UI',17,'bold')).pack(anchor='w',padx=18,pady=12)
        ttk.Label(root,text='Base incorporada: S148EN-7.04-FW-build929. Não é 7.6.6. Cabeçalho original preservado.').pack(anchor='w',padx=18)
        tabs=ttk.Notebook(root); tabs.pack(fill='both',expand=True,padx=18,pady=12)
        def page(title):
            f=ttk.Frame(tabs,padding=12); tabs.add(f,text=title); f.columnconfigure(1,weight=1); return f
        basic=page('1. Switch'); net=page('2. VLANs e portas'); sec=page('3. TACACS e SNMP'); svc=page('4. Serviços'); prev=page('5. Prévia')
        def field(parent,key,label,choices=None):
            row=parent.grid_size()[1]; ttk.Label(parent,text=label).grid(row=row,column=0,sticky='w',padx=4,pady=5)
            var=tk.StringVar(value=DEFAULTS[key]); self.fields[key]=var
            w=ttk.Combobox(parent,textvariable=var,values=choices,state='readonly') if choices else ttk.Entry(parent,textvariable=var,show='*' if key in SECRET_FIELDS else '')
            w.grid(row=row,column=1,sticky='ew',padx=6,pady=5)
        for k,label,choices in [('model','Modelo',['148E']),('version','Identificação da base',['Base 7.04 / build 0929']),('hostname','Hostname',None),('address','IP de gerenciamento / prefixo',None),('gateway','Gateway',None),('management_vlan','VLAN de gerenciamento',None),('management_name','Interface (nome fixo nesta base)',['LAN_VLAN_200']),('location','Localização / unidade',None)]: field(basic,k,label,choices)
        ttk.Label(basic,text='Somente 148E não PoE nesta revisão. Outros modelos/versões precisam de base cadastrada.\nConfigurações não editadas são herdadas da base, não do switch de destino.\nA restauração substitui a configuração do destino e pode reiniciar o equipamento.').grid(columnspan=2,sticky='w',pady=16)
        for key,title in [('vlans','VLANs: ID;descrição'),('access','Acessos: portas;VLAN;descrição — exemplo 1-8;200;USUARIOS'),('trunks','Trunks: portas;VLAN nativa;VLANs tagged;descrição — 9-10;1;104,200;UPLINK')]:
            ttk.Label(net,text=title).pack(anchor='w',pady=4)
            box=tk.Text(net,height=5,font=('Consolas',10)); box.insert('1.0',DEFAULTS[key]); box.pack(fill='both',expand=True); self.texts[key]=box
        ttk.Label(net,text='Uma linha por grupo. Portas e VLANs omitidas permanecem como estão na base.\nNão há remoção automática de VLANs antigas nem configuração de LACP.').pack(anchor='w',pady=4)
        for k,label,choices in [('tac_server','Servidor TACACS (opcional)',None),('tac_key','Chave TACACS',None),('ise_server','Servidor ISE (opcional)',None),('ise_key','Chave ISE',None),('active_group','Grupo utilizado pelo login',['ISE_GRP','TACACS_GRP']),('remote_admin','Nome do administrador remoto',None),('override','Perfil retornado pelo servidor?',['não','sim']),('community','Comunidade SNMP v2c',None),('snmp_hosts','Redes/hosts SNMP separados por vírgula',None),('contact','Contato SNMP',None)]: field(sec,k,label,choices)
        field(sec,'admin_password','Nova senha do admin local')
        ttk.Label(sec,text='Senha local e chaves originais foram removidas da base; preencha novas credenciais.\nPerfil local: prof_admin. Perfil retornado: fallback noaccess; configurar ISE/TACACS.\nO arquivo final contém segredos. Projetos e prévia ocultam esses campos.\nSNMP v2c: redes informadas; v1 e traps desabilitados.').grid(columnspan=2,sticky='w',pady=10)
        for k,label in [('dns','DNS (até dois IPs separados por vírgula)'),('domain','Domínio DNS'),('ntp','Servidor NTP'),('syslog','Servidor syslog')]: field(svc,k,label)
        self.preview=tk.Text(prev,wrap='none',font=('Consolas',10)); self.preview.pack(fill='both',expand=True)
        self.status=tk.StringVar(value='Pronto. Os endereços de serviços vieram do seu modelo; confirme antes de gerar.')
        ttk.Label(root,textvariable=self.status,wraplength=990).pack(anchor='w',padx=18,pady=5)
        buttons=ttk.Frame(root); buttons.pack(fill='x',padx=18,pady=10)
        for label,func in [('Abrir projeto',self.load),('Salvar projeto sem senhas',self.save_project),('Validar / prévia',self.show_preview),('Salvar restauração .conf',self.save_script)]: ttk.Button(buttons,text=label,command=lambda f=func:self.safe(f)).pack(side='left',padx=4)
        self.tabs=tabs; self.prev=prev

    def data(self): return {**{k:v.get() for k,v in self.fields.items()},**{k:v.get('1.0','end').strip() for k,v in self.texts.items()}}
    def safe(self,fn):
        try: fn()
        except (ValueError,OSError,KeyError,TypeError,json.JSONDecodeError) as exc: messagebox.showerror('Não foi possível concluir',str(exc))
    def show_preview(self):
        d=self.data(); text=render(d,True); self.preview.delete('1.0','end'); self.preview.insert('1.0',text); self.tabs.select(self.prev)
        used=validate(d)[4]; self.status.set(f'Estrutura validada: {len(text.splitlines())} linhas; {len(used)} portas editadas. Restauração em hardware ainda não validada.')
    def save_project(self):
        d=self.data()
        for k in SECRET_FIELDS: d[k]=''
        path=filedialog.asksaveasfilename(defaultextension='.json',initialfile='projeto.json',filetypes=[('Projeto','*.json')])
        if path: Path(path).write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding='utf-8'); self.status.set('Projeto salvo sem senhas. Reutilize para a próxima unidade.')
    def load(self):
        path=filedialog.askopenfilename(filetypes=[('Projeto','*.json')])
        if not path: return
        d=json.loads(Path(path).read_text(encoding='utf-8-sig'))
        if not isinstance(d,dict) or any(not isinstance(v,str) for v in d.values()): raise ValueError('Projeto inválido.')
        for k,v in self.fields.items(): v.set('' if k in SECRET_FIELDS else d.get(k,DEFAULTS[k]))
        for k,v in self.texts.items(): v.delete('1.0','end'); v.insert('1.0',d.get(k,DEFAULTS[k]))
        self.status.set('Projeto carregado. Preencha as chaves e comunidade SNMP.')
    def save_script(self):
        d=self.data(); text=render(d)
        path=filedialog.asksaveasfilename(defaultextension='.conf',initialfile=d['hostname']+'.conf',filetypes=[('Script CLI','*.conf')])
        if path:
            target=Path(path)
            if target.resolve().is_relative_to((BASE/'bases').resolve()): raise ValueError('Salve fora da pasta de bases.')
            target.write_text(text,encoding='utf-8')
            from refresh_core.storage import event
            event('Configuração FortiSwitch',target,detail='Gerada; sem aplicação')
            self.status.set('Restauração salva: '+path+' — contém segredos; confira modelo/build antes de restaurar.')


if __name__=='__main__':
    root=tk.Tk(); App(root); root.mainloop()
