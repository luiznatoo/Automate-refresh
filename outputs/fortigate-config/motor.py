"""FortiGate 60F 7.4.9: deterministic transformations of the supplied full backup."""
from pathlib import Path
import copy
import hashlib
import ipaddress as ip
import json
import re
from config_tree import parse,walk,protected,quote

BASE=Path(__file__).resolve().parent
LAN='LAN_VLAN_200'
LOCAL={'TRUNK_SWAG','LAN_VLAN_200','LAN_VLAN_500','LAN_VLAN_290','LAN_VLAN_210'}

def catalog():
    data=json.loads((BASE/'bases/catalogo.json').read_text(encoding='utf-8'))
    return data if isinstance(data,list) else [data]

def base_id(meta): return f"{meta['model']}-{meta['version']}-build{meta['build']}"
def metadata(identifier=None):
    for meta in catalog():
        if identifier is None or base_id(meta)==identifier: return meta
    raise ValueError('Base não cadastrada: '+str(identifier))

def load(identifier=None):
    meta=metadata(identifier)
    raw=(BASE/'bases'/meta['file']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=meta['sha256']: raise ValueError('Base alterada: hash não corresponde ao catálogo.')
    text=raw.decode('utf-8-sig')
    prefix=f"#config-version=FGT{meta['model']}-{meta['version']}-FW-build{meta['build']}-"
    if not text.startswith(prefix): raise ValueError('Base incompatível.')
    return text,parse(text)

def profiles(): return json.loads((BASE/'bases/operadoras.json').read_text(encoding='utf-8'))
def top(r,key): return r.child('config',key)
def value(node,key,default=''): return (node.get(key) or [default])[0]
def edits(node): return [c for c in node.children() if c.kind=='edit']
def iface_value(node):
    t=node.get('ip'); return str(ip.IPv4Interface(t[0]+'/'+t[1]))

def defaults(root=None,identifier=None):
    if root is None: _,root=load(identifier)
    header=root.dump().splitlines()[0]
    meta=next(m for m in catalog() if header.startswith(f"#config-version=FGT{m['model']}-{m['version']}-FW-build{m['build']}-"))
    interfaces={n.key:iface_value(n) for n in edits(top(root,'system interface')) if n.get('ip')}
    ha=top(root,'system ha'); bgp=top(root,'router bgp'); sdwan=top(root,'system sdwan')
    d={'schema':1,'base':base_id(meta),'hostname':value(top(root,'system global'),'hostname'),
       'location':value(top(root,'system snmp sysinfo'),'location'),
       'ha':{k:value(ha,k) for k in ('group-name','group-id','priority')},'interfaces':interfaces,'links':{},'dhcp':{}}
    members=edits(sdwan.child('config','members'))
    for link in ('LINK1','LINK2'):
        n=top(root,'system interface').child('edit',link)
        member=next(m for m in members if value(m,'interface')==link)
        item={'operator':'BASE','gateway':value(member,'gateway'),'description':value(n,'description'),
              'alias':value(n,'alias'),'bandwidth':value(member,'spillover-threshold'),'vpns':{}}
        for n in edits(top(root,'vpn ipsec phase1-interface')):
            if value(n,'interface')!=link: continue
            intf=top(root,'system interface').child('edit',n.key)
            remote=value(intf,'remote-ip'); neighbor=bgp.child('config','neighbor').child('edit',remote)
            item['vpns'][n.key]={k:value(n,k) for k in ('remote-gw','localid','peerid')}
            item['vpns'][n.key].update({'remote-ip':remote,'remote-as':value(neighbor,'remote-as')})
        d['links'][link]=item
    for server in edits(top(root,'system dhcp server')):
        ranges=server.optional('config','ip-range')
        for n in edits(ranges) if ranges else []:
            # Empty means translate the original offsets to the new subnet.
            d['dhcp'][server.key+'/'+n.key]={'start':'','end':''}
    d['auto_networks']=True
    d['bgp_networks']={n.key:'' for n in edits(bgp.child('config','network'))}
    return d

def bgp_network_rows(d,root=None):
    if root is None: _,root=load(d.get("base"))
    interfaces={n.key:ip.IPv4Interface('/'.join(n.get('ip'))) for n in edits(top(root,'system interface')) if n.get('ip')}
    overrides={} if d.get('auto_networks',False) else d.get('bgp_networks',{})
    nodes=edits(top(root,'router bgp').child('config','network'))
    if set(overrides)-{n.key for n in nodes}: raise ValueError('Network BGP não cadastrado na base.')
    rows=[]
    for node in nodes:
        original=ip.IPv4Network('/'.join(node.get('prefix')),strict=True)
        sources=[name for name,v in interfaces.items() if v.network==original]
        auto=ip.IPv4Interface(d['interfaces'][sources[0]]).network if len(sources)==1 else original
        manual=overrides.get(node.key,'').strip()
        effective=ip.IPv4Network(manual,strict=True) if manual else auto
        rows.append((node.key,', '.join(sources) or 'Base',str(auto),str(effective)))
    if len({r[3] for r in rows})!=len(rows): raise ValueError('Networks BGP duplicados.')
    return rows

def apply_profile(d,link,operator):
    if operator=='BASE':
        base=defaults(identifier=d.get("base")); d['links'][link]['vpns']=copy.deepcopy(base['links'][link]['vpns'])
        d['links'][link]['alias']=base['links'][link]['alias']
    else:
        p=profiles()[operator]
        for name,v in d['links'][link]['vpns'].items(): v.update(p['EQX' if name.endswith('_EQX') else 'HUB'])
        d['links'][link]['alias']=operator
    d['links'][link]['operator']=operator

def host(text):
    a=ip.IPv4Address(text)
    if a.is_multicast or a.is_unspecified or a.is_loopback or int(a)==2**32-1: raise ValueError('Endereço IPv4 não utilizável: '+text)
    return a

def interface(text):
    a=ip.IPv4Interface(text); host(str(a.ip))
    if a.network.prefixlen<1: raise ValueError('Interface não pode usar /0.')
    if a.network.prefixlen<31 and a.ip in (a.network.network_address,a.network.broadcast_address): raise ValueError('IP da interface é rede/broadcast: '+text)
    return a

def translated(address,old,new):
    a=ip.IPv4Address(address)
    if a not in old.network: raise ValueError('Endereço dependente fora da rede de origem: '+address)
    v=ip.IPv4Address(int(new.network.network_address)+int(a)-int(old.network.network_address))
    if v not in new.network or (new.network.prefixlen<31 and v in (new.network.network_address,new.network.broadcast_address)):
        raise ValueError('Nova máscara não comporta endereço/faixa existente: '+address+'. Ajuste as faixas DHCP ou use rede maior.')
    return str(v)

def automatic_pool(text):
    n=interface(text)
    start=ip.IPv4Address(int(n.network.network_address)+1)
    end=ip.IPv4Address(int(n.ip)-2)
    if n.network.prefixlen>30 or end<start or end not in n.network:
        raise ValueError('Gateway não permite faixa do primeiro IP até gateway menos 2: '+text)
    return str(start),str(end)

def generate(d):
    original,root=load(d.get("base")); base=defaults(root); changes=[]
    if not isinstance(d.get('auto_networks',False),bool): raise ValueError('Modo automático inválido.')
    network_rows=bgp_network_rows(d,root)
    if d.get('schema')!=1 or d.get('base')!=base['base']: raise ValueError('Projeto não pertence à base selecionada.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,34}',d['hostname']): raise ValueError('Hostname inválido (máximo 35 caracteres).')
    quote(d['location']); quote(d['ha']['group-name'])
    if not 1<=len(d['ha']['group-name'])<=35: raise ValueError('Nome HA: 1..35 caracteres.')
    for k in ('group-id','priority'):
        if not str(d['ha'][k]).isdigit() or not 0<=int(d['ha'][k])<=255: raise ValueError('HA '+k+': 0..255.')
    if set(d['interfaces'])!=set(base['interfaces']) or set(d['links'])!=set(base['links']) or set(d['dhcp'])!=set(base['dhcp']): raise ValueError('Projeto alterou objetos da base. Não crie/remova interfaces ou servidores nesta revisão.')
    old={k:interface(v) for k,v in base['interfaces'].items()}; new={k:interface(v) for k,v in d['interfaces'].items()}
    if len({v.ip for v in new.values()})!=len(new): raise ValueError('IP local duplicado entre interfaces.')
    # New overlaps are forbidden; existing topology is not silently redesigned.
    for a in new:
        for b in new:
            if a>=b or a.startswith('IPSEC_') or b.startswith('IPSEC_'): continue
            if new[a].network.overlaps(new[b].network) and not old[a].network.overlaps(old[b].network): raise ValueError('Redes sobrepostas: '+a+' / '+b)
    for k,n in new.items():
        if k.startswith('IPSEC_') and n.network.prefixlen!=32: raise ValueError('Túneis desta base usam IP local /32: '+k)
    secrets=protected(root)
    def put(n,k,v,path,quoted=False): n.set(k,[str(x) for x in v],changes,path,quoted)
    intfs=top(root,'system interface')
    for name,n in new.items():
        if n!=old[name]: put(intfs.child('edit',name),'ip',[n.ip,n.netmask],'interface/'+name)
    # Exact configured host-address dependencies, not a global text/IP replacement.
    ipmap={str(old[k].ip):str(v.ip) for k,v in new.items() if v.ip!=old[k].ip}
    for node,path in walk(root):
        for _,raw,t in node.settings():
            if len(t)<3: continue
            key=t[1]
            if key in ('source-ip','fmg-source-ip','router-id') and t[2] in ipmap:
                put(node,key,[ipmap[t[2]]],path,'"' in raw)
            if key in ('hostname','description','location','alias','comments','group-name') and base['hostname'] in ' '.join(t[2:]):
                put(node,key,[v.replace(base['hostname'],d['hostname']) for v in t[2:]],path,True)
    put(top(root,'system snmp sysinfo'),'location',[d['location']],'SNMP',True)
    for k,v in d['ha'].items():
        if k not in base['ha']: raise ValueError('Campo HA não permitido.')
        put(top(root,'system ha'),k,[v],'HA',k=='group-name')
    # Every exact subnet match in address objects and BGP announcements is updated.
    networks={(str(old[k].network.network_address),str(old[k].netmask)):(str(v.network.network_address),str(v.netmask)) for k,v in new.items() if v.network!=old[k].network}
    for scope,key in [('firewall address','subnet')]:
        for node,path in walk(top(root,scope),scope):
            v=node.get(key)
            if v and tuple(v) in networks: put(node,key,networks[tuple(v)],path)
    for nid,source,auto,effective in network_rows:
        network=ip.IPv4Network(effective)
        put(top(root,'router bgp').child('config','network').child('edit',nid),'prefix',[network.network_address,network.netmask],'BGP/network/'+nid)
    # Existing DHCP servers only. Reservations keep their original host offset.
    for server in edits(top(root,'system dhcp server')):
        name=value(server,'interface'); path='DHCP/'+server.key
        if name not in new: continue
        changed=new[name]!=old[name]; n=new[name]; o=old[name]
        if changed:
            gw=value(server,'default-gateway')
            put(server,'default-gateway',[str(n.ip) if gw==str(o.ip) else translated(gw,o,n)],path)
            put(server,'netmask',[n.netmask],path)
        ranges=server.optional('config','ip-range'); values=[]
        automated=d.get('auto_networks',False) and name in LOCAL
        if automated and (not ranges or len(edits(ranges))!=1): raise ValueError('Automação DHCP exige uma faixa existente por servidor: '+name)
        for rr in edits(ranges) if ranges else []:
            inputs=d['dhcp'][server.key+'/'+rr.key]
            if automated:
                start,end=automatic_pool(d['interfaces'][name])
                put(server,'default-gateway',[n.ip],path)
                put(server,'netmask',[n.netmask],path)
            else:
                start=inputs['start'] or (translated(value(rr,'start-ip'),o,n) if changed else value(rr,'start-ip'))
                end=inputs['end'] or (translated(value(rr,'end-ip'),o,n) if changed else value(rr,'end-ip'))
            a,b=host(start),host(end)
            if a not in n.network or b not in n.network or a>b or a<=n.ip<=b or a==n.network.network_address or b==n.network.broadcast_address: raise ValueError('Faixa DHCP inválida em '+name+' / '+rr.key)
            if any(not (b<x or a>y) for x,y in values): raise ValueError('Faixas DHCP sobrepostas em '+name)
            values.append((a,b)); put(rr,'start-ip',[a],path+'/range/'+rr.key); put(rr,'end-ip',[b],path+'/range/'+rr.key)
        reserved=server.optional('config','reserved-address')
        for rr in edits(reserved) if reserved else []:
            if rr.get('ip') and changed:
                addr=translated(value(rr,'ip'),o,n)
                if addr==str(n.ip): raise ValueError('Reserva DHCP conflita com gateway: '+name)
                put(rr,'ip',[addr],path+'/reserva/'+rr.key)
    dns=top(root,'system dns-database')
    for node,path in walk(dns,'DNS local'):
        addr=node.get('ip')
        if not addr: continue
        for name in LOCAL & old.keys():
            if new[name].network!=old[name].network and ip.IPv4Address(addr[0]) in old[name].network:
                put(node,'ip',[translated(addr[0],old[name],new[name])],path); break
    sd=top(root,'system sdwan'); members={value(n,'interface'):n for n in edits(sd.child('config','members'))}
    bgpn=top(root,'router bgp').child('config','neighbor'); sdn=sd.child('config','neighbor')
    # Bind before renaming, so swapping operators/link positions is atomic.
    original_bgps={n.key:n for n in edits(bgpn)}; original_sd={n.key:n for n in edits(sdn)}
    peers=[]
    for link,item in d['links'].items():
        if item['operator'] not in ('BASE','VIVO','EMBRATEL','TERCEIRA'): raise ValueError('Operadora inválida.')
        gateway=host(item['gateway']); n=new[link]
        if gateway not in n.network or gateway==n.ip or (n.network.prefixlen<31 and gateway in (n.network.network_address,n.network.broadcast_address)): raise ValueError('Gateway fora da rede/igual ao IP: '+link)
        if not str(item['bandwidth']).isdigit() or not 1<=int(item['bandwidth'])<=16776000: raise ValueError('Velocidade inválida (Kbps).')
        quote(item['description']); quote(item['alias'])
        if len(item['description'])>255 or len(item['alias'])>25: raise ValueError('Descrição/alias do link muito longo.')
        put(members[link],'gateway',[gateway],'SDWAN/'+link)
        associated=[link]+list(item['vpns'])
        for name in associated:
            intf=intfs.child('edit',name)
            if item['description']!=base['links'][link]['description']: put(intf,'description',[item['description']],'interface/'+name,True)
            if item['alias']!=base['links'][link]['alias']: put(intf,'alias',[item['alias']],'interface/'+name,True)
            if item['bandwidth']!=base['links'][link]['bandwidth']:
                for key in ('estimated-upstream-bandwidth','estimated-downstream-bandwidth'): put(intf,key,[item['bandwidth']],'interface/'+name)
                for key in ('spillover-threshold','ingress-spillover-threshold'): put(members[name],key,[item['bandwidth']],'SDWAN/'+name)
        if set(item['vpns'])!=set(base['links'][link]['vpns']): raise ValueError('Túneis não podem ser criados/removidos nesta revisão.')
        for name,v in item['vpns'].items():
            if set(v)!=set(base['links'][link]['vpns'][name]): raise ValueError('Campos VPN inválidos.')
            remote=str(host(v['remote-ip'])); host(v['remote-gw']); peers.append(remote)
            if remote in {str(x.ip) for x in new.values()}: raise ValueError('IP remoto do túnel conflita com IP local.')
            if not str(v['remote-as']).isdigit() or not 1<=int(v['remote-as'])<=4294967295: raise ValueError('AS remoto inválido.')
            for key in ('localid','peerid'):
                quote(v[key])
                if not 1<=len(v[key])<=63: raise ValueError('ID VPN inválido.')
            p1=top(root,'vpn ipsec phase1-interface').child('edit',name)
            for key in ('remote-gw','peerid','localid'): put(p1,key,[v[key]],'VPN/'+name,key!='remote-gw')
            intf=intfs.child('edit',name); prev=base['links'][link]['vpns'][name]['remote-ip']
            put(intf,'remote-ip',[remote,'255.255.255.255'],'interface/'+name)
            neighbor=original_bgps[prev]; neighbor.rename(remote,changes,'BGP/'+name)
            put(neighbor,'remote-as',[v['remote-as']],'BGP/'+name)
            ns=original_sd[prev]; ns.rename(remote,changes,'SDWAN neighbor/'+name)
            if v!=base['links'][link]['vpns'][name] or new[name]!=old[name]:
                put(ns,'member',[members[name].key],'SDWAN neighbor/'+name)
    if len(peers)!=len(set(peers)): raise ValueError('Peers BGP duplicados: os dois links precisam de conjuntos de peers distintos.')
    output=root.dump(); checked=parse(output)
    if protected(checked)!=secrets: raise ValueError('Exportação bloqueada: credencial/certificado foi alterado.')
    warnings=[
        'Base preserva equipamentos FortiSwitch gerenciados, números de série, políticas, certificados e reservas MAC da unidade de origem; não há migração desses itens nesta revisão.',
        'A base contém regras SD-WAN EQX com priority-members 67 57 (57 é túnel HUB). Preservado; revisar separadamente.',
        ('Modo automático: faixa DHCP do primeiro host até gateway menos 2 nas redes principais; reservas mantêm o deslocamento original. RDI não ganha servidor DHCP.' if d.get('auto_networks',False) else 'Modo manual: DHCP vazio mantém o deslocamento original. Não é criado servidor para RDI.'),
        'As senhas ENC foram preservadas literalmente. Isso não valida a autenticação nem a aceitação desses valores pelo equipamento de destino.'
    ]
    if any(x['operator']!='BASE' for x in d['links'].values()): warnings.append('Perfil de operadora aplica apenas endpoints/IDs/AS do MOP. PSKs e propostas da base permanecem: confirme a chave correspondente no HUB/EQX.')
    return output,changes,warnings
