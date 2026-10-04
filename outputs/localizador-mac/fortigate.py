"""Descoberta IPv4 por ARP/DHCP e união com aprendizados dos switches."""
import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from fortigate_ssh import SSH, COMMANDS, clean, redact

IP=r'(?:\d{1,3}\.){3}\d{1,3}'
MAC=r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'


def usable_mac(value):
    value=re.sub(r'[:.\-]', '', value).lower()
    if not re.fullmatch('[0-9a-f]{12}',value) or value=='000000000000' or int(value[:2],16)&1:
        return ''
    return value


def parse_hosts(raw,category):
    rows=[]; warnings=[]; interface=''; header=''; recognized=False
    for line in raw.splitlines():
        line=line.replace('|',' ')
        stripped=line.strip()
        if not stripped: continue
        if category=='ARP' and 'Address' in line and 'Age' in line and 'Interface' in line:
            recognized=True; continue
        if re.search(r'(?i)\bMAC(?:-Address)?\b',line) and re.search(r'(?i)\b(?:IP|Address)\b',line):
            header=line; recognized=True; continue
        if re.search(r'(?i)\b(?:no .*?(?:lease|entr)|total.*?\b0\b)',line):
            recognized=True; continue
        m=re.match(r'^\s*('+IP+r')\s+(.*)$',line)
        if not m:
            if category=='DHCP' and not re.match(r'^[\s=\-]+$',line):
                interface=re.sub(r'(?i)^Interface\s*:\s*','',stripped).rstrip(':')
            continue
        try: ipaddress.IPv4Address(m[1])
        except ValueError:
            warnings.append('IP inválido na saída'); continue
        recognized=True; found=re.search(MAC,m[2]); address=usable_mac(found[0]) if found else ''
        name=''; iface=interface; detail=m[2]
        if category=='ARP':
            parts=m[2].split(); iface=parts[-1] if len(parts)>1 else ''
        elif found and 'Hostname' in header:
            # Fixed column positions preserve blank hostnames and names containing spaces.
            begin=header.index('Hostname'); ends=[header.find(k,begin+1) for k in ('VCI','Expiry','Expiration')]
            end=min((n for n in ends if n>=0),default=len(line))
            absolute_mac=m.start(2)+found.start()
            if begin>absolute_mac+len(found[0]):
                name=line[begin:end].strip()
                if re.match(r'(?i)^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b|^\d{4}[-/]|^(?:never|expired|infinite)$',name): name=''
        note='' if address else 'A revisar: MAC ausente, incompleto ou não unicast na resposta.'
        if category=='DHCP' and re.search(r'(?i)\bexpired\b',detail): note+=' A revisar: concessão DHCP indicada como expirada.'
        if note: warnings.append(note)
        rows.append({'ip':m[1],'mac':address,'interface':iface,'hostname':name,'source':category,'details':detail,'note':note})
    return rows,recognized,list(dict.fromkeys(warnings))


def collect(device,password,args,folder):
    result={'name':device['nome'],'host':device['host'],'at':datetime.now(timezone.utc).isoformat(),
            'hosts':[],'errors':[],'status':{},'system':{},'ha':''}
    conn=None
    try:
        conn=SSH({**device,'porta':int(device.get('porta') or 22)},password,args.timeout,args.known_hosts)
        for category,command in COMMANDS.items():
            try:
                raw=conn.command(command)
                safe=redact(raw,password)
                slug=hashlib.sha256(('FortiGate'+device['nome']+command).encode()).hexdigest()[:16]
                (folder/(slug+'.txt')).write_text(device['nome']+'\n'+command+'\n'+safe,encoding='utf-8')
                if re.search(r'(?im)^\s*(?:command parse error|unknown action|command fail|permission denied|access denied|return code\s+-)',raw):
                    raise ValueError('Consulta recusada; confira permissões e log')
                if category=='Sistema':
                    info=dict((k.strip(),v.strip()) for k,v in re.findall(r'(?m)^([^:\n]+):\s*(.*)$',raw))
                    result['system']={k:info.get(k,'') for k in ('Version','Hostname','Serial-Number','Current HA mode','Virtual domain configuration')}
                    if not info.get('Virtual domain configuration','').lower().startswith('disable'):
                        raise ValueError('VDOM desabilitado não confirmado; esta versão requer VDOM desabilitado')
                    if not re.search(r'v7\.4\.(?:9|12)\b',info.get('Version','')):
                        result['errors'].append({'command':command,'error':'Versão fora do escopo 7.4.9/7.4.12; revisar compatibilidade.'})
                elif category=='HA':
                    result['ha']=safe
                    if not re.search(r'(?i)\b(?:HA|standalone|mode)\b',raw): raise ValueError('Estado HA não reconhecido')
                else:
                    rows,ok,warnings=parse_hosts(raw,category)
                    result['hosts'].extend(rows)
                    if not ok: raise ValueError('Resposta vazia ou formato não reconhecido; não comprova ausência de dispositivos')
                    if warnings: raise ValueError('; '.join(warnings))
                result['status'][category]='OK'
            except (TimeoutError,ConnectionError,OSError):
                # A timed-out stream cannot safely be reused for a different command.
                raise
            except Exception as exc:
                result['status'][category]='A revisar'
                result['errors'].append({'command':command,'error':redact(str(exc),password)[:1500]})
                if category=='Sistema': break
    except Exception as exc:
        result['errors'].append({'command':'SSH','error':redact(clean(str(exc)),password)[:1500]})
    finally:
        if conn: conn.close()
    for category in COMMANDS: result['status'].setdefault(category,'Não coletado')
    return result


def discover(firewalls,switches,manual=()):
    """One target per known MAC; unknown MACs stay separated by firewall/interface/IP."""
    targets={}; ip_macs={}
    def add(key,address,name='',ip='',source='',iface='',note=''):
        t=targets.setdefault(key,{'mac':address,'nome':'','ips':set(),'sources':set(),'interfaces':set(),'notes':set()})
        if name and not t['nome']: t['nome']=name
        if ip: t['ips'].add(ip)
        if source: t['sources'].add(source)
        if iface: t['interfaces'].add(iface)
        if note: t['notes'].add(note)
    for t in manual:
        add(t['mac'],t['mac'],t['nome'],t.get('ip',''),'Lista manual')
    for fw in firewalls:
        for h in fw['hosts']:
            key=h['mac'] or (fw['name'],h['interface'],h['ip'])
            add(key,h['mac'],h['hostname'],h['ip'],fw['name']+' / '+h['source'],fw['name']+' / '+h['interface'],h['note'])
            if h['mac']: ip_macs.setdefault((fw['name'],h['interface'],h['ip']),set()).add(h['mac'])
    for sw in switches:
        for h in sw['entries']:
            address=usable_mac(h['mac'])
            if address: add(address,address,source='Tabela MAC / '+sw['name'])
    for scope,addresses in ip_macs.items():
        if len(addresses)>1:
            for address in addresses: targets[address]['notes'].add('A revisar: IP '+scope[2]+' associado a MACs diferentes em ARP/DHCP ('+scope[0]+' / '+scope[1]+').')
    result=[]
    for t in targets.values():
        if len(t['interfaces'])>1: t['notes'].add('A revisar: MAC observado em mais de uma interface/firewall; conferir escopo e VLAN.')
        result.append({'mac':t['mac'],'nome':t['nome'] or 'Nome não identificado','ip':'\n'.join(sorted(t['ips'])),
                       'origem':'; '.join(sorted(t['sources'])),'interface_firewall':'; '.join(sorted(t['interfaces'])),
                       'revisar':'; '.join(sorted(t['notes']))})
    return sorted(result,key=lambda t:(t['mac'],t['ip']))


def add_tables(tables,firewalls):
    tables['Descoberta FortiGate']=[{'Firewall':fw['name'],'IP':h['ip'],'MAC':':'.join(h['mac'][i:i+2] for i in range(0,12,2)) if h['mac'] else 'A revisar',
        'Hostname':h['hostname'],'Interface firewall':h['interface'],'Fonte':h['source'],'Detalhes':h['details'],'Observação':h['note'],'Coleta UTC':fw['at']}
        for fw in firewalls for h in fw['hosts']]
    tables['Coleta FortiGate']=[{'Firewall':fw['name'],'IP gerenciamento':fw['host'],**fw['system'],**fw['status'],
        'Coleta UTC':fw['at'],'Erros':'; '.join(e['command']+': '+e['error'] for e in fw['errors']),'Estado HA':fw['ha']} for fw in firewalls]
    tables['A revisar']=[r.copy() for r in tables['Localização'] if r['Resultado'].startswith('A revisar')]
