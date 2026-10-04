"""Edição estrutural de uma base completa; não fabrica cabeçalhos de firmware."""
import hashlib
import json
from pathlib import Path
import re
import shlex

BASE=Path(__file__).resolve().parent

class Node:
    def __init__(self,line='',kind='root',key=''):
        self.line=line; self.kind=kind; self.key=key; self.items=[]; self.close=''
    def child(self,kind,key):
        return next((x for x in self.items if isinstance(x,Node) and x.kind==kind and x.key==key),None)
    def dump(self):
        return self.line+''.join(x.dump() if isinstance(x,Node) else x for x in self.items)+self.close

def parse(text):
    root=Node(); stack=[root]
    for line in text.splitlines(keepends=True):
        s=line.strip()
        if s.startswith(('config ','edit ')):
            kind,value=s.split(' ',1)
            # This catalog entry has no multiline certificates. New bases require review.
            try: key=' '.join(shlex.split(value))
            except ValueError: raise ValueError('Base contém nome inválido.')
            if stack[-1].child(kind,key): raise ValueError('Objeto duplicado na base: '+key)
            node=Node(line,kind,key); stack[-1].items.append(node); stack.append(node)
        elif s in ('end','next'):
            expected='config' if s=='end' else 'edit'
            if len(stack)==1 or stack[-1].kind!=expected: raise ValueError('Estrutura de configuração inválida.')
            stack.pop().close=line
        else: stack[-1].items.append(line)
    if len(stack)!=1: raise ValueError('Configuração incompleta.')
    return root

def field(line):
    m=re.match(r'\s*(?:set|unset)\s+(\S+)',line)
    return m[1] if m else None

def merge(dst,src):
    for value in src.items:
        if isinstance(value,Node):
            old=dst.child(value.kind,value.key)
            if old is None: dst.items.append(value)
            elif value.kind=='config' and value.key=='hosts':
                dst.items[dst.items.index(old)]=value
            else: merge(old,value)
        elif field(value):
            key=field(value)
            indexes=[i for i,x in enumerate(dst.items) if isinstance(x,str) and field(x)==key]
            if indexes:
                if len(indexes)>1: raise ValueError('Parâmetro duplicado: '+key)
                i=indexes[0]; indent=re.match(r'\s*',dst.items[i])[0]; dst.items[i]=indent+value.strip()+'\n'
            else:
                indent=re.match(r' *',dst.line)[0]+'    '
                dst.items.append(indent+value.strip()+'\n')

def load_base():
    catalog=json.loads((BASE/'bases'/'catalogo.json').read_text(encoding='utf-8'))
    entry=catalog['bases'][0]
    path=BASE/'bases'/entry['arquivo']; raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=entry['sha256']: raise ValueError('A base foi alterada fora do catálogo. Revise e cadastre uma nova revisão.')
    text=raw.decode('utf-8'); parse(text)
    if text.splitlines()[0]!=entry['cabecalho']: raise ValueError('Cabeçalho da base divergente.')
    return entry,text

def render(d,cli,quote,redact=False):
    entry,text=load_base()
    if (d['model'],d['version'])!=(entry['modelo'],entry['versao_rotulo']): raise ValueError('Não há base de restauração para esse modelo/versão.')
    if d['management_name']!='LAN_VLAN_200': raise ValueError('Esta base usa LAN_VLAN_200. Renomear exige revisar todas as referências; altere o IP e VLAN sem mudar esse nome.')
    if d['remote_admin']!='ISE': raise ValueError('Esta base usa o administrador remoto ISE; o grupo pode ser escolhido sem renomear o objeto.')
    if not d.get('admin_password') or d['admin_password'].startswith('ENC '): raise ValueError('Informe uma nova senha para o admin local; a senha do equipamento de origem não será clonada.')
    quote(d['admin_password'])
    if not d['ise_server'] or not d['tac_server']: raise ValueError('Nesta base, preencha ambos os servidores TACACS/ISE para substituir suas credenciais.')
    root=parse(text); patch=parse(cli)
    # Only named scopes are edited. Every other block is kept verbatim.
    permitted={'system global','switch vlan','switch interface','system interface','router static','system accprofile',
               'user tacacs+','user group','system admin','system snmp sysinfo','system snmp community',
               'system dns','system ntp','log syslogd2 setting'}
    for scope in patch.items:
        if not isinstance(scope,Node) or scope.key not in permitted: continue
        if scope.key=='system global': scope.items=[x for x in scope.items if isinstance(x,str) and field(x)=='hostname']
        if scope.key=='system interface': scope.items=[x for x in scope.items if isinstance(x,Node) and x.key==d['management_name']]
        if scope.key=='switch interface': scope.items=[x for x in scope.items if isinstance(x,Node) and x.key!='internal']
        dst=root.child('config',scope.key)
        if dst is None: raise ValueError('Bloco necessário ausente na base: '+scope.key)
        merge(dst,scope)
    # Preserve the original internal VLANs and replace just management VLAN 200.
    internal=root.child('config','switch interface').child('edit','internal')
    old=next((x for x in internal.items if isinstance(x,str) and field(x)=='allowed-vlans'),None)
    if old is None: raise ValueError('VLANs internas ausentes.')
    parts=old.strip().split()[-1].split(',')
    if '200' not in parts: raise ValueError('VLAN de gerenciamento de origem não identificada.')
    parts=[d['management_vlan'] if x=='200' else x for x in parts]
    internal.items[internal.items.index(old)]='        set allowed-vlans '+','.join(dict.fromkeys(parts))+'\n'
    admin=root.child('config','system admin').child('edit','admin')
    p=Node(); p.items=['set password '+quote(d['admin_password'])+'\n']; merge(admin,p)
    output=root.dump()
    if '__PREENCHER_' in output: raise ValueError('Credencial da base ainda não foi substituída.')
    parse(output)
    if redact: output=redacted(output)
    return output

def redacted(text):
    result=[]; snmp=False
    for line in text.splitlines(keepends=True):
        if line.startswith('config '): snmp=line.strip()=='config system snmp community'
        key=field(line)
        if key and (re.search(r'password|passwd|secret|key|community',key,re.I) or (snmp and key=='name')):
            line=re.match(r' *',line)[0]+'set '+key+' "[OCULTO]"\n'
        result.append(line)
    return ''.join(result)
