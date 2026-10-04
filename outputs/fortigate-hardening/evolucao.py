"""Compatibilidade, exceções, sessão e histórico: sem escrita no equipamento."""
import copy
import ipaddress
import json
import re
from datetime import date
from pathlib import Path

MATRIX = {model: {version: {'maintainer': 'Não aplicável','telemetria_rating':'Não aplicável — removido desde 7.4.4'} for version in ('7.4.9','7.4.12')}
          for model in ('40F','60F','100F')}

MATRIX['50E']={'6.2.16':{}}

def legacy_50e(snapshot):
    text=snapshot.get('Sistema',{}).get('value',{}).get('Version','')
    return model(snapshot)=='50E' and bool(re.search(r'\bv6\.2\.16\b',text))

def describe(snapshot,rule,policy):
    from padrao_empresa import RULES
    spec=RULES.get(rule)
    fields={'timeout':('Global','admintimeout'),'tentativas':('Global','admin-lockout-threshold'),
            'bloqueio':('Global','admin-lockout-duration'),'cripto':('Global','strong-crypto'),
            'tls':('Global','admin-https-ssl-versions'),'ntp':('NTP','ntpsync'),
            'senha':('Senha','minimum-length'),'mfa':('Administradores','two-factor'),
            'trusted_hosts':('Administradores','trusthost1'),'http_telnet':('Interfaces','allowaccess'),
            'wan_admin':('Interfaces','role'),'snmp':('SNMP','status')}
    system=snapshot.get('Sistema',{}).get('value',{})
    match=re.search(r'\bv(\d+\.\d+\.\d+)\b',system.get('Version',''))
    profile=MATRIX.get(model(snapshot),{}).get(match[1] if match else '',{})
    if rule in profile:return profile[rule]
    prefix='Perfil catalogado; ' if model(snapshot) in MATRIX and match and match[1] in MATRIX[model(snapshot)] else 'Perfil não catalogado; '
    if spec:
        cat,field=spec[:2];entry=policy['mapa_interfaces'].get(rule.split('_')[1]) if cat=='Interfaces' else None
        return prefix+capability(snapshot,cat,field,entry)
    cat,field=fields[rule]
    source=snapshot.get(cat,{}).get('value')
    if isinstance(source,list):
        return prefix+('; '.join(sorted({capability(snapshot,cat,field,r['id']) for r in source})) if source else 'Sem objetos configurados')
    return prefix+capability(snapshot,cat,field)

def model(snapshot):
    text=snapshot.get('Sistema',{}).get('value',{}).get('Version','')
    match=re.search(r'FortiGate-(\S+)\s+v',text)
    return match[1] if match else 'Desconhecido'

def error_kind(text):
    if re.search(r'permission|denied|privilege|not permitted',text,re.I):return 'Sem permissão'
    if re.search(r'parse error|unknown action|entry not found',text,re.I):return 'Comando inexistente ou não suportado'
    return 'Consulta recusada'

def capability(snapshot,category,field,entry=None):
    source=snapshot.get(category,{})
    if 'error' in source:return source.get('kind','Falha de coleta')
    value=source.get('value',{})
    if entry is not None:value=next((r for r in value if r['id']==entry),{})
    if field in value:return 'Observado na coleta'
    if category=='Senha' and value.get('status')=='disable':return 'Oculto enquanto desativado'
    return 'Ausente — compatibilidade não comprovada'

def session(text):
    fields=dict(re.findall(r'(?m)^([a-z ]+):\s*(.*?)\s*$',text))
    if fields.get('login local')!='ssh':raise ValueError('Sessão atual não confirmada como SSH')
    local=re.fullmatch(r'([^:]+):(\d+\.\d+\.\d+\.\d+):(\d+)',fields.get('login device',''))
    remote=re.fullmatch(r'(\d+\.\d+\.\d+\.\d+):(\d+)',fields.get('login remote',''))
    if not local or not remote or not fields.get('username'):raise ValueError('Origem/interface SSH não identificada (IPv4)')
    ipaddress.IPv4Address(local[2]);ipaddress.IPv4Address(remote[1])
    return {'username':fields['username'],'interface':local[1],'destination':local[2],'source':remote[1]}

def validate_exceptions(rows,labels):
    if not isinstance(rows,list):raise ValueError('Exceções devem ser uma lista')
    seen=set()
    for row in rows:
        if set(row)!={'serial','rule','entry','reason','expires'}:raise ValueError('Exceção: serial, regra, objeto, motivo e validade obrigatórios')
        if not all(isinstance(v,str) for v in row.values()):raise ValueError('Exceção inválida')
        if not row['serial'].strip() or row['rule'] not in labels or len(row['reason'].strip())<10:raise ValueError('Identifique equipamento/regra e justifique a exceção (mínimo 10 caracteres)')
        if row['entry'] and row['rule'] not in ('mfa','trusted_hosts','http_telnet','wan_admin','snmp'):raise ValueError('Esta regra aceita exceção por equipamento; deixe objeto vazio')
        date.fromisoformat(row['expires'])
        key=(row['serial'],row['rule'],row['entry'])
        if key in seen:raise ValueError('Exceção repetida')
        seen.add(key)
    return copy.deepcopy(rows)

def exceptions(policy,serial,rule):
    return [e for e in policy.get('exceptions',[]) if e['serial']==serial and e['rule']==rule and date.fromisoformat(e['expires'])>=date.today()]

def apply_exceptions(findings,policy,serial):
    for finding in findings:
        rows=exceptions(policy,serial,finding['rule'])
        if not rows:continue
        finding['exceptions']=rows
        if any(not r['entry'] for r in rows):
            finding.update(eligible=False,blocked='Exceção aprovada: '+'; '.join(r['reason'] for r in rows))
        elif finding.get('operations'):
            excluded={r['entry'] for r in rows}
            finding['operations']=[o for o in finding['operations'] if o['entry'] not in excluded]
            if not finding['operations']:finding.update(eligible=False,blocked='Todos os objetos divergentes têm exceção vigente')
        finding['evidence']+='; exceções vigentes: '+'; '.join((r['entry'] or 'equipamento')+' — '+r['reason']+' até '+r['expires'] for r in rows)
    return findings

def config_state(snapshot):
    """Sessão e metadados variáveis não participam do controle de drift."""
    return {k:v for k,v in snapshot.items() if k not in ('Session',)}

def compare(before,after):
    def index(report):
        result={}
        for d in report['devices']:
            serial=d['identity'].get('serial')
            key=serial or 'host:'+d['device']['host']
            if key in result:raise ValueError('Equipamento duplicado na verificação')
            result[key]=d
        return result
    a,b=index(before),index(after);rows=[]
    for key in sorted(a.keys()|b.keys()):
        old={f['rule']:f for f in a.get(key,{}).get('findings',[])}
        new={f['rule']:f for f in b.get(key,{}).get('findings',[])}
        for rule in sorted(old.keys()|new.keys()):
            x,y=old.get(rule),new.get(rule)
            if not x:state='Sem referência anterior'
            elif not y:state='Não verificado agora'
            elif 'Não foi possível verificar' in (x['status'],y['status']):state='Inconclusivo'
            elif y['status']=='Conforme':state='Resolvido' if x['status'] not in ('Conforme','Não aplicável') else 'Permanece conforme'
            elif y['status']=='Não aplicável':state='Não aplicável'
            elif x['status']=='Conforme':state='Novo problema'
            else:state='Recorrente'
            rows.append({'equipment':key,'rule':rule,'before':x['status'] if x else 'Ausente','after':y['status'] if y else 'Ausente','result':state,'policy_changed':before['policy']!=after['policy']})
    return rows

def append_journal(path,record):
    import os
    from datetime import datetime,timezone
    with Path(path).open('a',encoding='utf-8') as stream:
        stream.write(json.dumps({'utc':datetime.now(timezone.utc).isoformat(),**record},ensure_ascii=False)+'\n');stream.flush();os.fsync(stream.fileno())

def finish_reaudit(outcomes,refreshed,journal,safety,verify):
    for row in outcomes:
        if row['status']!='Verificado':continue
        fresh=next((d for d in refreshed['devices'] if d['device']==row['device']),None)
        if not fresh or (row.get('identity') and fresh['identity']!=row['identity']) or safety(fresh['snapshot']) or not verify(fresh['snapshot'],row['changes']):
            row.update(status='Reauditoria inconclusiva',detail='Sessão independente não confirmou o estado; nova aplicação bloqueada.')
        append_journal(journal,{'event':'reaudit','device':row['device'],'status':row['status'],'detail':row['detail']})
    append_journal(journal,{'event':'final','outcomes':outcomes})
