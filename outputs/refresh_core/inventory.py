"""Cadastro central: referências de credenciais, nunca senhas."""
import csv
import hashlib
import json
import os
import re
from pathlib import Path
from .storage import write_json

FIELDS=['unidade','nome','host','porta','plataforma','grupo']
GROUP_FIELDS=['nome','usuario','password_env','secret_env','key_file']
PLATFORMS=('fortinet','juniper_junos','cisco_ios','cisco_nxos')

def validate(data):
    if set(data)!={'schema','units','groups','devices'} or data['schema']!=1:raise ValueError('Cadastro incompatível')
    if len(set(data['units']))!=len(data['units']):raise ValueError('Unidades repetidas')
    if any(not isinstance(x,str) or not x.strip() or any(ord(c)<32 for c in x) for x in data['units']):raise ValueError('Unidade inválida')
    groups={}
    for g in data['groups']:
        if set(g)!=set(GROUP_FIELDS) or any(not isinstance(v,str) or any(ord(c)<32 for c in v) for v in g.values()):raise ValueError('Grupo inválido; senhas não podem ser salvas')
        if not g['nome'] or g['nome'] in groups:raise ValueError('Grupo vazio/repetido')
        for key in ('password_env','secret_env'):
            if g[key] and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',g[key]):raise ValueError('Use nome de variável de ambiente para '+key)
            if g[key].upper() in ('PATH','HOME','USERPROFILE','SYSTEMROOT','WINDIR','TEMP','TMP','PYTHONPATH','PYTHONHOME','CODEX_HOME') or g[key].upper().startswith('REFRESH_'):raise ValueError('Nome de variável reservado; use por exemplo UNIDADE_PASSWORD')
        if g['key_file'] and not Path(g['key_file']).expanduser().is_absolute():raise ValueError('Informe o caminho absoluto da chave SSH')
        groups[g['nome']]=g
    seen=set();names=set()
    for d in data['devices']:
        if set(d)!=set(FIELDS):raise ValueError('Colunas de equipamento inválidas')
        if d['unidade'] not in data['units'] or d['grupo'] not in groups:raise ValueError('Unidade/grupo não cadastrado')
        if d['plataforma'] not in PLATFORMS or not d['nome'].strip():raise ValueError('Nome/plataforma inválido')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+',d['host']):raise ValueError('Host deve ser IP ou DNS, sem protocolo')
        if not str(d['porta']).isdigit() or not 1<=int(d['porta'])<=65535:raise ValueError('Porta inválida')
        if any(any(ord(c)<32 for c in str(v)) for v in d.values()):raise ValueError('Caracteres de controle não permitidos')
        endpoint=(d['unidade'],d['host'].casefold(),int(d['porta']));name=(d['unidade'],d['nome'].casefold())
        if endpoint in seen or name in names:raise ValueError('Equipamento repetido na unidade')
        seen.add(endpoint);names.add(name)
    return data

def read(path):
    if not Path(path).exists():return {'schema':1,'units':[],'groups':[],'devices':[]}
    return validate(json.loads(Path(path).read_text(encoding='utf-8')))

def save(path,data):write_json(path,validate(data))

def password_key(group):return group['password_env'] or 'REFRESH_PASS_'+hashlib.sha256(group['nome'].encode()).hexdigest()[:12].upper()

def devices(data,unit):
    groups={g['nome']:g for g in data['groups']};rows=[]
    for d in data['devices']:
        if d['unidade']!=unit:continue
        g=groups[d['grupo']]
        rows.append({'nome':d['nome'],'host':d['host'],'porta':str(d['porta']),'plataforma':d['plataforma'],
                     **{k:g[k] for k in ('usuario','password_env','secret_env','key_file')},'password_env':password_key(g)})
    return rows

def dispatch(path,data,unit,tool):
    rows=devices(data,unit)
    if tool=='fortigate-hardening':rows=[r for r in rows if r['plataforma']=='fortinet']
    elif tool!='localizador-mac':return None
    if not rows:raise ValueError('A unidade selecionada não tem equipamentos compatíveis com esta ferramenta')
    # Hardening uses one SSH password per execution. Never collapse different groups silently.
    if tool=='fortigate-hardening':
        if len({r['password_env'] for r in rows})>1:raise ValueError('Esta ferramenta usa uma senha por lote. Separe a unidade por grupo de senha para este lançamento')
        if any(r['key_file'] for r in rows):raise ValueError('Hardening usa senha nesta interface. Selecione um grupo sem chave SSH')
    write_json(path,{'tool':tool,'unit':unit,'devices':rows})
    return Path(path)

def preload(app,tool):
    path=os.getenv('REFRESH_INVENTORY')
    if not path:return
    data=json.loads(Path(path).read_text(encoding='utf-8'))
    if data['tool']!=tool:raise ValueError('Inventário destinado a outra ferramenta')
    rows=data['devices']
    if tool=='fortigate-hardening':
        app.inventory.set_rows(rows)
        password=os.getenv(rows[0].get('password_env',''),'')
        if password:app.values['senha'].set(password)
    else:
        app.editors['switches'].set_rows([r for r in rows if r['plataforma']!='fortinet'])
        app.editors['firewalls'].set_rows([r for r in rows if r['plataforma']=='fortinet'])
        app.settings['modo'].set('integrado' if any(r['plataforma']=='fortinet' for r in rows) else 'lista')
        app.settings['mesma_senha'].set(False);app.refresh_credentials()
    app.status.set('Cadastro central carregado: '+data['unit']+'. Confira os destinos e informe as senhas da sessão.')
