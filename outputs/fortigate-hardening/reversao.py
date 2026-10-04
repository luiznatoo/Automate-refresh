"""Reversão revisada, restrita aos campos conhecidos e condicionada ao estado atual."""
import copy
import ipaddress
import json
import re
from pathlib import Path
import remediacao as r

def value(snapshot,op):
    source=snapshot[op['category']]['value']
    if op['entry'] is not None:source=next(x for x in source if x['id']==op['entry'])
    return source.get(op['field'],'')

def validate(op):
    cat,field,text,entry=(op[k] for k in ('category','field','after','entry'))
    allowed={(c,f) for c,f,_,_ in r.RULES.values()}|{('Global','strong-crypto'),('Global','admin-https-ssl-versions'),('Global','admin-lockout-threshold'),('Global','admintimeout'),('Global','admin-lockout-duration'),('Senha','status'),('Senha','minimum-length'),('NTP','ntpsync'),('Interfaces','allowaccess')}
    allowed|={('SNMP',f) for f in ('query-v1-status','query-v2c-status','trap-v1-status','trap-v2c-status')}
    allowed|={('Administradores',f) for f in ('two-factor','email-to','fortitoken',*[f'trusthost{i}' for i in range(1,11)])}
    if (cat,field) not in allowed:raise ValueError('Campo não reversível')
    if (cat in ('Interfaces','Administradores','SNMP'))!=(entry is not None):raise ValueError('Objeto inválido')
    if entry is not None:r.quote(entry)
    if field=='admin-maintainer' and text not in ('enable','disable'):raise ValueError('Valor maintainer inválido')
    if field=='buffer':
        if len(text)>16000 or any(ord(c)<32 and c not in '\n\t' for c in text):raise ValueError('Banner inválido')
    elif field.startswith('trusthost'):ipaddress.IPv4Network(text.replace(' ','/'),strict=True)
    elif not re.fullmatch(r'[A-Za-z0-9_.@+% /:-]{0,250}',text):raise ValueError('Valor de reversão inválido')
    if cat=='SNMP' and not re.fullmatch('[1-9][0-9]*',entry):raise ValueError('ID SNMP inválido')

def batches(ops):
    groups={}
    for op in ops:validate(op);groups.setdefault((op['category'],op['entry']),[]).append(op)
    result=[]
    for (cat,entry),items in groups.items():
        lines=['config '+r.SECTIONS[cat]]
        if entry is not None:lines.append('edit '+r.quote(entry))
        for o in sorted(items,key=lambda o:0 if o['field']=='two-factor' and o['after']=='disable' else 2 if o['field']=='two-factor' else 1):
            text=o['after']
            if o['field']=='buffer':text='"'+text.replace('\\','\\\\').replace('"','\\"')+'"'
            lines.append('set '+o['field']+' '+text if text else 'unset '+o['field'])
        if entry is not None:lines.append('next')
        lines.append('end');result.append(lines)
    return result

def prepare(path,report):
    import hardening as h
    records=[json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines()]
    approval=next(r for r in records if r['event']=='approval');plan=[]
    for item in approval['plan']:
        if not any(r['event']=='before' and r['device']==item['device'] for r in records):continue
        current=next((d for d in report['devices'] if d['identity']==item['identity'] and d['device']==item['device']),None)
        if not current:raise ValueError('Audite o mesmo equipamento/identidade antes da reversão')
        if h.safety(current['snapshot']):raise ValueError(h.safety(current['snapshot']))
        ops=[]
        for op in r.operations(item['changes']):
            if op['field']=='admin-maintainer' and not h.evolucao.legacy_50e(current['snapshot']):raise ValueError('Reversão maintainer requer 50E 6.2.16')
            if op['before']=='Não exposto enquanto desativado':raise ValueError('Valor anterior oculto; use o procedimento do backup')
            actual=value(current['snapshot'],op)
            if actual==op['before']:continue
            if actual!=op['after']:raise ValueError('Campo sofreu outra alteração; reversão bloqueada: '+op['field'])
            rev={**op,'before':op['after'],'after':op['before']};validate(rev);ops.append(rev)
        if ops:plan.append({'device':item['device'],'identity':item['identity'],'group':h.group_id(current['snapshot']),'snapshot_hash':h.digest(h.evolucao.config_state(current['snapshot'])),'operations':ops})
    if not plan:raise ValueError('Nenhum parâmetro conhecido precisa ser revertido')
    return plan

def apply(plan,approved,password,backup_password,timeout,known,folder,cancel):
    import hardening as h
    from datetime import datetime
    if h.digest(plan)!=approved:raise ValueError('Plano de reversão mudou')
    journal=Path(folder)/('reversao_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f')+'.jsonl')
    h.evolucao.append_journal(journal,{'event':'rollback_approval','plan':plan,'plan_hash':approved});rows=[]
    for item in plan:
        if cancel.is_set():break
        connection=None;row={'device':item['device'],'status':'Bloqueado'}
        try:
            for op in item['operations']:validate(op)
            connection=h.Writer(item['device'],password,timeout,known);fresh=h.snapshot(connection)
            if h.safety(fresh) or h.identity(fresh)!=item['identity'] or h.group_id(fresh)!=tuple(item['group']) or h.digest(h.evolucao.config_state(fresh))!=item['snapshot_hash']:raise ValueError('Estado/identidade mudou; audite novamente')
            # Reverse allowaccess may restore access, but must never remove the active SSH path.
            session=fresh.get('Session',{}).get('value',{})
            for op in item['operations']:
                if op['field']=='admin-maintainer' and not h.evolucao.legacy_50e(fresh):raise ValueError('Reversão maintainer requer 50E 6.2.16')
                if op['field']=='allowaccess' and (not session or op['entry']==session['interface'] and 'ssh' not in op['after'].split()):raise ValueError('Caminho SSH não preservado')
                if op['category']=='Administradores' and (not session or op['entry']==session['username']):raise ValueError('Reversão de conta requer outra conta executora')
            backup=h.backup_seguro.save(connection,folder,backup_password,item['identity']);row['backup']=backup
            h.evolucao.append_journal(journal,{'event':'rollback_before','device':item['device'],'backup':backup})
            if cancel.is_set():raise ValueError('Cancelado antes da reversão')
            row['status']='Estado incerto — revisar';connection.write_batches(batches(item['operations']))
            after=h.wait_ha(connection,item,90,cancel,lambda r:h.evolucao.append_journal(journal,r))
            expected=copy.deepcopy(fresh)
            for op in item['operations']:
                if op['field']=='admin-maintainer' and not h.evolucao.legacy_50e(fresh):raise ValueError('Reversão maintainer requer 50E 6.2.16')
                target=expected[op['category']]['value']
                if op['entry'] is not None:target=next(r for r in target if r['id']==op['entry'])
                target[op['field']]=op['after']
            if h.safety(after) or h.digest(h.evolucao.config_state(after))!=h.digest(h.evolucao.config_state(expected)):raise ValueError('Reversão não confirmada integralmente')
            row.update(status='Reversão verificada',detail='Campos anteriores conferidos; execute nova verificação')
        except Exception as exc:row['detail']=str(exc) if type(exc) is ValueError else type(exc).__name__
        finally:
            if connection:connection.close()
        h.evolucao.append_journal(journal,{'event':'rollback_result',**row});rows.append(row)
        if row['status']!='Reversão verificada':break
    return rows,journal
