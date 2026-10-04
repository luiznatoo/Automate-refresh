"""Propostas estruturadas. Nenhum campo aceita comandos CLI livres."""
import evolucao
import copy
import ipaddress
import re
from padrao_empresa import RULES

DEFAULTS={'redes_gerencia':[], 'origem_ssh':'', 'interface_gerencia':'', 'mfa_email':{}, 'smtp_validado':False,'mfa_tokens':{}}
SECTIONS={'Global':'system global','Interfaces':'system interface','Administradores':'system admin',
          'Senha':'system password-policy','NTP':'system ntp','SNMP':'system snmp community',
          'FortiAnalyzer':'log fortianalyzer setting','AutoInstall':'system auto-install',
          'Eventos':'log eventfilter','BannerPre':'system replacemsg admin "pre_admin-disclaimer-text"',
          'BannerPost':'system replacemsg admin "post_admin-disclaimer-text"'}

def validate(options):
    options=copy.deepcopy(options)
    options.setdefault('mfa_tokens',{})
    if not isinstance(options,dict) or set(options)!=set(DEFAULTS):raise ValueError('Parâmetros de correção inválidos')
    nets=options['redes_gerencia']
    if not isinstance(nets,list) or len(nets)>10:raise ValueError('Informe até 10 redes IPv4 autorizadas')
    for net in nets:
        n=ipaddress.IPv4Network(net,strict=True)
        if n.prefixlen==0:raise ValueError('Trusted hosts não aceita rede 0.0.0.0/0')
    if options['origem_ssh']:ipaddress.IPv4Address(options['origem_ssh'])
    if not isinstance(options['interface_gerencia'],str) or not re.fullmatch(r'[A-Za-z0-9_.:/-]{0,79}',options['interface_gerencia']):raise ValueError('Interface de gerência inválida')
    if type(options['smtp_validado']) is not bool:raise ValueError('Confirmação SMTP inválida')
    if not isinstance(options['mfa_email'],dict):raise ValueError('Informe conta e e-mail para MFA')
    for account,email in options['mfa_email'].items():
        quote(account)
        if not re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}',email):raise ValueError('E-mail MFA inválido para '+account)
    if not isinstance(options['mfa_tokens'],dict):raise ValueError('Mapa FortiToken inválido')
    for account,token in options['mfa_tokens'].items():
        quote(account)
        if not re.fullmatch(r'FTK[A-Za-z0-9]{6,40}',token):raise ValueError('Serial FortiToken inválido')
        if account in options['mfa_email']:raise ValueError('Escolha apenas um método MFA por conta')
    if len(set(options['mfa_tokens'].values()))!=len(options['mfa_tokens']):raise ValueError('FortiToken repetido')
    return copy.deepcopy(options)

def quote(text):
    if not isinstance(text,str) or not text or any(ord(c)<32 for c in text):raise ValueError('Nome inválido')
    return '"'+text.replace('\\','\\\\').replace('"','\\"')+'"'

def propose(rule,s,p):
    ops=[];options=p['correcoes']
    def add(category,field,value,entry=None):
        source=s[category]['value']
        if entry is not None:source=next(x for x in source if x['id']==entry)
        # Missing parameters never get guessed. email-to may be hidden until MFA is enabled.
        if field not in source and not ((category=='Administradores' and field in ('email-to','fortitoken')) or (category=='Senha' and field=='minimum-length' and source.get('status')=='disable')):
            raise ValueError('Campo '+field+' não foi coletado; refaça a verificação')
        before=source.get(field,'Não exposto enquanto desativado' if category=='Senha' else '')
        if str(before)!=str(value):ops.append({'category':category,'entry':entry,'field':field,'before':str(before),'after':str(value)})
    if rule in RULES:
        cat,field,value,_=RULES[rule]
        if rule=='maintainer' and not evolucao.legacy_50e(s):raise ValueError('Correção maintainer disponível somente no 50E com FortiOS 6.2.16')
        if rule in ('texto_pre','texto_post'):value=p['banners']['pre' if rule=='texto_pre' else 'post']
        add(cat,field,value,p['mapa_interfaces'][rule.split('_')[1]] if cat=='Interfaces' else None)
        if rule in ('banner_pre','banner_post'):
            key='pre' if rule=='banner_pre' else 'post'
            add('BannerPre' if key=='pre' else 'BannerPost','buffer',p['banners'][key])
    elif rule in ('cripto','tls','ntp'):
        cat,field,value={'cripto':('Global','strong-crypto','enable'),'tls':('Global','admin-https-ssl-versions',' '.join(p['tls_permitidos'])),'ntp':('NTP','ntpsync','enable')}[rule]
        add(cat,field,value)
    elif rule=='senha':
        add('Senha','status','enable')
        add('Senha','minimum-length',max(int(s['Senha']['value'].get('minimum-length',p['senha_min'])),p['senha_min']))
    elif rule in ('http_telnet','wan_admin'):
        rows=s['Interfaces']['value']
        for row in rows:
            if 'allowaccess' not in row:continue
            if rule=='wan_admin' and row.get('role')!='wan':continue
            old=row['allowaccess'].split();remove={'http','telnet'} if rule=='http_telnet' else {'http','https','ssh','telnet'}
            if set(old)&remove:add('Interfaces','allowaccess',' '.join(x for x in old if x not in remove),row['id'])
        if rule=='wan_admin' and ops:
            protected=options['interface_gerencia']
            management=next((r for r in rows if r['id']==protected),None)
            if not management or 'ssh' not in management.get('allowaccess','').split():raise ValueError('Informe uma interface de gerência com SSH preservado em Parâmetros de correção')
            if any(o['entry']==protected for o in ops):raise ValueError('A remoção de acesso WAN atingiria a interface de gerência. Use outro caminho de gerência')
    elif rule=='trusted_hosts':
        nets=[ipaddress.IPv4Network(n) for n in options['redes_gerencia']]
        if not nets or not options['origem_ssh']:raise ValueError('Informe redes autorizadas e IP de origem SSH visto pelo firewall em Parâmetros de correção')
        if not any(ipaddress.IPv4Address(options['origem_ssh']) in n for n in nets):raise ValueError('A origem SSH precisa estar dentro das redes autorizadas')
        for row in s['Administradores']['value']:
            if not all(ipaddress.IPv4Network(row[f'trusthost{i}'].replace(' ','/'),strict=False).prefixlen==0 for i in range(1,11)):continue
            for i,n in enumerate(nets,1):add('Administradores',f'trusthost{i}',f'{n.network_address} {n.netmask}',row['id'])
    elif rule=='mfa':
        for row in s['Administradores']['value']:
            if row['remote-auth']=='disable' and row['two-factor']=='disable':
                token=options.get('mfa_tokens',{}).get(row['id'])
                if token:
                    available={r['id']:r['status'] for r in s.get('Tokens',{}).get('value',[])}
                    if available.get(token)!='active':raise ValueError('FortiToken deve estar provisionado/ativo na coleta: '+token)
                    if 'value' not in s.get('TokenUsers',{}):raise ValueError('Coleta de vínculos FortiToken de usuários necessária')
                    if any(r.get('fortitoken')==token for r in s['TokenUsers']['value']):raise ValueError('FortiToken já atribuído a usuário VPN')
                    if any(r.get('fortitoken')==token for r in s['Administradores']['value'] if r['id']!=row['id']):raise ValueError('FortiToken já atribuído a outra conta')
                    add('Administradores','fortitoken',token,row['id']);add('Administradores','two-factor','fortitoken',row['id'])
                else:
                    if not options['smtp_validado'] or not s.get('Email',{}).get('value',{}).get('server'):raise ValueError('MFA por e-mail exige SMTP coletado e teste de entrega confirmado')
                    email=options['mfa_email'].get(row['id'])
                    if not email:raise ValueError('Informe e-mail ou FortiToken da conta '+row['id'])
                    add('Administradores','two-factor','email',row['id']);add('Administradores','email-to',email,row['id'])
    elif rule=='snmp':
        for row in s['SNMP']['value']:
            if row['status']=='enable':
                for field in ('query-v1-status','query-v2c-status','trap-v1-status','trap-v2c-status'):add('SNMP',field,'disable',row['id'])
    else:raise ValueError('Regra de correção desconhecida')
    return ops

def validate_op(op):
    cat,field,value,entry=(op[k] for k in ('category','field','after','entry'))
    if cat not in SECTIONS or not isinstance(value,str):raise ValueError('Operação inválida')
    block=cat in ('Interfaces','Administradores','SNMP')
    if block!=(entry is not None):raise ValueError('Destino inválido')
    if entry is not None:quote(entry)
    if cat=='SNMP' and not re.fullmatch(r'[1-9][0-9]*',entry):raise ValueError('ID SNMP inválido')
    if field=='buffer' and cat in ('BannerPre','BannerPost'):
        if not value.strip() or len(value)>16000 or any(ord(c)<32 and c not in '\n\t' for c in value):raise ValueError('Banner inválido')
        return
    if any(ord(c)<32 for c in value):raise ValueError('Controle não permitido no valor')
    allowed={(c,f):{str(v)} for c,f,v,_ in RULES.values() if c!='Interfaces'}
    allowed.update({('Global','strong-crypto'):{'enable'},('NTP','ntpsync'):{'enable'},('Senha','status'):{'enable'}})
    if cat=='Interfaces':
        if field=='allowaccess':
            if not set(value.split())<={'ping','https','ssh','snmp','http','telnet','fgfm','radius-acct','probe-response','fabric','ftm','speed-test'}:raise ValueError('Serviço administrativo desconhecido')
            return
        allowed.update({('Interfaces',f):{str(v)} for c,f,v,_ in RULES.values() if c=='Interfaces' and f!='role'})
        allowed[('Interfaces','role')]={'lan','wan'}
    if cat=='Global' and field in ('admintimeout','admin-lockout-threshold','admin-lockout-duration'):
        lo,hi={'admintimeout':(1,30),'admin-lockout-threshold':(1,10),'admin-lockout-duration':(60,900)}[field]
        if not value.isdigit() or not lo<=int(value)<=hi:raise ValueError('Limite inválido')
        return
    if cat=='Global' and field=='admin-https-ssl-versions':
        if not value.split() or not set(value.split())<={'tlsv1-2','tlsv1-3'}:raise ValueError('TLS inválido')
        return
    if cat=='Senha' and field=='minimum-length':
        if not value.isdigit() or not 8<=int(value)<=128:raise ValueError('Comprimento inválido')
        return
    if cat=='SNMP' and field in ('query-v1-status','query-v2c-status','trap-v1-status','trap-v2c-status') and value=='disable':return
    if cat=='Administradores':
        if re.fullmatch(r'trusthost(?:[1-9]|10)',field):
            n=ipaddress.IPv4Network(value.replace(' ','/'),strict=True)
            if n.prefixlen==0:raise ValueError('Rede irrestrita')
            return
        if field=='two-factor' and value in ('email','fortitoken'):return
        if field=='fortitoken' and re.fullmatch(r'FTK[A-Za-z0-9]{6,40}',value):return
        if field=='email-to' and re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}',value):return
    if value not in allowed.get((cat,field),set()):raise ValueError('Correção fora da lista permitida')

def operations(changes):
    merged={}
    for change in changes:
        ops=change.get('operations')
        if ops is None:ops=[{'category':'Global','entry':None,'field':change['field'],'before':str(change.get('before','')),'after':str(change['after'])}]
        for op in ops:
            validate_op(op);key=(op['category'],op['entry'],op['field'])
            if key in merged and merged[key]['after']!=op['after']:
                if key[2]!='allowaccess':raise ValueError('Propostas conflitantes para o mesmo parâmetro')
                merged[key]['after']=' '.join(v for v in merged[key]['after'].split() if v in op['after'].split())
            else:merged[key]=copy.deepcopy(op)
    if not merged:raise ValueError('Sem alterações')
    return list(merged.values())

def cli(op):
    validate_op(op)
    cat,entry,field,value=(op[k] for k in ('category','entry','field','after'))
    lines=['config '+SECTIONS[cat]]
    if entry is not None:lines.append('edit '+quote(entry))
    if field=='buffer':value='"'+value.replace('\\','\\\\').replace('"','\\"')+'"'
    if not value:lines.append('unset '+field)
    else:lines.append('set '+field+' '+value)
    if entry is not None:lines.append('next')
    lines.append('end')
    return lines

def expected(snapshot,changes):
    result=copy.deepcopy(snapshot)
    for op in operations(changes):
        target=result[op['category']]['value']
        if op['entry'] is not None:target=next(r for r in target if r['id']==op['entry'])
        target[op['field']]=op['after']
    return result

def batches(changes):
    grouped={}
    for op in operations(changes):grouped.setdefault((op['category'],op['entry']),[]).append(op)
    result=[]
    for (category,entry),ops in sorted(grouped.items(),key=lambda pair:0 if pair[0][0] in ('BannerPre','BannerPost') else 1):
        # Set the MFA destination before enabling the method in the same edit block.
        ops.sort(key=lambda op:op['field']=='two-factor')
        lines=['config '+SECTIONS[category]]
        if entry is not None:lines.append('edit '+quote(entry))
        for op in ops:lines.append(cli(op)[2 if entry is not None else 1])
        if entry is not None:lines.append('next')
        lines.append('end');result.append(lines)
    return result
