"""Parser restrito à configuração e identidade usadas pelo hardening."""
import shlex
import re

def commands(text):
    pending='';quote=None;escaped=False
    for line in text.splitlines(keepends=True):
        pending+=line
        for char in line:
            if escaped:escaped=False;continue
            if char=='\\' and quote!="'":escaped=True;continue
            if quote:
                if char==quote:quote=None
            elif char in ('"',"'"):quote=char
        if quote is None:yield pending;pending='';escaped=False
    if pending:raise ValueError('Texto com aspas incompletas')

def config_blocks(text):
    blocks=[];current=None;depth=0
    for raw in commands(text):
        tokens=shlex.split(raw)
        if not tokens:continue
        if tokens[0]=='config':depth+=1
        elif tokens[0]=='end':depth-=1
        elif depth==1 and tokens[0]=='edit':
            current={'id':tokens[1],'settings':{}};blocks.append(current)
        elif depth==1 and tokens[0]=='next':current=None
        elif current is not None and depth==1 and tokens[0] in ('set','unset'):
            if tokens[1] in current['settings']:raise ValueError('Campo repetido')
            current['settings'][tokens[1]]=' '.join(tokens[2:]) if tokens[0]=='set' else ''
    return blocks

def parse(category,text):
    rows=[]
    if category=='Sistema':
        fields={'Version','Serial-Number','Hostname','Virtual domain configuration','Current HA mode'}
        rows=[{'id':k.strip(),'value':v.strip()} for k,v in re.findall(r'(?m)^([^:\n]+):\s*(.*)$',text) if k.strip() in fields]
        ok=any(r['id']=='Version' for r in rows)
    elif category=='HA':
        for label in ('HA Health Status','Mode','Group Name','Group ID'):
            m=re.search(r'(?im)^'+re.escape(label)+r':\s*(.*)',text)
            if m:rows.append({'id':label,'value':m[1].strip()})
        for role,name,serial in re.findall(r'(?im)^\s*(Primary|Secondary|Master|Slave)\s*:\s*([^,\n]+),\s*([^,\s]+)',text):rows.append({'id':'member/'+serial,'value':role.lower()})
        for serial,state in re.findall(r'(?im)^\s*(\S+)\s*(?:\([^\n]*\))?:\s*(in-sync|out-of-sync)\s*$',text):rows.append({'id':'sync/'+serial,'value':state.lower()})
        ok='HA Health Status' in text and bool(rows)
    else:ok=False
    return {'status':'ok' if ok else 'unparsed','rows':rows}
