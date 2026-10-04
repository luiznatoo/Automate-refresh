"""Fortinet text tree retaining original bytes (UTF-8) of unedited commands."""
import re
import shlex

def words(text):
    return shlex.split(text,comments=False,posix=True)

def quote(value):
    value=str(value)
    if any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError('Campo contÃƒÂ©m caracteres de controle.')
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'

class Node:
    def __init__(self,line='',kind='root',key=''):
        self.line=line; self.kind=kind; self.key=key; self.items=[]; self.close=''
    def children(self): return [x for x in self.items if isinstance(x,Node)]
    def child(self,kind,key):
        found=[x for x in self.children() if x.kind==kind and x.key==key]
        if len(found)!=1: raise ValueError(f'Objeto ausente/ambÃƒÂ­guo: {kind} {key}')
        return found[0]
    def optional(self,kind,key): return next((x for x in self.children() if x.kind==kind and x.key==key),None)
    def dump(self): return self.line+''.join(x.dump() if isinstance(x,Node) else x for x in self.items)+self.close
    def settings(self):
        return [(i,x,words(x)) for i,x in enumerate(self.items) if isinstance(x,str) and x.lstrip().startswith(('set ','unset '))]
    def get(self,key,default=None):
        found=[t[2:] for _,_,t in self.settings() if t[0]=='set' and len(t)>1 and t[1]==key]
        if len(found)>1: raise ValueError('Campo repetido: '+key)
        return found[0] if found else default
    def set(self,key,values,changes,path,quoted=False):
        values=[str(v) for v in values]
        if self.get(key)==values: return
        old=self.get(key,[])
        found=[i for i,_,t in self.settings() if len(t)>1 and t[1]==key]
        if len(found)>1: raise ValueError('Campo repetido: '+key)
        newline='\r\n' if '\r\n' in self.line else '\n'
        indent=re.match(r' *',self.line)[0]+'    '
        new=indent+'set '+key+' '+' '.join(quote(v) if quoted else str(v) for v in values)+newline
        if found: self.items[found[0]]=new
        else: self.items.append(new)
        changes.append({'path':path+'/'+key,'before':' '.join(old),'after':' '.join(values)})
    def rename(self,key,changes,path):
        if key==self.key: return
        changes.append({'path':path+'/edit','before':self.key,'after':key})
        self.key=key; self.line=re.match(r' *',self.line)[0]+'edit '+quote(key)+ ('\r\n' if '\r\n' in self.line else '\n')

def commands(text):
    pending=''; state=None; escaped=False
    for line in text.splitlines(keepends=True):
        pending+=line
        # Certificates/HTML contain quoted multiline values. Do not parse their contents as CLI.
        if not state and line.lstrip().startswith('#'):
            yield pending; pending=''; continue
        for c in line:
            if escaped: escaped=False; continue
            if c=='\\' and state!="'": escaped=True; continue
            if state:
                if c==state: state=None
            elif c in ('"',"'"): state=c
        if not state:
            yield pending; pending=''; escaped=False
    if pending: raise ValueError('Texto contÃƒÂ©m aspas nÃƒÂ£o terminadas.')

def parse(text):
    root=Node(); stack=[root]
    for line in commands(text):
        s=line.strip()
        if s.startswith(('config ','edit ')):
            t=words(s); kind=t[0]; key=' '.join(t[1:])

            child=Node(line,kind,key); stack[-1].items.append(child); stack.append(child)
        elif s in ('end','next'):
            if len(stack)==1 or stack[-1].kind!=('config' if s=='end' else 'edit'): raise ValueError('Fechamento inesperado na configuraÃƒÂ§ÃƒÂ£o.')
            stack.pop().close=line
        else: stack[-1].items.append(line)
    if len(stack)!=1: raise ValueError('ConfiguraÃƒÂ§ÃƒÂ£o incompleta.')
    for parent,path in [(root,'')]+list(walk(root)):
        seen=set()
        for child in parent.children():
            identity=(child.kind,child.key)
            if identity in seen:
                append_only=(path=='/config firewall addrgrp' and child.kind=='edit' and
                    bool(child.items) and all(isinstance(item,str) and item.strip().startswith('append member ') for item in child.items))
                if not append_only: raise ValueError('Objeto duplicado: '+child.key)
            seen.add(identity)
    return root

def walk(node,path=''):
    for child in node.children():
        p=path+'/'+child.kind+' '+child.key
        yield child,p
        yield from walk(child,p)

def protected(root):
    """All ENC and credential/certificate statements must remain byte-identical."""
    result=[]
    for node,path in walk(root):
        for _,raw,t in node.settings():
            key=t[1] if len(t)>1 else ''
            if 'ENC' in t or re.search(r'password|passwd|secret|(?:^|-)key$|certificate|community',key,re.I):
                # Paths may rename BGP neighbor keys; statement content remains exact.
                result.append(raw)
    return sorted(result)
