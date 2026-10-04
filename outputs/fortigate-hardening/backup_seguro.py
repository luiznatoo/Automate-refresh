"""Backup SCP sys_config criptografado localmente; nunca registra conteúdo em logs."""
import base64
import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

LIMIT=32*1024*1024

def key(password,salt):
    if len(password)<12:raise ValueError('Senha do backup precisa ter pelo menos 12 caracteres')
    return PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=600000).derive(password.encode())

def download(connection):
    channel=connection.client.get_transport().open_session(timeout=connection.timeout)
    channel.settimeout(connection.timeout)
    def exact(n):
        data=b''
        while len(data)<n:
            part=channel.recv(min(65536,n-len(data)))
            if not part:raise ValueError('Backup SCP incompleto')
            data+=part
        return data
    def line():
        value=b''
        while not value.endswith(b'\n'):
            value+=exact(1)
            if len(value)>1024:raise ValueError('Resposta SCP inválida')
        return value
    try:
        channel.exec_command('scp -f sys_config');channel.sendall(b'\0')
        header=line()
        if header.startswith(b'T'):channel.sendall(b'\0');header=line()
        import re
        match=re.fullmatch(rb'C[0-7]{4} ([0-9]+) [^/\\\r\n]+\n',header)
        if not match:raise ValueError('Backup recusado: confirme admin-scp habilitado e conta super_admin')
        size=int(match[1])
        if not 100<=size<=LIMIT:raise ValueError('Tamanho de backup inválido')
        channel.sendall(b'\0');data=exact(size)
        if exact(1)!=b'\0':raise ValueError('Transferência SCP não confirmada')
        channel.sendall(b'\0')
        if not data.startswith(b'#config-version=') or b'config system global' not in data or not data.rstrip().endswith(b'end'):
            raise ValueError('Arquivo de configuração SCP não reconhecido')
        return data
    finally:channel.close()

def save(connection,folder,password,identity):
    from refresh_core.storage import write_json
    import uuid
    data=download(connection);salt=os.urandom(16);nonce=os.urandom(12)
    meta={'schema':1,'identity':identity,'sha256':hashlib.sha256(data).hexdigest(),'format':'FortiOS sys_config'}
    aad=json.dumps(meta,sort_keys=True).encode()
    encrypted=AESGCM(key(password,salt)).encrypt(nonce,data,aad)
    path=Path(folder)/('backup_'+uuid.uuid4().hex+'.fgbackup')
    write_json(path,{'meta':meta,'salt':base64.b64encode(salt).decode(),'nonce':base64.b64encode(nonce).decode(),'data':base64.b64encode(encrypted).decode()})
    guide=path.with_suffix('.restauracao.txt')
    guide.write_text('Backup da configuração do equipamento '+identity['serial']+' / FortiOS '+identity['version']+'.\n'
        '1. Use Exportar backup para descriptografar com a senha definida na aplicação.\n'
        '2. Confira serial/modelo/firmware e programe janela: restauração interrompe tráfego e reinicia o firewall.\n'
        '3. Use Restore Configuration na interface do FortiGate e selecione o .conf exportado.\n'
        '4. Acesse por console/gerência, valide HA, rotas, VPNs e execute nova verificação.\n'
        'O programa não restaura automaticamente. Backup SCP não substitui exportação separada de certificados/chaves não incluídos pelo firmware.\n',encoding='utf-8')
    return {'path':str(path),'sha256':meta['sha256'],'procedure':str(guide)}

def decrypt(path,password):
    obj=json.loads(Path(path).read_text(encoding='utf-8'))
    if obj['meta']['schema']!=1:raise ValueError('Formato de backup desconhecido')
    data=AESGCM(key(password,base64.b64decode(obj['salt']))).decrypt(base64.b64decode(obj['nonce']),base64.b64decode(obj['data']),json.dumps(obj['meta'],sort_keys=True).encode())
    if hashlib.sha256(data).hexdigest()!=obj['meta']['sha256']:raise ValueError('Integridade do backup inválida')
    return data
