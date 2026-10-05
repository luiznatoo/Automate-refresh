"""Versioned updates: validate payload, create new installation, migrate user data."""
import hashlib
import json
import shutil
import stat
import zipfile
from pathlib import Path,PurePosixPath
from datetime import datetime

DATA_DIRS={'dados','logs','resultados','relatorios','coletas','projetos','projects'}
SETTINGS={'inventario.csv','politica_hardening.json','regras.json','projeto_coleta.json'}

def inspect(archive):
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        manifests=[n for n in names if n.endswith('/release.json') and len(PurePosixPath(n).parts)==2]
        if len(manifests)!=1:raise ValueError('Pacote deve ter uma única release.json na raiz da Central')
        prefix=manifests[0].rsplit('/',1)[0]+'/'
        if len(set(names))!=len(names) or len(names)>50000:raise ValueError('Pacote duplicado ou excessivo')
        if sum(i.file_size for i in z.infolist())>3*1024**3:raise ValueError('Pacote excede 3 GiB')
        for i in z.infolist():
            parts=PurePosixPath(i.filename).parts
            if not i.filename.startswith(prefix) or '..' in parts or '\\' in i.filename or ':' in i.filename or stat.S_ISLNK(i.external_attr>>16):raise ValueError('Caminho inseguro no pacote')
        meta=json.loads(z.read(manifests[0]))
        if meta.get('schema')!=1 or not isinstance(meta.get('files'),dict):raise ValueError('Manifesto inválido')
        actual={n[len(prefix):] for n in names if not n.endswith('/') and n!=manifests[0]}
        if actual!=set(meta['files']):raise ValueError('Conteúdo difere do manifesto')
        for name,digest in meta['files'].items():
            if hashlib.sha256(z.read(prefix+name)).hexdigest()!=digest:raise ValueError('Arquivo corrompido: '+name)
        if 'CentralRefresh.exe' not in actual:raise ValueError('Executável ausente')
        return meta,prefix

def migrate(source,destination,manifest,preserve_existing=False):
    source=Path(source).resolve();destination=Path(destination).resolve();copied=[]
    if source==destination or source.is_relative_to(destination) or destination.is_relative_to(source):raise ValueError('As instalações devem estar em pastas independentes')
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    for file in source.rglob('*'):
        if not file.is_file() or not file.resolve().is_relative_to(source):continue
        rel=file.relative_to(source)
        if file.name in ('release.json','version.json'):continue
        if any(p in ('_internal','__pycache__','bases','empacotar','refresh_core') for p in rel.parts):continue
        is_data=bool(set(rel.parts[:-1])&DATA_DIRS) or file.name in SETTINGS
        custom=rel.as_posix() not in manifest['files'] and file.suffix.lower() in ('.json','.csv','.xlsx','.conf','.jsonl')
        if not (is_data or custom):continue
        if file.suffix.lower() in ('.py','.pyw','.exe','.dll','.pyd'):continue
        target=destination/rel
        if preserve_existing and target.exists():
            digest=hashlib.sha256(target.read_bytes()).hexdigest()
            if target.read_bytes()==file.read_bytes():continue
            if digest!=manifest['files'].get(rel.as_posix()):target=destination/'dados/importados'/stamp/rel
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(file,target);copied.append(target.relative_to(destination).as_posix())
    if (source/'central.py').exists() and not (source/'ferramentas').exists() and (source.parent/'refresh_core').exists():
        for module in ('fortigate-hardening','switch-mapper','localizador-mac','fortigate-config','fortiswitch-config'):
            folder=source.parent/module
            if not folder.is_dir():continue
            prefix='ferramentas/'+module+'/'
            subset={'files':{k[len(prefix):]:v for k,v in manifest['files'].items() if k.startswith(prefix)}}
            copied.extend(prefix+r for r in migrate(folder,destination/'ferramentas'/module,subset,preserve_existing))
    return copied

def install(archive,source,parent):
    meta,prefix=inspect(archive)
    version=meta['version']
    if not isinstance(version,str) or not all(c.isdigit() or c=='.' for c in version):raise ValueError('Versão inválida')
    parent=Path(parent).resolve();source=Path(source).resolve()
    if parent==source or parent.is_relative_to(source):raise ValueError('Escolha uma pasta fora da instalação atual')
    target=parent/('CentralRefresh-'+version+'-'+datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    target.mkdir(parents=True,exist_ok=False)
    try:
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.is_dir():continue
                path=target/info.filename[len(prefix):]
                if not path.resolve().is_relative_to(target):raise ValueError('Destino inválido')
                path.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as incoming,path.open('xb') as outgoing:shutil.copyfileobj(incoming,outgoing)
        copied=migrate(source,target,meta)
        from .storage import write_json,now
        write_json(target/'dados/atualizacao.json',{'at':now(),'from':str(source),'version':version,'preserved':copied})
    except Exception:
        # Preserve an incomplete extraction for diagnosis; never alter or delete the source installation.
        (target/'ATUALIZACAO_INCOMPLETA.txt').write_text('Não abra esta instalação; repita a atualização a partir da instalação anterior.',encoding='utf-8')
        raise
    return target,len(copied)
