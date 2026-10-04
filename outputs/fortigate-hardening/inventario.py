import csv
from pathlib import Path
FIELDS=["nome","host","porta","usuario"]

def inventory(path):
    text=Path(path).read_text(encoding='utf-8-sig')
    if not text.strip(): raise ValueError('Inventário vazio')
    import io
    reader=csv.DictReader(io.StringIO(text),delimiter=';' if ';' in text.splitlines()[0] else ',')
    if not {'nome','host'}<=set(reader.fieldnames or []): raise ValueError('CSV precisa de nome e host.')
    return validate_devices(list(reader))

def validate_devices(items,allow_empty=False):
    rows=[]; seen=set()
    for number,row in enumerate(items,2):
        d={k:str(row.get(k) or '').strip() for k in FIELDS}
        if not d['nome'] or not d['host']: raise ValueError(f'Linha {number}: nome/host obrigatório')
        if any(c.isspace() for c in d['host']) or any(c in d['host'] for c in '/\\@?#'):raise ValueError('Host deve ser IP ou nome DNS, sem protocolo, porta ou espaços')
        if any(ord(c)<32 for v in d.values() for c in v):raise ValueError('Campos não podem conter caracteres de controle')
        d['porta']=int(d['porta'] or 22)
        if not 1<=d['porta']<=65535: raise ValueError('Porta SSH inválida')
        endpoint=(d['host'].lower(),d['porta'])
        if endpoint in seen: raise ValueError(f'Equipamento repetido: {d["host"]}')
        seen.add(endpoint)
        rows.append(d)
    if not rows and not allow_empty: raise ValueError('Inventário vazio')
    return rows
