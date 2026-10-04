import json
import os
import uuid
from pathlib import Path
from datetime import datetime,timezone

def now():return datetime.now(timezone.utc).isoformat()

def write_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    try:
        with temp.open('x',encoding='utf-8') as f:
            json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()

def event(kind,path=None,status='Concluído',detail=''):
    folder=os.getenv('REFRESH_HISTORY')
    if not folder:return
    record={'at':now(),'run':os.getenv('REFRESH_RUN_ID',''),'tool':os.getenv('REFRESH_TOOL',''),
            'kind':kind,'status':status,'detail':detail,'path':str(Path(path).resolve()) if path else ''}
    write_json(Path(folder)/('event_'+uuid.uuid4().hex+'.json'),record)

def history(folder):
    rows=[]
    for path in Path(folder).glob('*.json'):
        try:rows.append(json.loads(path.read_text(encoding='utf-8')))
        except (ValueError,OSError):continue
    return sorted(rows,key=lambda r:r.get('at',''),reverse=True)
