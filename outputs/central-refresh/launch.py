import sys
from pathlib import Path
for parent in Path(__file__).resolve().parents:
    if (parent/'refresh_core').is_dir():sys.path.insert(0,str(parent));break
from refresh_core.runner import run
script=Path(sys.argv[1]).resolve();sys.path.insert(0,str(script.parent));sys.argv=[str(script)]
run(script)
