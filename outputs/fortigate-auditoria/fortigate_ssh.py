# Shared core is resolved for both source and portable distributions.
import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent/'refresh_core').is_dir():
        if str(_parent) not in _sys.path:_sys.path.insert(0,str(_parent))
        break
else:raise ImportError('refresh_core ausente: use o pacote completo da Central')
from refresh_core.ssh import SSH as SharedSSH, clean, redact
COMMANDS = {"Sistema": "get system status", "HA": "get system ha status", "ARP": "get system arp", "DHCP": "execute dhcp lease-list"}
class SSH(SharedSSH):
    command_set=COMMANDS
