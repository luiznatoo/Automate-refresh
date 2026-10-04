"""Transporte FortiGate somente leitura; paginação sem alterar console."""
import re
import time



def clean(text):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text).replace('\r', '')
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)


def redact(text, password=''):
    if password:
        text = text.replace(password, '[OCULTO]')
    return re.sub(r'(?im)^(\s*set\s+\S*(?:password|passwd|secret|psk|private-key|community)\S*\s+).*$', r'\1[OCULTO]', text)


class SSH:
    command_set = {}
    """Paramiko shell: handles pagination without changing FortiOS console configuration."""
    def __init__(self, device, password, timeout, known_hosts):
        import paramiko
        interactive=callable(getattr(password,'respond',None))
        if interactive:
            auth=password
            class InteractiveClient(paramiko.SSHClient):
                def _auth(client,username,*args,**kwargs):
                    client._transport.auth_interactive(username,lambda title,instructions,prompts:auth.respond(device.get('nome',device['host'])+' / '+device['host'],instructions,prompts))
            self.client=InteractiveClient()
            password=None
        else:
            self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        if known_hosts:
            self.client.load_host_keys(str(known_hosts))
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.timeout, self.prompt = timeout, ''
        try:
            self.client.connect(device['host'], port=device['porta'], username=device['usuario'],
                                password=password or None, key_filename=device.get('key_file') or None,
                                look_for_keys=False, allow_agent=False, timeout=timeout,
                                auth_timeout=timeout+120 if interactive else timeout, banner_timeout=timeout)
            self.channel = self.client.invoke_shell(width=240, height=1000)
            initial = self.receive(initial=True)
            self.prompt = initial.splitlines()[-1].strip()
        except Exception:
            self.client.close()
            raise

    def receive(self, initial=False, prompt_pattern=None):
        buffer, last = '', time.monotonic()
        banner_accepted=False
        deadline = last + self.timeout
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(65536).decode('utf-8', errors='replace')
                if not chunk:
                    raise ConnectionError('Sessão SSH encerrada')
                buffer += chunk
                last = time.monotonic()
                if len(buffer) > 32 * 1024 * 1024:
                    raise ValueError('Saída excede 32 MiB; coleta interrompida para não truncar dados')
                if '--More--' in buffer:
                    buffer = buffer.replace('--More--', '')
                    self.channel.send(' ')
            else:
                if self.channel.closed or self.channel.exit_status_ready():
                    raise ConnectionError('Sessão SSH encerrada')
                visible = clean(buffer)
                lines = visible.rstrip().splitlines()
                end = lines[-1].strip() if lines else ''
                if initial and not banner_accepted and re.search(r'(?i)(?:press\s+)?[\[\(\x27\"]?a[\]\)\x27\"]?\s+to accept',end):
                    self.channel.send('a\r');banner_accepted=True;buffer='';continue
                ready = bool(re.fullmatch(r'[^\n]{1,200}[#$]', end)) if initial else end == self.prompt
                if prompt_pattern is not None:
                    ready = bool(re.fullmatch(prompt_pattern, end))
                if ready and time.monotonic() - last > .25:
                    return visible
                time.sleep(.03)
        raise TimeoutError('Tempo de espera SSH esgotado; saída incompleta não será comparada')

    def command(self, command):
        if command not in self.command_set.values():
            raise ValueError('Comando fora da lista de consultas')
        self.channel.send(command + '\n')
        text = self.receive()
        lines = text.rstrip().splitlines()
        if lines and lines[-1].strip() == self.prompt:
            lines.pop()
        if lines and lines[0].strip() in (command, self.prompt + ' ' + command):
            lines.pop(0)
        return '\n'.join(lines)

    def close(self):
        self.client.close()



def connect_switch(**parameters):
    from netmiko import ConnectHandler
    parameters.update(ssh_strict=True,system_host_keys=True)
    return ConnectHandler(**parameters)
