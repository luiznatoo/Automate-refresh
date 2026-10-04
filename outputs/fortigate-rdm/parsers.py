"""Extração conservadora: saída não reconhecida nunca equivale a tabela vazia."""
import ipaddress
import re
import shlex

IP = r'(?:\d{1,3}\.){3}\d{1,3}'
MAC = r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'


def result(rows, recognized, warnings=None):
    warnings = warnings or []
    return {'status': 'ok' if recognized and not warnings else 'unparsed', 'rows': rows,
            'error': '; '.join(warnings) if warnings else '' if recognized else 'Formato não reconhecido; comparar manualmente o log.'}


def config_blocks(text):
    """Only outer edit blocks; nested sections kept as canonical configuration."""
    blocks, current, depth = [], None, 0
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('config '):
            depth += 1
        elif line == 'end':
            depth -= 1
        elif depth == 1 and line.startswith('edit '):
            current = {'id': shlex.split(line)[1], 'settings': {}, 'nested': []}
            blocks.append(current)
        elif depth == 1 and line == 'next':
            current = None
        elif current and depth == 1 and line.startswith('set '):
            tokens = shlex.split(line)
            current['settings'][tokens[1]] = ' '.join(tokens[2:])
        elif current and depth > 1:
            current['nested'].append(line)
    return blocks


def parse(category, text):
    rows, warnings = [], []
    if category in ('Interfaces_cfg', 'DHCP_cfg'):
        expected = 'config system interface' if category == 'Interfaces_cfg' else 'config system dhcp server'
        for block in config_blocks(text):
            rows.append({'id': block['id'], **block['settings'], 'nested': block['nested']})
        return result(rows, expected in text and text.rstrip().endswith('end'))
    if category == 'Sistema':
        for key, value in re.findall(r'(?m)^([^:\n]+):\s*(.*)$', text):
            if key.strip() in ('Version', 'Serial-Number', 'Hostname', 'Virtual domain configuration', 'Current virtual domain', 'Current HA mode', 'System time'):
                rows.append({'id': key.strip(), 'value': value.strip()})
        return result(rows, any(r['id'] == 'Version' for r in rows))
    if category == 'ARP':
        for line in text.splitlines():
            m = re.match(rf'\s*({IP})\s+(\S+)\s+({MAC})\s+(\S+)', line)
            if m:
                rows.append({'ip': m[1], 'mac': m[3].lower(), 'interface': m[4], 'age': m[2]})
            elif re.match(rf'^\s*{IP}\s', line):
                warnings.append('Entrada ARP não interpretada')
        return result(rows, bool(rows) or ('Address' in text and 'Age' in text), warnings)
    if category == 'DHCP':
        interface = ''
        for line in text.splitlines():
            label = re.match(r'^\s*(?:Interface\s*:?\s*)?(\S+)\s*$', line)
            if label and label[1].lower() not in ('ip', 'dhcp'):
                interface = label[1].rstrip(':')
            m = re.match(rf'^\s*({IP})\s+({MAC})\s*(.*)$', line)
            if m:
                rest = m[3].strip()
                rows.append({'ip': m[1], 'mac': m[2].lower(), 'interface': interface,
                             'details': rest})
            elif re.match(rf'^\s*{IP}\s', line):
                warnings.append('Lease DHCP não interpretado')
        return result(rows, bool(rows) or ('MAC' in text and ('Expiry' in text or 'Hostname' in text)) or bool(re.search(r'(?i)(no .*lease|total.*\b0\b)', text)), warnings)
    if category == 'BGP':
        vrf = '0'
        for line in text.splitlines():
            m = re.search(r'VRF\s+(\d+)', line)
            if m:
                vrf = m[1]
            parts = line.split()
            if not parts:
                continue
            try:
                ipaddress.ip_address(parts[0])
            except ValueError:
                continue
            if len(parts) < 10:
                warnings.append('Vizinho BGP incompleto')
                continue
            state = ' '.join(parts[9:])
            rows.append({'id': vrf + '/' + parts[0], 'vrf': vrf, 'neighbor': parts[0], 'as': parts[2],
                         'state': 'Established' if state.isdigit() else state,
                         'prefixes': int(state) if state.isdigit() else None, 'uptime': parts[8]})
        recognized = bool(rows) or 'State/PfxRcd' in text or bool(re.search(r'(?i)(no bgp|bgp.*not running|total.*neighbors.*\b0\b)', text))
        return result(rows, recognized, warnings)
    if category == 'VPN':
        for line in text.splitlines():
            m = re.search(r"^\s*'([^']+)'\s+(\S+)\s+selectors\(total,up\):\s*(\d+)/(\d+)\s+rx\(pkt,err\):\s*(\d+)/(\d+)\s+tx\(pkt,err\):\s*(\d+)/(\d+)", line)
            if m:
                rows.append({'id': m[1] + '/' + m[2], 'name': m[1], 'peer': m[2],
                             'total': int(m[3]), 'up': int(m[4]), 'rx_errors': int(m[6]), 'tx_errors': int(m[8])})
            elif 'selectors(' in line or line.lstrip().startswith("'"):
                warnings.append('Túnel VPN não interpretado')
        # A truly blank successful summary is the normal no-tunnels response.
        return result(rows, bool(rows) or not text.strip() or 'No tunnels' in text, warnings)
    if category == 'Rotas':
        vrf, prefix, protocol = '0', '', ''
        for line in text.splitlines():
            v = re.search(r'Routing table for VRF=(\d+)', line)
            if v:
                vrf = v[1]
            m = re.match(rf'^([A-Z][A-Za-z* >]*)\s+({IP}/\d+)\s+(.*)', line)
            if m:
                protocol, prefix, tail = m.groups()
            elif prefix and line.startswith(' ') and ('via ' in line or 'directly connected' in line):
                tail = line.strip()
            else:
                continue
            hop = re.search(r'via\s+([^,\s]+)', tail)
            direct = re.search(r'is directly connected,\s*(\S+)', tail)
            iface = re.search(r'via\s+[^,]+,\s*([^,\s]+)', tail)
            if not hop and not direct:
                warnings.append('Rota sem próximo salto/interface reconhecível')
                continue
            rows.append({'id': vrf + '/' + prefix, 'vrf': vrf, 'prefix': prefix,
                         'protocol': protocol.strip(), 'next_hop': hop[1] if hop else '',
                         'interface': (direct or iface)[1] if direct or iface else ''})
        return result(rows, bool(rows) or 'Routing table for VRF=' in text, warnings)
    if category == 'Interfaces':
        for block in re.split(r'(?=^if=)', text, flags=re.M):
            m = re.search(r'^if=(\S+)', block)
            flags = re.search(r'flags=(.*)', block)
            if m and flags:
                tokens = flags[1].lower().split()
                rows.append({'id': m[1], 'admin': 'up' if 'up' in tokens else 'down',
                             'link': 'up' if 'run' in tokens or 'running' in tokens else 'down'})
        return result(rows, bool(rows))
    if category == 'HA':
        for label in ('HA Health Status', 'Mode', 'Group Name', 'Group ID'):
            m = re.search(r'(?im)^' + re.escape(label) + r':\s*(.*)', text)
            if m:
                rows.append({'id': label, 'value': m[1].strip()})
        for role, name, serial in re.findall(r'(?im)^\s*(Primary|Secondary|Master|Slave)\s*:\s*([^,\n]+),\s*([^,\s]+)', text):
            rows.append({'id': 'member/' + serial, 'value': role.lower(), 'name': name.strip()})
        for serial, state in re.findall(r'(?im)^\s*(\S+)\s*(?:\([^\n]*\))?:\s*(in-sync|out-of-sync)\s*$', text):
            rows.append({'id': 'sync/' + serial, 'value': state.lower()})
        return result(rows, bool(rows) and 'HA Health Status' in text)
    if category == 'SDWAN':
        check = ''
        for line in text.splitlines():
            m = re.search(r'Health Check\((.+?)\)', line)
            if m:
                check = m[1]
            m = re.search(r'Seq\((\d+)\s+([^)]*)\).*state\(([^)]+)\)', line)
            if m:
                rows.append({'id': check + '/' + m[1], 'check': check, 'interface': m[2], 'state': m[3]})
        return result(rows, bool(rows) or not text.strip())
    if category == 'Recursos':
        for label in ('CPU states', 'Memory', 'Average sessions', 'Uptime'):
            m = re.search(r'(?im)^' + re.escape(label) + r':\s*(.*)', text)
            if m:
                rows.append({'id': label, 'value': m[1]})
        return result(rows, bool(rows))
    return result([], False)
