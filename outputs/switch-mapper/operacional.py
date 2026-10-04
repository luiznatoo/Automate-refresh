"""Parsers independentes de TextFSM para saídas operacionais comuns."""
import re
import xml.etree.ElementTree as ET


def junos_xml(raw):
    start = raw.find('<rpc-reply')
    if start < 0:
        start = raw.find('<interface-information')
    if start < 0:
        return []
    text = raw[start:]
    closing = '</rpc-reply>' if '<rpc-reply' in text else '</interface-information>'
    text = text[:text.index(closing) + len(closing)]
    root = ET.fromstring(text)
    for node in root.iter():
        node.tag = node.tag.split('}')[-1]
    rows = []
    for node in root.iter('physical-interface'):
        def value(path):
            return (node.findtext(path) or '').strip()
        row = {'interface': value('name'), 'admin_status': value('admin-status'),
               'link_status': value('oper-status'), 'speed': value('speed'),
               'duplex': value('link-mode'), 'media_type': value('media-type'),
               'input_errors': value('input-error-list/input-errors'),
               'output_errors': value('output-error-list/output-errors')}
        if row['interface']:
            rows.append(row)
    return rows


def parse(platform, sheet, raw):
    rows = []
    junos = platform == 'juniper_junos'
    if junos and sheet == 'LLDP_XML':
        start = raw.find('<rpc-reply')
        if start < 0:
            start = raw.find('<lldp-neighbors-information')
        if start < 0:
            return []
        closing = '</rpc-reply>' if raw[start:].startswith('<rpc-reply') else '</lldp-neighbors-information>'
        root = ET.fromstring(raw[start:raw.index(closing, start) + len(closing)])
        for node in root.iter():
            node.tag = node.tag.split('}')[-1]
        for node in root.iter('lldp-neighbor-information'):
            def text(tag):
                return (node.findtext('.//' + tag) or '').strip()
            local = text('lldp-local-interface') or text('lldp-local-port-id')
            if local and not local.isdigit():
                rows.append({'local_interface': local, 'neighbor_name': text('lldp-remote-system-name'),
                             'neighbor_interface': text('lldp-remote-port-id'),
                             'port_description': text('lldp-remote-port-description'),
                             'chassis_id': text('lldp-remote-chassis-id')})
        return rows
    if sheet == 'Vizinhos_LLDP':
        current = None
        summary_columns = None
        for line in raw.splitlines():
            if junos and 'Local Interface' in line and 'Chassis' in line and 'System' in line:
                labels = ['Local Interface', 'Parent Interface', 'Chassis', 'Port', 'System']
                offsets = [line.find(label) for label in labels]
                if all(i >= 0 for i in offsets) and offsets == sorted(offsets):
                    summary_columns = offsets
                continue
            if junos and summary_columns and re.match(r'^\s*(?:ge-|xe-|et-|fe-|mge-|ae\d|em\d|me\d)', line):
                values = [line[a:b].strip() for a, b in zip(summary_columns, summary_columns[1:] + [len(line)])]
                if values[0] and values[2]:
                    rows.append({'local_interface': values[0], 'chassis_id': values[2],
                                 'port_description': values[3], 'neighbor_name': values[4]})
                continue
            m = re.match(r'\s*(?:Local Interface|Local Intf|Local Port id)\s*:\s*(\S+)', line, re.I)
            if m:
                if m[1].isdigit():
                    continue  # Junos Local Port ID is an SNMP index, not a new interface.
                current = {'local_interface': m[1].rstrip(',')}
                rows.append(current)
                continue
            if current is None:
                continue
            for label, key in [('System name', 'neighbor_name'), ('Port id', 'neighbor_interface'),
                               ('Port Description', 'port_description'), ('Chassis id', 'chassis_id')]:
                m = re.match(r'\s*' + label + r'\s*:\s*(.*?)\s*$', line, re.I)
                if m:
                    current[key] = m[1]
        return [r for r in rows if any(r.get(k) for k in ('neighbor_name', 'neighbor_interface', 'chassis_id'))]
    if junos and sheet == 'VLANs_operacionais':
        current = None
        for line in raw.splitlines():
            # ELS: instance name tag; legacy: name tag. Continuation ports are not new VLANs.
            m = re.match(r'^\s*(?:(\S+)\s+)?(\S+)\s+(\d+)\s*(.*)$', line)
            if m and 1 <= int(m[3]) <= 4094:
                current = {'instance': m[1] or '', 'nome': m[2], 'vlan_id': m[3], 'interfaces': m[4].strip()}
                rows.append(current)
            elif current and re.match(r'^\s+(?:ge-|xe-|et-|fe-|ae\d)', line):
                current['interfaces'] = ', '.join(filter(None, [current['interfaces'], line.strip()]))
        return rows
    if junos and sheet == 'Detalhes_XML':
        return junos_xml(raw)
    if junos and sheet == 'Estado_portas':
        for m in re.finditer(r'(?m)^\s*(\S+)\s+(up|down)\s+(up|down)(?:\s|$)', raw):
            rows.append(dict(zip(('interface', 'admin_status', 'link_status'), m.groups())))
    elif junos and sheet == 'Detalhes_portas':
        for block in re.split(r'(?=Physical interface:)', raw):
            m = re.search(r'Physical interface:\s*(\S+),\s*(Enabled|Disabled),\s*Physical link is (\w+)', block)
            if not m:
                continue
            name, admin, link = m.groups()
            row = {'interface': name, 'admin_status': 'up' if admin == 'Enabled' else 'down', 'link_status': link.lower()}
            for key, pattern in {
                'speed': r'\bSpeed:\s*([^,\n]+)', 'duplex': r'\bLink-mode:\s*([^,\n]+)',
                'media_type': r'\bMedia type:\s*([^,\n]+)',
                'input_errors': r'Input errors:\s*\n\s*Errors:\s*(\d+)',
                'output_errors': r'Output errors:\s*\n\s*Errors:\s*(\d+)',
            }.items():
                found = re.search(pattern, block, re.I)
                if found:
                    row[key] = found[1].strip()
            rows.append(row)
    elif junos and sheet == 'STP':
        instance = ''
        for line in raw.splitlines():
            m = re.search(r'(?:VLAN|instance)\s+(\S+)', line, re.I)
            if m:
                instance = m[1]
            parts = line.split()
            if len(parts) >= 7 and re.match(r'^(?:ge-|xe-|et-|fe-|ae\d)', parts[0]):
                rows.append({'interface': parts[0], 'vlan_id': instance, 'status': parts[-2], 'role': parts[-1]})
    elif junos and sheet in ('LAG_operacional', 'LACP_detalhes'):
        group = ''
        members = {}
        for line in raw.splitlines():
            m = re.search(r'Aggregated interface:\s*(\S+)', line)
            if m:
                group = m[1]
            m = re.match(r'\s*((?:ge-|xe-|et-|fe-)\S+)\s+Actor\s+(.+)', line)
            if m:
                name, data = m.groups()
                row = members.setdefault((group, name), {'interface': name, 'agregacao': group})
                tokens = data.split()
                if tokens and tokens[-1].lower() in ('active', 'passive'):
                    row['role'] = tokens[-1]
                # Extensive LACP info: Actor system-priority system-id port-priority port-number key.
                mac = re.search(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', data, re.I)
                if mac:
                    row['system_id'] = mac[0]
                    rest = data[mac.end():].split()
                    if rest:
                        row['priority'] = rest[0]
            m = re.match(r'\s*((?:ge-|xe-|et-|fe-)\S+)\s+(.+?)\s+(Collecting distributing|Detached|Waiting|Attached|Collecting|Distributing)\s*$', line, re.I)
            if m:
                name, _, state = m.groups()
                row = members.setdefault((group, name), {'interface': name, 'agregacao': group})
                row['state'] = state
        rows = list(members.values())
    elif junos and sheet == 'PoE':
        for line in raw.splitlines():
            # Junos table: Interface Admin Oper Max power Priority Power consumption Class.
            m = re.match(r'\s*((?:ge-|mge-|fe-)\S+)\s+(Enabled|Disabled)\s+(\S+)', line, re.I)
            if m:
                rows.append({'interface': m[1], 'status': m[3], 'admin': m[2]})
    elif not junos and sheet == 'Detalhes_portas':
        for block in re.split(r'(?m)(?=^\S+ is )', raw):
            m = re.match(r'(\S+) is (administratively down|up|down)[^\n]*', block)
            if not m:
                continue
            row = {'interface': m[1], 'link_status': 'down' if 'down' in m[2] else 'up'}
            # NX-OS reports administrative state on a separate line; do not infer it from link down.
            admin = re.search(r'admin state is (up|down)', block, re.I)
            if admin:
                row['admin_status'] = admin[1].lower()
            elif platform == 'cisco_ios' or m[2] == 'administratively down':
                row['admin_status'] = 'down' if m[2] == 'administratively down' else 'up'
            for key, pattern in {'duplex': r'\b(Full-duplex|Half-duplex|full-duplex|half-duplex)',
                                 'speed': r'\b((?:\d+)(?:Gb/s|Mb/s|Mbps|Gbps))',
                                 'input_errors': r'(\d+) input errors', 'output_errors': r'(\d+) output errors',
                                 'media_type': r'media type is ([^,\n]+)'}.items():
                found = re.search(pattern, block)
                if found:
                    row[key] = found[1]
            rows.append(row)
    elif not junos and sheet == 'STP':
        instance = ''
        for line in raw.splitlines():
            m = re.match(r'\s*(VLAN\d+|MST\d+)', line)
            if m:
                instance = m[1]
            m = re.match(r'\s*(\S+)\s+(Root|Desg|Altn|Back|Mstr)\s+(FWD|BLK|LRN|LIS|DIS|BKN)\b', line)
            if m:
                rows.append({'interface': m[1], 'role': m[2], 'status': m[3], 'vlan_id': instance})
    elif not junos and sheet == 'LAG_operacional':
        group = ''
        states = {'P': 'Bundled', 'I': 'Stand-alone', 'H': 'Hot-standby', 's': 'Suspended',
                  'D': 'Down', 'w': 'Waiting', 'b': 'Hot-standby'}
        for line in raw.splitlines():
            m = re.search(r'\b(Po\d+)\([A-Za-z]+\)', line)
            if m:
                group = m[1]
            if group:
                for member, state in re.findall(r'((?:Gi|Te|Fa|Eth|Hu|Twe)\S+?)\(([PIHsDwb])\)', line):
                    rows.append({'interface': member, 'agregacao': group, 'state': states[state]})
    return rows
