"""Coleta SSH pré/pós-RDM e comparação FortiGate 7.4.x, HA, sem VDOMs."""
import argparse
import csv
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from parsers import parse
from comparar import compare, export_excel

BASE = Path(__file__).resolve().parent
COMMANDS = {
    'Sistema': 'get system status', 'HA': 'get system ha status',
    'BGP': 'get router info bgp summary', 'VPN': 'get vpn ipsec tunnel summary',
    'Rotas': 'get router info routing-table all', 'Interfaces': 'diagnose netlink interface list',
    'Interfaces_cfg': 'show system interface', 'ARP': 'get system arp',
    'DHCP': 'execute dhcp lease-list', 'DHCP_cfg': 'show system dhcp server',
    'SDWAN': 'diagnose sys sdwan health-check', 'Recursos': 'get system performance status',
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


# Shared core is resolved for both source and portable distributions.
import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent/'refresh_core').is_dir():
        if str(_parent) not in _sys.path:_sys.path.insert(0,str(_parent))
        break
else:raise ImportError('refresh_core ausente: use o pacote completo da Central')
from refresh_core.ssh import SSH as SharedSSH, clean, redact
class SSH(SharedSSH):
    command_set=COMMANDS


def inventory(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        if not {'nome', 'host'} <= set(reader.fieldnames or []):
            raise ValueError('CSV precisa de nome,host; separador vírgula')
        rows, names, endpoints = [], set(), set()
        for line, raw in enumerate(reader, 2):
            if None in raw:
                raise ValueError(f'Linha {line}: colunas extras')
            row = {k: (v or '').strip() for k, v in raw.items()}
            if not any(row.values()):
                continue
            name, host = row['nome'], row['host']
            port = row.get('porta') or '22'
            if not name or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError(f'Linha {line}: nome, host ou porta inválidos')
            if name.casefold() in names or (host.casefold(), int(port)) in endpoints:
                raise ValueError(f'Linha {line}: nome/endereço duplicado')
            names.add(name.casefold())
            endpoints.add((host.casefold(), int(port)))
            row['porta'] = int(port)
            if row.get('key_file'):
                key = Path(row['key_file']).expanduser()
                if not key.is_absolute():
                    key = Path(path).resolve().parent / key
                if not key.is_file():
                    raise ValueError(f'Linha {line}: chave privada não encontrada')
                row['key_file'] = str(key)
            rows.append(row)
    if not rows:
        raise ValueError('Inventário vazio')
    return rows


def collect(device, password, args, run):
    data = {}
    result = {'host': device['host'], 'port': device['porta'], 'data': data}
    slug = hashlib.sha256(device['nome'].encode()).hexdigest()[:12]
    log_dir = run / 'logs' / slug
    log_dir.mkdir(parents=True)
    conn = None
    try:
        conn = SSH(device, password, args.timeout, args.known_hosts)
        for category, command in COMMANDS.items():
            at = now()
            raw = conn.command(command)
            safe = redact(raw, password)
            file = log_dir / (category + '.txt')
            file.write_text(f'Equipamento: {device["nome"]}\nUTC: {at}\nComando: {command}\n\n{safe}', encoding='utf-8')
            try:
                if re.search(r'(?im)^\s*(?:command parse error|unknown action|command fail|permission denied|access denied|return code\s+-)', raw):
                    raise ValueError('Comando recusado ou sem permissão; conferir log')
                sample = parse(category, safe)
                sample.update(at=at, command=command, log=str(file.relative_to(run)))
                data[category] = sample
            except Exception as exc:
                data[category] = {'status': 'error', 'rows': [], 'at': at, 'command': command,
                                  'error': redact(str(exc), password), 'log': str(file.relative_to(run))}
            if category == 'Sistema':
                info = {r['id']: r['value'] for r in data[category].get('rows', [])}
                vdom = info.get('Virtual domain configuration', '').lower()
                if not vdom.startswith('disable'):
                    raise ValueError('VDOM ativo ou escopo não confirmado. Coleta interrompida: esta versão requer VDOM desabilitado.')
    except Exception as exc:
        error = type(exc).__name__ + ': ' + redact(clean(str(exc)), password)
        for category in COMMANDS:
            if category not in data:
                data[category] = {'status': 'error', 'rows': [], 'error': error, 'at': now(), 'command': COMMANDS[category]}
    finally:
        if conn:
            conn.close()
    return result


def saved_snapshots(phase, rdm=None, after=None):
    entries = []
    for path in (BASE / 'coletas').glob('*/*/snapshot.json'):
        try:
            sample = json.loads(path.read_text(encoding='utf-8'))
            if sample.get('schema') != 1 or sample.get('phase') != phase:
                continue
            if rdm and sample.get('rdm') != rdm:
                continue
            if after and sample.get('started', '') <= after:
                continue
            devices = sample['devices']
            ok = sum(s.get('status') == 'ok' for d in devices.values() for s in d['data'].values())
            total = sum(len(d['data']) for d in devices.values())
            if not ok:
                continue  # Never offer a completely failed baseline.
            entries.append((path, sample, ok, total))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    return sorted(entries, key=lambda e: e[1]['started'], reverse=True)


def choose_snapshot(phase, rdm=None, after=None):
    entries = saved_snapshots(phase, rdm, after)
    if not entries:
        print('Nenhuma coleta utilizável encontrada. Coletas totalmente falhas não aparecem na lista.')
        return None
    print('\nColetas disponíveis (mais recentes primeiro):')
    for index, (_, sample, ok, total) in enumerate(entries, 1):
        print(f'{index}. {sample["rdm"]} | {sample["started"]} UTC | '
              f'{", ".join(sample["devices"])} | {ok}/{total} áreas interpretadas')
    print('0. Voltar')
    while True:
        answer = input('Escolha o número da coleta: ').strip()
        if answer == '0':
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(entries):
            entry = entries[int(answer) - 1]
            if entry[2] < entry[3]:
                print('Esta coleta é parcial. As áreas com falha ficarão inconclusivas no Excel.')
            return entry
        print('Número inválido.')


def menu():
    while True:
        print('\nFORTIGATE — RDM\n1. Coletar PRÉ-RDM\n2. Coletar PÓS-RDM e gerar Excel\n3. Comparar coletas já salvas\n0. Sair')
        choice = input('Escolha: ').strip()
        if choice == '0':
            return 0
        if choice == '1':
            rdm = input('Número/nome da RDM (ex.: RDM12345): ').strip()
            main(['coletar', '--fase', 'pre', '--rdm', rdm])
        elif choice in ('2', '3'):
            baseline = choose_snapshot('pre')
            if baseline is None:
                continue
            path, sample, _, _ = baseline
            if choice == '2':
                main(['coletar', '--fase', 'pos', '--rdm', sample['rdm'], '--comparar-pre', str(path)])
            else:
                post = choose_snapshot('pos', sample['rdm'], sample['started'])
                if post:
                    main(['comparar', '--pre', str(path), '--pos', str(post[0])])
        else:
            print('Opção inválida.')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        try:
            return menu()
        except (EOFError, KeyboardInterrupt):
            print('\nMenu encerrado.')
            return 0
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    collect_parser = sub.add_parser('coletar')
    collect_parser.add_argument('--fase', choices=['pre', 'pos'], required=True)
    collect_parser.add_argument('--rdm', required=True)
    collect_parser.add_argument('--inventario', type=Path, default=Path(os.getenv('REFRESH_INVENTORY',str(BASE / 'inventario.csv'))))
    collect_parser.add_argument('--usuario', default=os.getenv('FGT_USER', ''))
    collect_parser.add_argument('--known-hosts', type=Path)
    collect_parser.add_argument('--timeout', type=int, default=120)
    collect_parser.add_argument('--workers', type=int, default=3)
    collect_parser.add_argument('--nao-interativo', action='store_true')
    collect_parser.add_argument('--comparar-pre', type=Path, help='Comparar automaticamente o pós com esta coleta pré')
    compare_parser = sub.add_parser('comparar')
    compare_parser.add_argument('--pre', type=Path, required=True)
    compare_parser.add_argument('--pos', type=Path, required=True)
    compare_parser.add_argument('--saida', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'comparar':
            import openpyxl  # dependency validation before processing
            before = json.loads(args.pre.read_text(encoding='utf-8'))
            after = json.loads(args.pos.read_text(encoding='utf-8'))
            report = compare(before, after)
            output = args.saida or BASE / 'relatorios' / f'comparativo_{datetime.now():%Y%m%d_%H%M%S_%f}.xlsx'
            if output.suffix.lower() != '.xlsx':
                raise ValueError('A saída precisa terminar em .xlsx')
            export_excel(before, after, report, output, args.pre, args.pos)
            from refresh_core.storage import event
            event('Comparação RDM',output,detail=str(len(report['Alertas']))+' alertas')
            print(f'Excel: {output.resolve()}')
            return 2 if any(r['Comparável'] == 'Não' for r in report['Cobertura']) or any(r['Área'] == 'Coleta' for r in report['Alertas']) else 0
        import paramiko  # fail before password prompts
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', args.rdm):
            raise ValueError('RDM: use até 80 letras, números, hífen ou sublinhado')
        if not 1 <= args.workers <= 16 or not 5 <= args.timeout <= 1800:
            raise ValueError('workers: 1..16; timeout: 5..1800 segundos')
        devices = inventory(args.inventario)
        if args.comparar_pre:
            import openpyxl  # Verify Excel dependency before the post collection.
            pre = json.loads(args.comparar_pre.read_text(encoding='utf-8'))
            if args.fase != 'pos' or pre.get('phase') != 'pre' or pre.get('rdm') != args.rdm:
                raise ValueError('Comparação automática requer pós e pré da mesma RDM')
            expected = {name: (d['host'], d['port']) for name, d in pre['devices'].items()}
            current = {d['nome']: (d['host'], d['porta']) for d in devices}
            if current != expected:
                raise ValueError('O inventário mudou em relação ao pré selecionado. Ajuste nomes/IPs/portas ou selecione o pré correto. Nenhuma coleta foi iniciada.')
        secrets, jobs = {}, []
        for device in devices:
            user = device.get('usuario') or args.usuario
            if not user and not args.nao_interativo:
                args.usuario = user = input('Usuário SSH: ').strip()
            if not user:
                raise ValueError('Informe --usuario ou FGT_USER')
            device['usuario'] = user
            env = device.get('password_env') or 'FGT_PASSWORD'
            if device.get('key_file'):
                password = ''
            elif env in os.environ:
                password = os.environ[env]
            else:
                if env not in secrets:
                    if args.nao_interativo:
                        raise ValueError(f'Variável {env} ausente')
                    secrets[env] = getpass.getpass(f'Senha {env} (não será salva): ')
                password = secrets[env]
            jobs.append((device, password))
        run = BASE / 'coletas' / args.rdm / f'{args.fase}_{datetime.now():%Y%m%d_%H%M%S_%f}'
        run.mkdir(parents=True, exist_ok=False)
        snapshot = {'schema': 1, 'rdm': args.rdm, 'phase': args.fase, 'started': now(), 'devices': {}}
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(collect, d, p, args, run): d for d, p in jobs}
            for future in as_completed(futures):
                device = futures[future]
                try:
                    value = future.result()
                except Exception as exc:
                    value = {'host': device['host'], 'port': device['porta'], 'data': {
                        c: {'status': 'error', 'rows': [], 'error': type(exc).__name__ + ': falha interna', 'at': now()}
                        for c in COMMANDS}}
                snapshot['devices'][device['nome']] = value
                errors = [c for c, s in value['data'].items() if s['status'] != 'ok']
                print(f'{device["nome"]}: ' + ('áreas a revisar: ' + ', '.join(errors) if errors else 'coleta interpretada'))
                shown = set()
                for sample in value['data'].values():
                    error = sample.get('error', '')
                    if error and error not in shown:
                        print('  ' + error)
                        shown.add(error)
                if any('not found in known_hosts' in error for error in shown):
                    print('  Primeiro conecte com o cliente SSH e confira a impressão digital do FortiGate antes de aceitar a chave:')
                    print(f'  ssh -p {device["porta"]} {device["usuario"]}@{device["host"]}')
                    print('  Depois repita a coleta. Também é possível informar --known-hosts com o arquivo correto.')
        snapshot['finished'] = now()
        path = run / 'snapshot.json'
        path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
        from refresh_core.storage import event
        event('Coleta RDM '+args.fase,path,detail=args.rdm)
        print(f'Coleta salva: {path.resolve()}')
        if args.comparar_pre:
            print('Gerando o Excel comparativo automaticamente...')
            return main(['comparar', '--pre', str(args.comparar_pre), '--pos', str(path)])
        return 2 if any(s['status'] != 'ok' for d in snapshot['devices'].values() for s in d['data'].values()) else 0
    except ImportError as exc:
        print(f'Dependência ausente: {exc}. Instale requirements.txt no mesmo Python usado para executar.')
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f'Erro: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
