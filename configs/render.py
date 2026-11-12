#!/usr/bin/env python3
"""Generate a candidate generation; only common.sh can activate it."""
import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid
from urllib.parse import urlencode, quote
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'data'
sys.path.insert(0, str(ROOT / 'configs'))
from portal import render_portal
USERS = ['denis', 'vlad', 'liza', 'parents', 'router', 'svyat', 'sveta', 'ruslan']
PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '192.0.0.0/24',
           '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4', '::/0']

def keypair(url=False):
    key = X25519PrivateKey.generate()
    enc = base64.urlsafe_b64encode if url else base64.b64encode
    def fmt(raw):
        value = enc(raw).decode()
        return value.rstrip('=') if url else value
    return (fmt(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            fmt(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))

def user_record(index):
    private, public = keypair()
    return dict(uuid=str(uuid.uuid4()), short_id=secrets.token_hex(8),
                private=private, public=public, psk=base64.b64encode(secrets.token_bytes(32)).decode(),
                address=f'10.77.0.{index + 2}', enabled=True, portal_token=secrets.token_urlsafe(32))

def endpoint(value):
    if not value or len(value) > 253:
        raise ValueError('Set ENDPOINT to your public IPv4 or DNS name')
    try:
        addr = ipaddress.ip_address(value)
        if addr.version != 4 or not addr.is_global:
            raise ValueError('Endpoint must be a public IPv4 address')
    except ValueError:
        import re
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}', value):
            raise ValueError('Endpoint must be a public IPv4 or DNS name')
    return value

def probe_sni(name):
    # TLS validation cannot prove political safety or permanent CDN ownership.
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['h2'])
    with socket.create_connection((name, 443), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=name) as conn:
            if conn.selected_alpn_protocol() != 'h2':
                raise ValueError('TLS target does not support h2')
    # Reject known Cloudflare CNAMEs and Cloudflare response markers.
    cname = subprocess.check_output(['dig', '+short', 'CNAME', name], text=True, timeout=8)
    if 'cloudflare' in cname.lower():
        raise ValueError('Cloudflare CNAME')
    headers = subprocess.check_output(['curl', '-sSI', '--max-time', '10', 'https://' + name], text=True)
    if 'cloudflare' in headers.lower() or 'cf-ray:' in headers.lower():
        raise ValueError('Cloudflare response')

def initial(names):
    shuffled = names[:]
    secrets.SystemRandom().shuffle(shuffled)
    selected = None
    for name in shuffled:
        try:
            probe_sni(name)
            selected = name
            break
        except Exception as exc:
            print(f'SNI {name}: rejected ({exc})', file=sys.stderr)
    if selected is None:
        raise ValueError('No usable SNI target. Retry from VPS after checking connectivity.')
    private, public = keypair(True)
    awg_private, awg_public = keypair()
    # Distinct fixed headers are valid AWG 2+ range values with a single element.
    headers = secrets.SystemRandom().sample(range(100000, 2000000000), 4)
    obfs = dict(Jc=secrets.randbelow(5)+4, Jmin=64+secrets.randbelow(64),
                Jmax=800+secrets.randbelow(300), S1=32+secrets.randbelow(64),
                S2=32+secrets.randbelow(64), S3=12+secrets.randbelow(20), S4=12+secrets.randbelow(20))
    obfs.update({f'H{i+1}': v for i, v in enumerate(headers)})
    port = None
    for _ in range(100):
        candidate = 20000 + secrets.randbelow(40000)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('0.0.0.0', candidate))
            port = candidate
            break
        except OSError:
            continue
    if port is None:
        raise ValueError('Cannot select an unused UDP port')
    return dict(schema=1, endpoint=endpoint(os.environ.get('ENDPOINT', '')), sni=selected,
                reality_private=private, reality_public=public, awg_private=awg_private,
                awg_public=awg_public, port=port, path='/' + secrets.token_hex(12),
                obfs=obfs, users={name: user_record(i) for i, name in enumerate(USERS)})

def render(state, dest):
    dest.mkdir(mode=0o700, parents=True)
    output = dest / 'output'
    output.mkdir(mode=0o700)
    (dest / 'state.json').write_text(json.dumps(state, indent=2) + '\n')
    ads = [line.strip() for line in (ROOT/'configs/blocked-domains.txt').read_text().splitlines()
           if line.strip() and not line.startswith('#')]
    shutil.copyfile(ROOT/'configs/blocked-domains.txt', dest/'blocked-domains.txt')
    shutil.copyfile(ROOT/'configs/dnscrypt-proxy.toml', dest/'dnscrypt-proxy.toml')
    config = json.loads((ROOT/'configs/xray.json').read_text())
    enabled = {n: u for n, u in state['users'].items() if u['enabled']}
    for port, network in [(443, 'xhttp'), (8443, 'tcp')]:
        reality = dict(show=False, dest=state['sni']+':443', xver=0,
                       serverNames=[state['sni']], privateKey=state['reality_private'],
                       shortIds=[u['short_id'] for u in enabled.values()])
        # Preserve valid REALITY syntax when all VLESS client lists are empty.
        if not reality['shortIds']:
            reality['shortIds'] = [state['users'][USERS[0]]['short_id']]
        clients = [dict(id=u['uuid'], email=name,
                        **({'flow': 'xtls-rprx-vision'} if port == 8443 else {}))
                   for name, u in enabled.items()]
        stream = dict(network=network, security='reality', realitySettings=reality)
        if network == 'xhttp':
            stream['xhttpSettings'] = dict(path=state['path'], mode='stream-one')
        config['inbounds'].append(dict(tag=network, listen='0.0.0.0', port=port,
            protocol='vless', settings=dict(clients=clients, decryption='none'),
            streamSettings=stream, sniffing=dict(enabled=True, destOverride=['http','tls','quic'], routeOnly=True)))
    config['routing']['rules'] = [
        dict(type='field', domain=['domain:'+d for d in ads], outboundTag='blocked'),
        dict(type='field', port='53', outboundTag='dns-out'),
        dict(type='field', ip=PRIVATE, outboundTag='blocked'),
        dict(type='field', port='853', outboundTag='blocked')]
    (dest/'xray.json').write_text(json.dumps(config, indent=2)+'\n')
    obfs = '\n'.join(f'{k} = {v}' for k,v in state['obfs'].items())
    server = f"[Interface]\nPrivateKey = {state['awg_private']}\nListenPort = 51820\n{obfs}\n"
    for name, u in enabled.items():
        server += f"\n# {name}\n[Peer]\nPublicKey = {u['public']}\nPresharedKey = {u['psk']}\nAllowedIPs = {u['address']}/32\n"
        profile = (f"[Interface]\nPrivateKey = {u['private']}\nAddress = {u['address']}/32\n"
            f"DNS = 10.77.0.1\nMTU = 1280\n{obfs}\n\n[Peer]\nPublicKey = {state['awg_public']}\n"
            f"PresharedKey = {u['psk']}\nEndpoint = {state['endpoint']}:{state['port']}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n")
        # IPv6 is captured on the client and deliberately has no server egress.
        (output/f'{name}.conf').write_text(profile)
        subprocess.run(['qrencode', '-l', 'L', '-o', str(output/f'{name}-awg.png')], input=profile, text=True, check=True)
        for port, network in [(443,'xhttp'),(8443,'tcp')]:
            query = dict(encryption='none', security='reality', sni=state['sni'],
                fp='firefox', pbk=state['reality_public'], sid=u['short_id'], type=network)
            if network == 'xhttp':
                query.update(path=state['path'], mode='stream-one')
            else:
                query['flow']='xtls-rprx-vision'
            link=f"vless://{u['uuid']}@{state['endpoint']}:{port}?{urlencode(query)}#{quote(name+'-'+network)}"
            (output/f'{name}-{network}.txt').write_text(link+'\n')
            subprocess.run(['qrencode','-l','L','-o',str(output/f'{name}-{network}.png')], input=link, text=True, check=True)
        # Explicitly a repository-local export URI, NOT a standard client import format.
        (output/f'{name}.awg-uri.txt').write_text('awg://'+base64.urlsafe_b64encode(profile.encode()).decode().rstrip('=')+'\n')
    (dest/'awg.conf').write_text(server)
    webroot = render_portal(state, dest)
    for path in dest.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
    # Only this subtree is mounted into the unprivileged portal container.
    webroot.chmod(0o755)
    for path in webroot.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)

def print_links(state, name=None, direct=False):
    selected = state['users'] if name is None else {name: state['users'].get(name)}
    if name is not None and (selected[name] is None or not selected[name]['enabled']):
        raise ValueError('Unknown or disabled user')
    portal_enabled = (DATA/'portal/enabled').is_file()
    if portal_enabled and not direct:
        print('\nЛичные страницы подключения (ссылки содержат ключи доступа):\n')
        for username, user in selected.items():
            if user['enabled']:
                print(f"{username}: https://{state['endpoint']}:2087/p/{user['portal_token']}/")
    else:
        for net, title in [('xhttp', 'Основной VLESS / XHTTP'), ('tcp', 'Резервный VLESS / TCP Vision')]:
            print('\n'+title+':\n')
            for username, user in selected.items():
                if user['enabled']:
                    link=(DATA/f'current/output/{username}-{net}.txt').read_text().strip()
                    print(f'{username}: {link}')

def main():
    action = sys.argv[1]
    if action == 'candidate':
        names = sys.argv[2].split(',')
        if names != USERS:
            raise ValueError('User inventory mismatch')
        current = DATA/'current/state.json'
        state = json.loads(current.read_text()) if current.exists() else initial(sys.argv[3].split(','))
        if state['schema'] != 1 or list(state['users']) != USERS:
            raise ValueError('Unsupported state or inventory; restore a valid backup')
        state = copy.deepcopy(state)
        # Upgrade existing installations without changing VPN credentials.
        for user in state['users'].values():
            if 'portal_token' not in user:
                user['portal_token'] = secrets.token_urlsafe(32)
        if os.environ.get('ENDPOINT'):
            state['endpoint'] = endpoint(os.environ['ENDPOINT'])
        operation = sys.argv[4] if len(sys.argv)>4 else 'refresh'
        if operation in ('rotate','enable','disable'):
            name = sys.argv[5]
            if name not in USERS:
                raise ValueError('Unknown user')
            if operation == 'rotate':
                state['users'][name] = user_record(USERS.index(name))
            else:
                state['users'][name]['enabled'] = operation == 'enable'
        elif operation != 'refresh':
            raise ValueError('Unknown operation')
        dest = DATA/'generations'/f'{time.time_ns()}-{secrets.token_hex(3)}'
        render(state, dest)
        print(dest.relative_to(DATA).as_posix())
    elif action == 'port':
        print(json.loads((DATA/'current/state.json').read_text())['port'])
    elif action == 'endpoint':
        print(endpoint(json.loads((DATA/'current/state.json').read_text())['endpoint']))
    elif action in ('links', 'raw'):
        if len(sys.argv) > 3:
            raise ValueError('Usage: render.py links|raw [NAME]')
        state=json.loads((DATA/'current/state.json').read_text())
        print_links(state, sys.argv[2] if len(sys.argv)>2 else None, direct=action=='raw')
    elif action == 'show':
        state=json.loads((DATA/'current/state.json').read_text())
        print(f"{'USER':12} {'STATUS':10} {'AWG IP':15} OUTPUT")
        for name,u in state['users'].items():
            print(f"{name:12} {('enabled' if u['enabled'] else 'disabled'):10} {u['address']:15} data/output/{name}*")
        if len(sys.argv)>2:
            name=sys.argv[2]
            if name not in USERS or not state['users'][name]['enabled']:
                raise ValueError('Unknown or disabled user')
            for network in ('xhttp','tcp'):
                print((DATA/f'output/{name}-{network}.txt').read_text().strip())
    else:
        raise ValueError('Unknown action')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
