"""Build per-user connection pages; never expose state.json or other users' keys."""
import base64
from html import escape
import json
import re
from pathlib import Path
import shutil
import struct
import zlib

HERE = Path(__file__).resolve().parent

def amnezia_key(state, name, profile):
    user = state['users'][name]
    obfs = {key: str(value) for key, value in state['obfs'].items()}
    client = dict(config=profile, hostName=state['endpoint'], port=state['port'],
        client_ip=user['address'], client_priv_key=user['private'],
        client_pub_key=user['public'], server_pub_key=state['awg_public'],
        psk_key=user['psk'], clientId=user['public'],
        allowed_ips=['0.0.0.0/0', '::/0'], persistent_keep_alive='25', mtu='1280', **obfs)
    awg = dict(port=str(state['port']), transport_proto='udp',
        subnet_address='10.77.0.0', subnet_cidr='24', isThirdPartyConfig=True,
        last_config=json.dumps(client, separators=(',', ':')), **obfs)
    # Amnezia format_version=1, read-only profile: no SSH credentials/server private key.
    config = dict(format_version=1, description='VPN — '+name, hostName=state['endpoint'],
        defaultContainer='amnezia-awg2', dns1='10.77.0.1', dns2='10.77.0.1',
        containers=[dict(container='amnezia-awg2', awg=awg)])
    raw = json.dumps(config, ensure_ascii=False, separators=(',', ':')).encode()
    # Qt qCompress stores the original length as big-endian uint32, then zlib.
    packed = struct.pack('>I', len(raw)) + zlib.compress(raw, 8)
    return 'vpn://' + base64.urlsafe_b64encode(packed).decode().rstrip('=')

def render_portal(state, generation):
    webroot = generation/'webroot'
    webroot.mkdir()
    template = (HERE/'portal.html').read_text(encoding='utf-8')
    for name, user in state['users'].items():
        if not user['enabled']:
            continue
        token = user['portal_token']
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise ValueError('Invalid portal token')
        dest = webroot/'p'/token
        dest.mkdir(parents=True)
        output = generation/'output'
        profile = (output/f'{name}.conf').read_text()
        key = amnezia_key(state, name, profile)
        links = {net: (output/f'{name}-{net}.txt').read_text().strip() for net in ('xhttp', 'tcp')}
        subscription_url = f"https://{state['endpoint']}:2087/p/{token}/subscription.txt"
        replacements = dict(NAME=name, SERVER=state['endpoint'], AMNEZIA=key,
            XHTTP=links['xhttp'], TCP=links['tcp'], SUBSCRIPTION=subscription_url)
        page = template
        for key_name, value in replacements.items():
            page = page.replace('{{'+key_name+'}}', escape(value, quote=True))
        (dest/'index.html').write_text(page, encoding='utf-8')
        (dest/'amnezia.vpn').write_text(key+'\n')
        (dest/'subscription.txt').write_text(base64.b64encode(
            (links['xhttp']+'\n'+links['tcp']+'\n').encode()).decode()+'\n')
        shutil.copyfile(output/f'{name}.conf', dest/'amneziawg.conf')
        for net in ('xhttp', 'tcp', 'awg'):
            source = output/f'{name}-{net}.png'
            # The file is created by qrencode in production; test mocks may omit it.
            if source.exists():
                shutil.copyfile(source, dest/f'{net}.png')
        shutil.copyfile(HERE/'portal.js', dest/'portal.js')
    return webroot
