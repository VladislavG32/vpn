#!/usr/bin/env python3
"""Read-only VLESS smoke test from the VPS, with short-lived authenticated clients."""
import contextlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse, parse_qs
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT/'data'

class CheckError(Exception):
    pass

def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=20)
    if result.returncode:
        # Do not forward arbitrary daemon/Xray output that may contain credentials.
        raise CheckError('DOCKER_COMMAND_FAILED')
    return result.stdout.strip()

def read_exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size-len(data))
        if not part:
            raise CheckError('SOCKS_CONNECTION_CLOSED')
        data += part
    return data

def socks_connect(port, username, password, target='api.ipify.org', target_port=443):
    sock = socket.create_connection(('127.0.0.1', port), timeout=8)
    try:
        sock.sendall(b'\x05\x01\x02')  # RFC1929 username/password, no open proxy.
        if read_exact(sock, 2) != b'\x05\x02':
            raise CheckError('SOCKS_AUTH_METHOD_REJECTED')
        user, secret = username.encode(), password.encode()
        sock.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(secret)])+secret)
        if read_exact(sock, 2) != b'\x01\x00':
            raise CheckError('SOCKS_AUTH_FAILED')
        host = target.encode('idna')
        sock.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+target_port.to_bytes(2,'big'))
        header = read_exact(sock, 4)
        if header[:2] != b'\x05\x00':
            raise CheckError('SOCKS_CONNECT_FAILED')
        if header[3] == 1:
            read_exact(sock, 4)
        elif header[3] == 4:
            read_exact(sock, 16)
        elif header[3] == 3:
            read_exact(sock, read_exact(sock,1)[0])
        else:
            raise CheckError('SOCKS_INVALID_ADDRESS')
        read_exact(sock, 2)
        return sock
    except BaseException:
        sock.close()
        raise

def https_over_socks(port, user, password):
    with socks_connect(port, user, password) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname='api.ipify.org') as tls:
            tls.sendall(b'GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(256).decode('ascii',errors='replace').strip()
            # Any genuine HTTPS response proves the proxy path; a target-site
            # HTTP error is distinct from a tunnel/handshake failure.
            try:
                address = str(ipaddress.ip_address(body))
            except ValueError:
                address = None
            return response.status, address

def probe_client(port, user, password):
    # A cold REALITY target/DNS lookup can be slower than an established path.
    for attempt in range(2):
        try:
            return https_over_socks(port,user,password)
        except ssl.SSLCertVerificationError:
            raise
        except (OSError,CheckError):
            if attempt: raise
            time.sleep(.25)

def make_client(link, server_address, inbound, username, password):
    parsed = urlparse(link.strip())
    query = {key: values[0] for key,values in parse_qs(parsed.query).items()}
    if parsed.scheme != 'vless' or query.get('security') != 'reality':
        raise CheckError('INVALID_SAVED_PROFILE')
    network = query.get('type')
    expected = inbound['streamSettings']
    reality = expected['realitySettings']
    if network not in ('tcp','xhttp') or parsed.port != inbound['port']:
        raise CheckError('PROFILE_PORT_OR_TRANSPORT_MISMATCH')
    clients = inbound['settings']['clients']
    client = next((item for item in clients if item.get('id')==parsed.username), None)
    if client is None or query.get('sni') not in reality['serverNames'] or query.get('sid') not in reality['shortIds']:
        raise CheckError('SAVED_PROFILE_DIFFERS_FROM_RUNNING_SERVER')
    stream = dict(network=network, security='reality', realitySettings=dict(
        serverName=query['sni'], fingerprint=query.get('fp','firefox'),
        publicKey=query.get('pbk',''), shortId=query['sid']))
    account = dict(id=parsed.username, encryption='none')
    if network=='xhttp':
        xhttp = dict(path=query.get('path','/'),mode=query.get('mode','auto'))
        if any(xhttp[key] != expected.get('xhttpSettings',{}).get(key) for key in ('path','mode')):
            raise CheckError('XHTTP_PROFILE_MISMATCH')
        stream['xhttpSettings']=xhttp
    else:
        flow=query.get('flow','')
        if flow != client.get('flow',''):
            raise CheckError('VISION_PROFILE_MISMATCH')
        account['flow']=flow
    return dict(log=dict(loglevel='error',access='none'),
        inbounds=[dict(listen='0.0.0.0',port=1080,protocol='socks',settings=dict(
            auth='password',accounts=[dict(user=username,**{'pass':password})],udp=False))],
        outbounds=[dict(protocol='vless',settings=dict(vnext=[dict(address=server_address,
            port=inbound['port'],users=[account])]),streamSettings=stream)])

@contextlib.contextmanager
def temporary_client(image, network, config):
    parent=DATA/'diagnostics'
    parent.mkdir(mode=0o700,exist_ok=True)
    name='private-vpn-check-'+secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix='client-',dir=parent) as tmp:
        path=Path(tmp)/'client.json'
        path.write_text(json.dumps(config),encoding='utf-8'); path.chmod(0o600)
        try:
            docker('run','--detach','--rm','--name',name,'--network',network,
                '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
                '--pids-limit','64','--memory','256m','--publish','127.0.0.1::1080',
                '--mount',f'type=bind,source={path.resolve()},target=/client.json,readonly',
                '--entrypoint','xray',image,'run','-c','/client.json')
            info=json.loads(docker('inspect',name))[0]
            port=int(info['NetworkSettings']['Ports']['1080/tcp'][0]['HostPort'])
            for _ in range(30):
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.3):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise CheckError('TEMPORARY_CLIENT_NOT_READY')
            yield port
        finally:
            subprocess.run(['docker','rm','--force',name],capture_output=True,timeout=15)

def failure_code(exc):
    if isinstance(exc,CheckError): return str(exc)
    if isinstance(exc,ssl.SSLCertVerificationError): return 'HTTPS_CERTIFICATE_FAILED'
    if isinstance(exc,(TimeoutError,socket.timeout,subprocess.TimeoutExpired)): return 'TIMEOUT'
    if isinstance(exc,(ConnectionError,OSError)): return 'CONNECTION_ERROR'
    return 'CHECK_FAILED'

def main():
    if not hasattr(os,'geteuid') or os.geteuid()!=0:
        raise CheckError('ROOT_REQUIRED')
    state=json.loads((DATA/'current/state.json').read_text())
    username=sys.argv[2] if len(sys.argv)>2 else next((name for name,user in state['users'].items() if user['enabled']),None)
    if username is None: raise CheckError('NO_ENABLED_USERS')
    if username not in state['users'] or not state['users'][username]['enabled']:
        raise CheckError('UNKNOWN_OR_DISABLED_USER')
    info=json.loads(docker('inspect',sys.argv[1]))[0]
    networks=info['NetworkSettings']['Networks']
    network=next((name for name in networks if name.endswith('_egress')),None)
    if network is None: raise CheckError('XRAY_EGRESS_NETWORK_NOT_FOUND')
    server_address=networks[network]['IPAddress']
    running=json.loads(docker('exec',info['Id'],'cat','/etc/xray/config.json'))
    print('Проверка не меняет ключи, SNI, firewall или работающие сервисы.',flush=True)
    print('Проверяется сохраненный профиль: '+username,flush=True)
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('https://api.ipify.org',timeout=8) as response:
            address=str(ipaddress.ip_address(response.read(256).decode().strip()))
        print('VPS_DIRECT_HTTPS: OK; внешний IP '+address,flush=True)
    except Exception as exc:
        print('VPS_DIRECT_HTTPS: FAIL; '+failure_code(exc),flush=True)
    failed=False
    choices=[('xhttp',443)] if state.get('schema',1)==2 else [('xhttp',443),('tcp',8443)]
    for transport,port in choices:
        try:
            inbound=next((item for item in running['inbounds'] if item.get('port')==port),None)
            if inbound is None: raise CheckError('INBOUND_NOT_FOUND')
            link=(DATA/f'current/output/{username}-{transport}.txt').read_text()
            user='check-'+secrets.token_hex(4); password=secrets.token_urlsafe(24)
            config=make_client(link,server_address,inbound,user,password)
            with temporary_client(info['Image'],network,config) as local_port:
                status,address=probe_client(local_port,user,password)
            print(f'VLESS_{transport.upper()}_SERVER_TEST: OK; HTTPS {status}'+
                ('; внешний IP '+address if address else '; получен HTTP-ответ сайта'),flush=True)
        except Exception as exc:
            failed=True
            print(f'VLESS_{transport.upper()}_SERVER_TEST: FAIL; '+failure_code(exc),flush=True)
    print('Это тест внутри VPS. Доступ из сети клиента и обход DPI он не подтверждает.')
    return 1 if failed else 0

if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('VLESS_CHECK: FAIL; '+failure_code(exc),file=sys.stderr)
        sys.exit(1)
