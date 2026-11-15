import copy
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('check_vless',ROOT/'configs/check_vless.py')
check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)

class VlessCheckTests(unittest.TestCase):
    def profile(self,network='tcp'):
        server=dict(port=8443 if network=='tcp' else 443,
            settings=dict(clients=[dict(id='test-uuid',**({'flow':'xtls-rprx-vision'} if network=='tcp' else {}))]),
            streamSettings=dict(network=network,security='reality',realitySettings=dict(
                privateKey='server-private-never-export',serverNames=['example.org'],shortIds=['0123456789abcdef'])))
        if network=='xhttp':server['streamSettings']['xhttpSettings']=dict(path='/profile',mode='stream-one')
        link=f"vless://test-uuid@vpn.example.org:{server['port']}?security=reality&sni=example.org&sid=0123456789abcdef&pbk=test-public&fp=firefox&type={network}"
        link+='&flow=xtls-rprx-vision' if network=='tcp' else '&path=%2Fprofile&mode=stream-one'
        return link,server

    def test_both_profiles_keep_transport_settings_without_exporting_private_key(self):
        for network in ('tcp','xhttp'):
            link,server=self.profile(network);original=copy.deepcopy(server)
            config=check.make_client(link,'172.18.0.3',server,'temporary','secret')
            self.assertEqual(server,original)
            self.assertNotIn('server-private-never-export',json.dumps(config))
            self.assertEqual(config['outbounds'][0]['streamSettings']['network'],network)
            self.assertEqual(config['inbounds'][0]['settings']['auth'],'password')
            self.assertEqual(config['outbounds'][0]['settings']['vnext'][0]['address'],'172.18.0.3')

    def test_stale_uuid_sni_short_id_and_xhttp_path_are_reported(self):
        link,server=self.profile('xhttp')
        for old,new in [('test-uuid','old-uuid'),('sni=example.org','sni=old.example.org'),('sid=0123456789abcdef','sid=1111111111111111'),('path=%2Fprofile','path=%2Fold')]:
            with self.assertRaises(check.CheckError):
                check.make_client(link.replace(old,new),'172.18.0.3',server,'u','p')

    def test_error_output_does_not_echo_arbitrary_exception_text(self):
        self.assertEqual(check.failure_code(OSError('SECRET-UUID-HERE')),'CONNECTION_ERROR')
        self.assertEqual(check.failure_code(ValueError('SECRET-UUID-HERE')),'CHECK_FAILED')
        self.assertEqual(check.failure_code(ssl.SSLCertVerificationError('sensitive')),'HTTPS_CERTIFICATE_FAILED')

    def test_transient_failure_is_retried_without_disabling_tls_checks(self):
        with patch.object(check,'https_over_socks',side_effect=[TimeoutError(),(200,'192.0.2.1')]) as fetch,patch.object(check.time,'sleep'):
            self.assertEqual(check.probe_client(12345,'u','p'),(200,'192.0.2.1'))
            self.assertEqual(fetch.call_count,2)
        with patch.object(check,'https_over_socks',side_effect=ssl.SSLCertVerificationError()) as fetch:
            with self.assertRaises(ssl.SSLCertVerificationError):check.probe_client(12345,'u','p')
            self.assertEqual(fetch.call_count,1)

    def test_socks_uses_authentication_and_remote_domain_resolution(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1];seen=[];errors=[]
        def serve():
            try:
                with listener.accept()[0] as sock:
                    sock.settimeout(3)
                    seen.append(check.read_exact(sock,3));sock.sendall(b'\x05\x02')
                    self.assertEqual(check.read_exact(sock,1),b'\x01')
                    user=check.read_exact(sock,check.read_exact(sock,1)[0])
                    password=check.read_exact(sock,check.read_exact(sock,1)[0])
                    seen.extend([user,password]);sock.sendall(b'\x01\x00')
                    seen.append(check.read_exact(sock,4))
                    seen.append(check.read_exact(sock,check.read_exact(sock,1)[0]))
                    seen.append(check.read_exact(sock,2));sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                    self.assertEqual(check.read_exact(sock,2),b'hi');sock.sendall(b'ok')
            except BaseException as exc:errors.append(exc)
            finally:listener.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        try:
            with check.socks_connect(port,'temporary','secret',target='example.org',target_port=443) as sock:
                sock.sendall(b'hi');self.assertEqual(check.read_exact(sock,2),b'ok')
        finally:thread.join(timeout=4)
        if errors:raise errors[0]
        self.assertFalse(thread.is_alive())
        self.assertEqual(seen,[b'\x05\x01\x02',b'temporary',b'secret',b'\x05\x01\x00\x03',b'example.org',b'\x01\xbb'])

    def test_temporary_client_is_local_only_and_cleaned_after_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls=[]
            def docker(*args):
                calls.append(args)
                if args[0]=='inspect':return json.dumps([dict(NetworkSettings=dict(Ports={'1080/tcp':[dict(HostPort='12345')]}))])
                return 'temporary-container'
            with patch.object(check,'DATA',Path(tmp)),patch.object(check,'docker',side_effect=docker),patch.object(check.socket,'create_connection'),patch.object(check.subprocess,'run') as remove:
                with self.assertRaisesRegex(check.CheckError,'EXPECTED'):
                    with check.temporary_client('sha256:test','private-vpn_egress',dict(log={})):raise check.CheckError('EXPECTED')
                self.assertIn('127.0.0.1::1080',calls[0])
                self.assertIn('--cap-drop',calls[0])
                command=remove.call_args.args[0]
                self.assertEqual(command[:3],['docker','rm','--force'])
                self.assertTrue(command[3].startswith('private-vpn-check-'))
                self.assertEqual(list((Path(tmp)/'diagnostics').iterdir()),[])

if __name__=='__main__':unittest.main()
