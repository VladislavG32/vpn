import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import io
import unittest
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

spec = importlib.util.spec_from_file_location('render', Path(__file__).resolve().parents[1]/'configs/render.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class RenderTests(unittest.TestCase):
    def state(self):
        private, public = r.keypair(True)
        ap, au = r.keypair()
        return dict(schema=1, endpoint='vpn.example.org', sni='www.yahoo.com',
            reality_private=private, reality_public=public, awg_private=ap, awg_public=au,
            port=32999, path='/test', obfs=dict(Jc=4,Jmin=64,Jmax=900,S1=40,S2=50,S3=16,S4=18,H1=111111,H2=222222,H3=333333,H4=444444),
            users={n:r.user_record(i) for i,n in enumerate(r.USERS)})

    def render(self, state, dest):
        # QR encoder is exercised on the VPS; capture payloads without requiring it locally.
        with patch.object(r.subprocess, 'run') as qr:
            r.render(state, dest)
        return qr

    def test_profiles_match_server_and_stable_regeneration(self):
        state=self.state()
        with tempfile.TemporaryDirectory() as tmp:
            a,b=Path(tmp)/'a',Path(tmp)/'b'
            qr=self.render(state,a)
            self.render(state,b)
            self.assertEqual(qr.call_count,24)
            self.assertEqual((a/'xray.json').read_bytes(),(b/'xray.json').read_bytes())
            self.assertEqual((a/'awg.conf').read_bytes(),(b/'awg.conf').read_bytes())
            config=json.loads((a/'xray.json').read_text())
            self.assertEqual([i['port'] for i in config['inbounds']],[443,8443])
            self.assertEqual(config['inbounds'][0]['streamSettings']['xhttpSettings']['mode'],'stream-one')
            self.assertTrue(all(c['flow']=='xtls-rprx-vision' for c in config['inbounds'][1]['settings']['clients']))
            for name,user in state['users'].items():
                link=(a/f'output/{name}-xhttp.txt').read_text().strip()
                parsed=urlparse(link)
                self.assertEqual(parsed.username,user['uuid'])
                self.assertEqual(parse_qs(parsed.query)['fp'],['firefox'])
                self.assertIn('PresharedKey = '+user['psk'],(a/'awg.conf').read_text())
                self.assertIn('AllowedIPs = '+user['address']+'/32',(a/'awg.conf').read_text())
                self.assertIn('::/0',(a/f'output/{name}.conf').read_text())
                uri=(a/f'output/{name}.awg-uri.txt').read_text().strip().removeprefix('awg://')
                self.assertEqual(base64.urlsafe_b64decode(uri+'='*(-len(uri)%4)).decode(),(a/f'output/{name}.conf').read_text())

    def test_revocation_removes_server_access_and_exports(self):
        state=self.state()
        old=state['users']['vlad'].copy()
        state['users']['vlad']['enabled']=False
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'disabled'; self.render(state,dest)
            self.assertNotIn(old['uuid'],(dest/'xray.json').read_text())
            self.assertNotIn(old['public'],(dest/'awg.conf').read_text())
            self.assertFalse(list((dest/'output').glob('vlad*')))

    def test_endpoint_validation_rejects_injection_and_private_ip(self):
        for value in ['127.0.0.1','10.0.0.1','::1','x; touch /tmp/oops','https://vpn.example.org','']:
            with self.assertRaises(ValueError): r.endpoint(value)
        self.assertEqual(r.endpoint('vpn.example.org'),'vpn.example.org')

    def test_rotation_and_migration_preserve_other_credentials(self):
        state=self.state()
        with tempfile.TemporaryDirectory() as tmp:
            data=Path(tmp); (data/'current').mkdir()
            (data/'current/state.json').write_text(json.dumps(state))
            for args in [('rotate','vlad'),('refresh',)]:
                stdout=io.StringIO()
                env={'ENDPOINT':'new.example.org'} if args[0]=='refresh' else {}
                with patch.object(r,'DATA',data), patch.object(r.sys,'argv',['render.py','candidate',','.join(r.USERS),'',*args]), patch.dict(r.os.environ,env,clear=True), patch.object(r.subprocess,'run'), patch.object(r.sys,'stdout',stdout):
                    r.main()
                new=json.loads((data/stdout.getvalue().strip()/'state.json').read_text())
                self.assertEqual(new['reality_private'],state['reality_private'])
                self.assertEqual(new['awg_private'],state['awg_private'])
                self.assertEqual(new['users']['denis'],state['users']['denis'])
                if args[0]=='rotate':
                    self.assertNotEqual(new['users']['vlad']['uuid'],state['users']['vlad']['uuid'])
                    self.assertNotEqual(new['users']['vlad']['psk'],state['users']['vlad']['psk'])
                else:
                    self.assertEqual(new['users'],state['users'])
                    self.assertEqual(new['endpoint'],'new.example.org')

if __name__=='__main__': unittest.main()
