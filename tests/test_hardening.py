"""Migration preserves identity while changing both ends of AWG together."""
import base64
import json
import io
from pathlib import Path
import tempfile
import unittest
import zlib
from unittest.mock import patch
import test_render
from profiles import harden

r=test_render.r

class HardeningTests(unittest.TestCase):
    def setUp(self): self.helper=test_render.RenderTests()

    def test_new_install_uses_compact_layout_and_disables_router(self):
        with patch.object(r,'choose_sni',return_value='www.yahoo.com'), patch.dict(r.os.environ,{'ENDPOINT':'vpn.example.org'}):
            state=r.initial(['www.yahoo.com'])
        self.assertEqual(state['schema'],2)
        self.assertEqual(state['fingerprint'],'chrome')
        self.assertEqual(sum(user['enabled'] for user in state['users'].values()),7)
        self.assertFalse(state['users']['router']['enabled'])

    def test_candidate_migration_leaves_active_state_untouched(self):
        old=self.helper.state()
        with tempfile.TemporaryDirectory() as tmp:
            data=Path(tmp); (data/'current').mkdir()
            current=data/'current/state.json'; current.write_text(json.dumps(old))
            before=current.read_bytes(); output=io.StringIO()
            args=['render.py','candidate',','.join(r.USERS),'www.yahoo.com','harden']
            with patch.object(r,'DATA',data), patch.object(r.sys,'argv',args), patch.object(r,'probe_sni'), patch.object(r.subprocess,'run'), patch.object(r.sys,'stdout',output), patch.dict(r.os.environ,{},clear=True):
                r.main()
            self.assertEqual(current.read_bytes(),before)
            new=json.loads((data/output.getvalue().strip()/'state.json').read_text())
            self.assertEqual(new['schema'],2)
            self.assertEqual(new['users']['vlad'],old['users']['vlad'])

    def test_migration_preserves_keys_and_is_idempotent(self):
        old=self.helper.state(); new=harden(old)
        self.assertEqual(old['schema'],1)
        self.assertEqual(new['schema'],2)
        for key in ('endpoint','sni','path','port','reality_private','reality_public','awg_private','awg_public'):
            self.assertEqual(new[key],old[key])
        for name in r.USERS:
            for key,value in old['users'][name].items():
                if name=='router' and key=='enabled': continue
                self.assertEqual(new['users'][name][key],value)
        self.assertFalse(new['users']['router']['enabled'])
        self.assertEqual(harden(new),new)
        obfs=new['obfs']
        self.assertEqual(len(base64.b64decode(obfs['HeaderProtectionKey'],validate=True)),32)
        self.assertEqual(len({obfs[f'S{i}'] for i in range(1,5)}),1)
        self.assertGreaterEqual(obfs['S1'],12)
        self.assertEqual([obfs[f'H{i}'] for i in range(1,5)],[1,2,3,4])

    def test_compact_profiles_and_subscription_agree(self):
        state=harden(self.helper.state()); user=state['users']['vlad']
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'gen'; self.helper.render(state,dest)
            cfg=json.loads((dest/'xray.json').read_text())
            self.assertEqual([item['port'] for item in cfg['inbounds']],[443])
            self.assertFalse((dest/'output/vlad-tcp.txt').exists())
            self.assertFalse(list((dest/'output').glob('router*')))
            self.assertFalse((dest/'webroot/p'/state['users']['router']['portal_token']).exists())
            page=dest/'webroot/p'/user['portal_token']
            html=(page/'index.html').read_text(encoding='utf-8')
            self.assertNotIn('8443',html)
            self.assertNotIn('роутер',html)
            self.assertIn('AmneziaWG 3.1',html)
            links=base64.b64decode((page/'subscription.txt').read_text()).decode().splitlines()
            self.assertEqual(len(links),1)
            self.assertEqual(links[0],(dest/'output/vlad-happ.txt').read_text().strip())
            self.assertIn('fp=chrome',links[0])
            encoded=(page/'amnezia.vpn').read_text().strip().removeprefix('vpn://')
            raw=zlib.decompress(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))[4:])
            client=json.loads(json.loads(raw)['containers'][0]['awg']['last_config'])
            for key,value in state['obfs'].items():
                self.assertEqual(client[key],str(value))
                self.assertIn(f'{key} = {value}',client['config'])
                self.assertIn(f'{key} = {value}',(dest/'awg.conf').read_text())
            self.assertEqual(client['persistent_keep_alive'],'20-30')
            self.assertNotIn(state['awg_private'],raw.decode())

if __name__=='__main__': unittest.main()
