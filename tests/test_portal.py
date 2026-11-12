import base64
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import test_render
r = test_render.r

class PortalTests(unittest.TestCase):
    def setUp(self):
        self.helper = test_render.RenderTests()
        self.state = self.helper.state()

    def test_page_contains_only_own_credentials_and_real_amnezia_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'generation'
            self.helper.render(self.state, dest)
            user=self.state['users']['router']
            page=dest/'webroot/p'/user['portal_token']
            html=(page/'index.html').read_text(encoding='utf-8')
            self.assertIn('VPN — router',html)
            self.assertIn('Подключение на роутере',html)
            self.assertNotIn('{{',html)
            self.assertIn('amneziawg.conf',html)
            self.assertNotIn('<script src="http',html)
            encoded=(page/'amnezia.vpn').read_text().strip().removeprefix('vpn://')
            packed=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
            raw=zlib.decompress(packed[4:])
            self.assertEqual(struct.unpack('>I',packed[:4])[0],len(raw))
            profile=json.loads(raw)
            self.assertEqual(profile['format_version'],1)
            self.assertEqual(profile['defaultContainer'],'amnezia-awg2')
            client=json.loads(profile['containers'][0]['awg']['last_config'])
            self.assertEqual(client['client_priv_key'],user['private'])
            self.assertEqual(client['psk_key'],user['psk'])
            self.assertEqual(client['config'],(page/'amneziawg.conf').read_text())
            all_text=html+raw.decode()
            self.assertNotIn(self.state['awg_private'],all_text)
            self.assertNotIn(self.state['reality_private'],all_text)
            self.assertNotIn(self.state['users']['denis']['private'],all_text)
            self.assertNotIn('userName',profile)
            links=base64.b64decode((page/'subscription.txt').read_text()).decode().splitlines()
            self.assertEqual(len(links),2)
            self.assertTrue(all(line.startswith('vless://'+user['uuid']+'@') for line in links))

    def test_disabled_and_rotated_pages_disappear(self):
        old_token=self.state['users']['vlad']['portal_token']
        self.state['users']['vlad']['enabled']=False
        with tempfile.TemporaryDirectory() as tmp:
            disabled=Path(tmp)/'disabled'; self.helper.render(self.state,disabled)
            self.assertFalse((disabled/'webroot/p'/old_token).exists())
            self.state['users']['vlad']=r.user_record(r.USERS.index('vlad'))
            rotated=Path(tmp)/'rotated'; self.helper.render(self.state,rotated)
            self.assertFalse((rotated/'webroot/p'/old_token).exists())
            self.assertTrue((rotated/'webroot/p'/self.state['users']['vlad']['portal_token']).exists())

    def test_links_command_does_not_modify_keys_or_print_disabled_users(self):
        self.state['users']['ruslan']['enabled']=False
        with tempfile.TemporaryDirectory() as tmp:
            data=Path(tmp); self.helper.render(self.state,data/'current')
            (data/'portal').mkdir(); (data/'portal/enabled').touch()
            before=(data/'current/state.json').read_bytes()
            output=io.StringIO()
            with patch.object(r,'DATA',data), patch.object(r.sys,'argv',['render.py','links']), patch.object(r.sys,'stdout',output):
                r.main()
            self.assertIn('router: https://vpn.example.org:2087/p/',output.getvalue())
            self.assertNotIn('ruslan:',output.getvalue())
            self.assertNotIn('vless://',output.getvalue())
            self.assertEqual(before,(data/'current/state.json').read_bytes())

    def test_upgrade_adds_tokens_without_rotating_existing_vpn_keys(self):
        for user in self.state['users'].values(): del user['portal_token']
        with tempfile.TemporaryDirectory() as tmp:
            data=Path(tmp); (data/'current').mkdir()
            (data/'current/state.json').write_text(json.dumps(self.state))
            output=io.StringIO()
            with patch.object(r,'DATA',data), patch.object(r.sys,'argv',['render.py','candidate',','.join(r.USERS),'']), patch.object(r.subprocess,'run'), patch.object(r.sys,'stdout',output):
                r.main()
            upgraded=json.loads((data/output.getvalue().strip()/'state.json').read_text())
            self.assertEqual(upgraded['awg_private'],self.state['awg_private'])
            for name in r.USERS:
                user=upgraded['users'][name]
                self.assertEqual(len(user.pop('portal_token')),43)
                self.assertEqual(user,self.state['users'][name])

    def test_invalid_token_cannot_escape_webroot(self):
        self.state['users']['denis']['portal_token']='../../outside'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                self.helper.render(self.state,Path(tmp)/'bad')

if __name__ == '__main__': unittest.main()
