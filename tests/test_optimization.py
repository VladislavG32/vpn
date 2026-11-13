import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_render
from test_firewall import BASH
r = test_render.r
ROOT = Path(__file__).resolve().parents[1]

class SniOptimizationTests(unittest.TestCase):
    def candidate(self, state, probe):
        with tempfile.TemporaryDirectory() as tmp:
            data=Path(tmp); (data/'current').mkdir()
            (data/'current/state.json').write_text(json.dumps(state))
            output=io.StringIO()
            argv=['render.py','candidate',','.join(r.USERS),'gateway.icloud.com,www.yahoo.com,swift.com','optimize']
            with patch.object(r,'DATA',data), patch.object(r,'probe_sni',side_effect=probe), patch.object(r.sys,'argv',argv), patch.object(r.sys,'stdout',output), patch.object(r.subprocess,'run'):
                r.main()
            return json.loads((data/output.getvalue().strip()/'state.json').read_text())

    def test_bad_target_replaced_without_changing_user_or_server_credentials(self):
        state=test_render.RenderTests().state(); state['sni']='gateway.icloud.com'
        def probe(name):
            if name=='gateway.icloud.com': raise ValueError('warned target')
        new=self.candidate(state,probe)
        self.assertNotEqual(new['sni'],state['sni'])
        for key in state:
            if key!='sni': self.assertEqual(new[key],state[key])

    def test_healthy_target_is_preserved(self):
        state=test_render.RenderTests().state()
        self.assertEqual(self.candidate(state,lambda name:None),state)

    def test_failed_reselection_cannot_modify_active_state(self):
        state=test_render.RenderTests().state()
        def fail(name): raise ValueError('unreachable')
        with self.assertRaises(ValueError): self.candidate(state,fail)

    def test_warned_and_excluded_targets_rejected_before_network_access(self):
        with patch.object(r.socket,'getaddrinfo') as dns:
            for name in ['gateway.icloud.com','GATEWAY.ICLOUD.COM.','example.ru','example.cn']:
                with self.assertRaises(ValueError): r.probe_sni(name)
            dns.assert_not_called()

    def test_private_target_is_rejected(self):
        with patch.object(r.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError): r.probe_sni('example.org')

    def test_cloudflare_address_is_rejected_before_tls(self):
        for address in ('104.16.1.1','2606:4700::1111'):
            with patch.object(r.socket,'getaddrinfo',return_value=[(2,1,6,'',(address,443))]), patch.object(r.socket,'create_connection') as tls:
                with self.assertRaisesRegex(ValueError,'Cloudflare'): r.probe_sni('example.org')
                tls.assert_not_called()

    def test_shared_candidate_catalog_is_expanded_unique_and_excludes_warned_domains(self):
        names=[line.split('#',1)[0].strip() for line in (ROOT/'configs/sni-domains.txt').read_text().splitlines()]
        names=[name for name in names if name]
        self.assertGreaterEqual(len(names),20)
        self.assertEqual(len(names),len(set(names)))
        self.assertFalse(set(names)&r.AVOID_SNI)
        for name in names:
            self.assertFalse(name.endswith(('.ru','.cn')))
            self.assertNotIn('://',name)

MOCK = r'''
import json,os,sys
from pathlib import Path
path=Path(os.environ['VPN_TUNE_STATE']); state=json.loads(path.read_text())
args=sys.argv[1:]; state['calls'].append(args); code=0
if args[0]=='-n':
    key=args[1]
    if key=='net.ipv4.tcp_available_congestion_control': print(os.environ['VPN_TUNE_AVAILABLE'])
    else: print(state['values'][key])
elif args[:2]==['-q','-w']:
    key,value=args[2].split('=',1)
    if os.environ.get('VPN_TUNE_DENY')==key: code=1
    else: state['values'][key]=value
else: raise AssertionError(args)
path.write_text(json.dumps(state)); sys.exit(code)
'''

@unittest.skipUnless(BASH,'Bash is required')
class TuningTests(unittest.TestCase):
    def run_tuning(self, available='reno cubic bbr', deny='', repeats=1):
        with tempfile.TemporaryDirectory() as tmp:
            data=Path(tmp); file=data/'state.json'; mock=data/'mock.py'
            original={'net.core.default_qdisc':'fq_codel','net.ipv4.tcp_congestion_control':'cubic','net.ipv4.tcp_mtu_probing':'0'}
            file.write_text(json.dumps(dict(values=original,calls=[]))); mock.write_text(MOCK)
            env=dict(os.environ,VPN_TUNE_STATE=str(file),VPN_TUNE_AVAILABLE=available,VPN_TUNE_DENY=deny,
                VPN_TUNE_MOCK=str(mock),VPN_TUNE_PYTHON=sys.executable,VPN_TUNE_LIBRARY=(ROOT/'configs/tuning.sh').as_posix(),VPN_TUNE_REPEATS=str(repeats),VPN_TUNE_WINDOWS=str(int(os.name=='nt')))
            script='''set -Eeuo pipefail
sysctl() { "$VPN_TUNE_PYTHON" "$VPN_TUNE_MOCK" "$@"; }
modprobe() { return 0; }
if [[ $VPN_TUNE_WINDOWS == 1 ]]; then
    # NTFS ACLs are not POSIX permissions; Linux keeps the real install/chmod.
    install() { mkdir -p "${@: -1}"; }
    chmod() { return 0; }
fi
source "$VPN_TUNE_LIBRARY"
for ((i=0;i<VPN_TUNE_REPEATS;i++)); do vpn_tune_network sysctl.conf tuning; done
printf '%s' "$VPN_TCP_CC" > selected.txt
'''
            result=subprocess.run([BASH,'-c',script],cwd=data,env=env,capture_output=True,text=True,encoding='utf-8')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return result,json.loads(file.read_text()),(data/'sysctl.conf').read_text(),(data/'tuning/original.conf').read_text(),(data/'selected.txt').read_text()

    def test_bbr_persisted_and_original_values_survive_repeated_setup(self):
        result,state,config,original,selected=self.run_tuning(repeats=2)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(selected,'bbr')
        self.assertIn('net.ipv4.tcp_congestion_control = bbr',config)
        self.assertEqual(original.count('net.ipv4.tcp_congestion_control = cubic'),1)
        self.assertNotIn(' = bbr',original)
        allowed={'net.core.default_qdisc','net.ipv4.tcp_congestion_control','net.ipv4.tcp_mtu_probing'}
        self.assertTrue(all(call[2].split('=')[0] in allowed for call in state['calls'] if call[:2]==['-q','-w']))

    def test_missing_bbr_keeps_current_algorithm(self):
        result,state,config,_,selected=self.run_tuning(available='reno cubic')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(selected,'cubic')
        self.assertNotIn('= bbr',config)
        self.assertEqual(state['values']['net.ipv4.tcp_mtu_probing'],'1')

    def test_denied_bbr_does_not_persist_unsupported_setting(self):
        result,_,config,_,selected=self.run_tuning(deny='net.ipv4.tcp_congestion_control')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(selected,'cubic')
        self.assertNotIn('net.ipv4.tcp_congestion_control = bbr',config)

if __name__=='__main__': unittest.main()
