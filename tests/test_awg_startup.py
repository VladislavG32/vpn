"""Check kernel selection/fallback and optional MSS handling without NET_ADMIN."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_firewall import BASH

ROOT=Path(__file__).resolve().parents[1]
MOCK=r'''
import json,os,sys
from pathlib import Path
kind=sys.argv[1];args=sys.argv[2:];folder=Path(os.environ['VPN_AWG_TEST'])
with (folder/'calls.jsonl').open('a') as file: file.write(json.dumps([kind,*args])+'\n')
mode=os.environ['VPN_AWG_MODE']
if kind=='ip' and args[:3]==['link','add','awg0']: sys.exit(1 if mode=='absent' else 0)
if kind=='ip' and args==['-4','route','show','default']: print('default via 172.18.0.1 dev eth0')
if kind=='awg' and args[:2]==['setconf','awg0']:
    count=folder/'setconf-count'; n=int(count.read_text())+1 if count.exists() else 1;count.write_text(str(n))
    if mode=='legacy' and n==1: sys.exit(1)
if kind=='iptables' and 'TCPMSS' in args and os.environ['VPN_AWG_MSS_FAIL']=='1':sys.exit(1)
'''

@unittest.skipUnless(BASH,'Bash is required')
class AwgStartupTests(unittest.TestCase):
    def startup(self,mode,mss_fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);(folder/'mock.py').write_text(MOCK)
            env=dict(os.environ,VPN_AWG_TEST=str(folder),VPN_AWG_PYTHON=sys.executable,
                VPN_AWG_MOCK=str(folder/'mock.py'),VPN_AWG_MODE=mode,
                VPN_AWG_ENTRY=(ROOT/'configs/awg-entrypoint.sh').as_posix(),VPN_AWG_MSS_FAIL=str(int(mss_fail)))
            script='''
ip() { "$VPN_AWG_PYTHON" "$VPN_AWG_MOCK" ip "$@"; }
awg() { "$VPN_AWG_PYTHON" "$VPN_AWG_MOCK" awg "$@"; }
iptables() {
    "$VPN_AWG_PYTHON" "$VPN_AWG_MOCK" iptables "$@" || return $?
    if [[ "$*" == *POSTROUTING* ]]; then exit 77; fi
}
amneziawg-go() { "$VPN_AWG_PYTHON" "$VPN_AWG_MOCK" go "$@"; exec sleep 30; }
[() { if [[ ${1:-} == -S ]]; then return 0; fi; builtin [ "$@"; }
source "$VPN_AWG_ENTRY"
'''
            result=subprocess.run([BASH,'-c',script],cwd=folder,env=env,capture_output=True,text=True,encoding='utf-8',timeout=15)
            self.assertEqual(result.returncode,77,result.stdout+result.stderr)
            calls=[json.loads(line) for line in (folder/'calls.jsonl').read_text().splitlines()]
            return result,calls

    def test_compatible_kernel_skips_go_and_keeps_nat_and_mss_rules(self):
        _,calls=self.startup('compatible')
        self.assertFalse(any(call[0]=='go' for call in calls))
        self.assertEqual(sum('TCPMSS' in call for call in calls),2)
        self.assertTrue(any('MASQUERADE' in call for call in calls))

    def test_legacy_kernel_rejected_config_falls_back_to_go(self):
        result,calls=self.startup('legacy')
        self.assertTrue(any(call[0]=='go' for call in calls))
        self.assertEqual(sum(call[:3]==['awg','setconf','awg0'] for call in calls),2)
        self.assertIn('kernel rejected',result.stderr)

    def test_no_kernel_and_missing_mss_extension_still_start_tunnel(self):
        result,calls=self.startup('absent',mss_fail=True)
        self.assertTrue(any(call[0]=='go' for call in calls))
        self.assertIn('TCPMSS extension unavailable',result.stderr)

if __name__=='__main__':unittest.main()
