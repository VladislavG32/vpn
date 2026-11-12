"""Exercise the shell helper against stateful command doubles, never host firewall."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
if (BASH is None or os.name == 'nt') and shutil.which('git'):
    candidate = Path(shutil.which('git')).parent.parent/'bin/bash.exe'
    if candidate.is_file(): BASH = str(candidate)

MOCK = r'''
import json,os,sys
from pathlib import Path
file=Path(os.environ['VPN_FW_STATE']); state=json.loads(file.read_text())
kind=sys.argv[1]; args=sys.argv[2:]; state['calls'].append([kind,*args]); code=0
if kind=='ufw':
    if args==['status']: print('Status: '+os.environ['VPN_FW_UFW'])
else:
    if args[:2]==['-w','5']: args=args[2:]
    op,chain=args[:2]; rules=state['rules']
    if op=='-S': code=0 if chain in rules else 1
    elif op=='-N': rules[chain]=[]
    elif op=='-F': rules[chain]=[]
    elif op=='-A': rules[chain].append(args[2:])
    elif op=='-C': code=0 if args[2:] in rules.get(chain,[]) else 1
    elif op=='-I': rules[chain].insert(int(args[2])-1,args[3:])
    else: raise AssertionError(args)
file.write_text(json.dumps(state)); sys.exit(code)
'''

@unittest.skipUnless(BASH, 'Bash is required')
class FirewallTests(unittest.TestCase):
    def run_helper(self, active='active', portal='1', port='53903', repeats=1):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp); state=folder/'state.json'; mock=folder/'mock.py'
            initial=[['-p','tcp','--dport','2222','-j','ACCEPT'],['-j','DROP']]
            state.write_text(json.dumps(dict(rules={'INPUT':initial},calls=[])))
            mock.write_text(MOCK)
            env=dict(os.environ,VPN_FW_STATE=str(state),VPN_FW_UFW=active,
                VPN_FW_MOCK=str(mock),VPN_FW_PYTHON=sys.executable,
                VPN_FW_LIBRARY=(ROOT/'configs/firewall.sh').as_posix(),
                VPN_FW_PORT=port,VPN_FW_PORTAL=portal,VPN_FW_REPEATS=str(repeats))
            script='''set -Eeuo pipefail
iptables() { "$VPN_FW_PYTHON" "$VPN_FW_MOCK" iptables "$@"; }
ufw() { "$VPN_FW_PYTHON" "$VPN_FW_MOCK" ufw "$@"; }
source "$VPN_FW_LIBRARY"
for ((i=0;i<VPN_FW_REPEATS;i++)); do
    vpn_firewall_apply "$VPN_FW_PORT" "$VPN_FW_PORTAL"
done
'''
            result=subprocess.run([BASH,'-c',script],cwd=folder,env=env,capture_output=True,text=True,encoding='utf-8')
            return result,json.loads(state.read_text()),initial

    def test_active_ufw_and_repeated_run_preserve_ssh_and_other_policies(self):
        result,state,initial=self.run_helper(repeats=2)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(state['rules']['INPUT'],[['-j','PRIVATE-VPN-IN'],*initial])
        rules=state['rules']['PRIVATE-VPN-IN']
        self.assertEqual(len(rules),6)
        self.assertEqual({rule[3] for rule in rules if '--dport' in rule},{'80','2087','443','8443','53903'})
        for kind,*args in state['calls']:
            if kind=='ufw': self.assertIn(args[0],['status','allow'])
            if kind=='iptables':
                self.assertNotIn('-P',args)
                if '-F' in args: self.assertEqual(args[-1],'PRIVATE-VPN-IN')

    def test_inactive_ufw_is_not_enabled_and_portal_can_be_omitted(self):
        result,state,_=self.run_helper(active='inactive',portal='0')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual([call for call in state['calls'] if call[0]=='ufw'],[['ufw','status']])
        rules=state['rules']['PRIVATE-VPN-IN']
        self.assertEqual({rule[3] for rule in rules if '--dport' in rule},{'443','8443','53903'})

    def test_invalid_udp_port_makes_no_firewall_changes(self):
        result,state,initial=self.run_helper(port='22; echo bad')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(state['calls'],[])
        self.assertEqual(state['rules'],{'INPUT':initial})

if __name__=='__main__': unittest.main()
