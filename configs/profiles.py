"""Versioned deployment profiles; legacy state is changed only by explicit migration."""
import base64
import copy
import secrets

def compact(state):
    return state.get('schema',1)==2

def transports(state):
    return [(443,'xhttp')] if compact(state) else [(443,'xhttp'),(8443,'tcp')]

def awg3_parameters():
    padding=12+secrets.randbelow(13)
    return dict(Jc=4+secrets.randbelow(5),Jmin=64+secrets.randbelow(32),
        Jmax=800+secrets.randbelow(201),S1=padding,S2=padding,S3=padding,S4=padding,
        H1=1,H2=2,H3=3,H4=4,
        HeaderProtectionKey=base64.b64encode(secrets.token_bytes(32)).decode(),
        ContentPaddingAddition='8-32',RandomTrailers='on',DisableCookies='on',
        RekeyAfterTime='100-140',RekeyTimeout='4-6',RejectAfterTime='240-300',
        KeepaliveTimeout='10-20')

def harden(state):
    result=copy.deepcopy(state)
    if not compact(result):
        result['schema']=2
        result['obfs']=awg3_parameters()
        # Retire the unused router account without deleting its keys or token.
        if 'router' in result['users']: result['users']['router']['enabled']=False
    result['fingerprint']='chrome'
    return result
