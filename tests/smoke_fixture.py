"""Synthetic credentials only. Never use production data in CI."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from test_render import RenderTests
from profiles import harden

dest=Path(sys.argv[1]).resolve()
state=harden(RenderTests().state())
RenderTests().render(state,dest)
client=(dest/'output/vlad.conf').read_text()
lines=[line for line in client.splitlines()
       if not line.startswith(('Address =','DNS =','MTU =','Endpoint =','AllowedIPs ='))]
lines=[line if not line.startswith('PersistentKeepalive') else 'PersistentKeepalive = 1' for line in lines]
lines+=['Endpoint = SERVER_IP:51820','AllowedIPs = 10.77.0.0/24']
(dest/'client.conf').write_text('\n'.join(lines)+'\n')
