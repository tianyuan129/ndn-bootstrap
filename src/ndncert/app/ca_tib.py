from typing import Dict
from .ca import Ca
from ndn.app import NDNApp
from ndncert.security_support.tib import Tib

class CaWithTib(Ca):
    def __init__(self, app: NDNApp, config: Dict, tib: Tib):
        def _get_signer(name):
            return tib.suggest_signer(name)
        Ca.__init__(self, app, config, tib.keychain, _get_signer)