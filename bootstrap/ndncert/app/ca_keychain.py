from typing import Dict
from .ca import Ca
from ndn.app import NDNApp
from ndn.security import KeychainSqlite3

class CaWithKeychain(Ca):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3):
        ca_prefix = config['prefix_config']['prefix_name']
        cert_name = keychain[ca_prefix].default_key().default_cert().name     
        def _get_signer(name):
            return keychain.get_signer({'cert': cert_name})
        Ca.__init__(self, app, config, keychain, _get_signer)