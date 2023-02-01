from typing import Dict, List
import logging, pem
from OpenSSL.crypto import X509Store, X509StoreContext, X509StoreContextError, load_certificate, FILETYPE_PEM

from ..protocol import *
from ...crypto_tools import *

from .member_check import MembershipChecker
from ..auth_state import *
    
class ServerMembershipChecker(MembershipChecker): 
    def __init__(self, config: Dict):
        self.config = config
        self.x509_trust_anchors = self.config['trust_anchors']
        self.checker = lambda auth_state : self.whitelist(self.config['whitelist'], auth_state)
            
    def whitelist(self, whitelist: List, auth_state: AuthStateServer) -> AuthStateServer:
        pem_list = pem.parse(bytes(auth_state.x509_chain))
        loaded_chain = [load_certificate(FILETYPE_PEM, curr_pem.as_bytes())
                        for curr_pem in pem_list]
        trust_certs = X509Store()
        trust_certs.load_locations(cafile=None, capath=self.x509_trust_anchors)
        logging.info(f'Gettting certificate of {loaded_chain[0].get_subject().commonName}')
        ctx = X509StoreContext(trust_certs, loaded_chain[0], loaded_chain[1:])
        try:
            ctx.verify_certificate()
        except X509StoreContextError as e:
            logging.debug(f'Errors occurred in certificate {e.certificate.get_subject()} issued by {e.certificate.get_issuer()}, due to reason {e}')
            auth_state.is_member = False
        if loaded_chain[0].get_subject().commonName in whitelist:
            auth_state.is_member = True
        else:
            auth_state.is_member = False
        return auth_state
   
    async def check(self, auth_state: AuthStateServer) -> AuthStateServer:
        return self.checker(auth_state)