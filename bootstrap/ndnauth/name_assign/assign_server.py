from typing import Dict
import logging
from cryptography import x509
from ndn.encoding import Name, FormalName, Component

from .assign import NameAssigner
from ..auth_state import *

class ServerNameAssigner(NameAssigner): 
    def __init__(self, config: Dict):
        self.config = config

    # plain_copy: bruins.cs.ucla.edu -> bruins.cs.ucla.edu
    def plain_copy(self, common_name_str: str) -> FormalName:
        return Name.from_str(common_name_str)

    def assign(self, auth_state: AuthStateServer) -> FormalName:
        loaded_chain = x509.load_pem_x509_certificates(bytes(auth_state.x509_chain))
        leaf = loaded_chain[0]
        common_names = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        common_name_str = common_names[0].value 
        return getattr(__class__, self.config)(self, common_name_str)
