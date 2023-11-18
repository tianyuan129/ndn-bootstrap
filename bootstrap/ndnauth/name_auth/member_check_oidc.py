from typing import Dict, List

from ..protocol import *
from ...crypto_tools import *

from .member_check import MembershipChecker
from ..auth_state import *
    
class OidcMembershipChecker(MembershipChecker): 
    def __init__(self, config: Dict):
        self.config = config
        self.checker = lambda auth_state : self.whitelist(self.config['whitelist'], auth_state)
            
    def whitelist(self, whitelist: List, auth_state: AuthStateOidc) -> AuthStateOidc:
        if bytes(auth_state.oidc_user).decode('utf-8') in whitelist:
            auth_state.is_member = True
            return auth_state
        else:
            auth_state.is_member = False
            return auth_state
   
    async def check(self, auth_state: AuthStateOidc) -> AuthStateOidc:
        return self.checker(auth_state)