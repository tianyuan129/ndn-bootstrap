from typing import Dict, List

from ..protocol import *
from ...crypto_tools import *

from .member_check import MembershipChecker
from ..auth_state import *
    
class UserMembershipChecker(MembershipChecker): 
    def __init__(self, config: Dict):
        self.config = config
        for checker_type in self.config:
            self.checker = lambda auth_state : getattr(__class__, checker_type)(self, self.config[checker_type], auth_state)
            
    def whitelist(self, whitelist: List, auth_state: AuthStateUser) -> AuthState:
        if bytes(auth_state.email).decode('utf-8') in whitelist:
            return auth_state, None
        else:
            auth_state.is_memeber = False
            errs = ErrorMessage()
            errs.code = ERROR_NAME_NOT_ALLOWED[0]
            errs.info = ERROR_NAME_NOT_ALLOWED[1].encode()
            return auth_state, errs
   
    async def check(self, auth_state: AuthStateUser) -> AuthState:
        return self.checker(auth_state)