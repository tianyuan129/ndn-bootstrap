from typing import Dict, List

from ..protocol import *
from ...crypto_tools import *

from .member_check import MembershipChecker

class EmailMembershipChecker(MembershipChecker): 
    def __init__(self, config: Dict):
        self.config = config
        for checker_type in self.config:
            self.checker = lambda auth_id : getattr(__class__, checker_type)(self, self.config[checker_type], auth_id)
            
    def whitelist(self, whitelist: List, auth_id: str) -> bool:
        return auth_id in whitelist

    async def check(self, auth_id: str) -> bool:
        return self.checker(auth_id)