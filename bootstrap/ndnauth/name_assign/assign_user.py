from typing import Dict
from ndn.encoding import Name, FormalName, Component

from .assign import NameAssigner
from ..auth_state import *

class UserNameAssigner(NameAssigner): 
    def __init__(self, config: Dict):
        self.config = config

    # plain_split: alice@gmail.com -> /alice/gmail.com
    def plain_split(self, auth_id: str) -> FormalName: 
        index = auth_id.rindex("@")
        return Name.from_str('/' + str(auth_id[:index]) + 
                             '/' + str(auth_id[index + 1:]))
    
    # domain_split: alice@gmail.com -> /alice/gmail/com
    def domain_split(self, auth_id: str) -> FormalName: 
        index = auth_id.rindex("@")
        user_part = str(auth_id[:index])
        domain_part = str(auth_id[index + 1:])
        domain_comps = [Component.from_str(seg) for seg in domain_part.rsplit('.')]
        return [Component.from_str(user_part)] + domain_comps

    # domain_split: alice@gmail.com -> /com/gmail/alice
    def domain_split_reverse(self, auth_id: str) -> FormalName: 
        splitted = self.domain_split(auth_id)
        splitted.reverse()
        return splitted
    
    def assign(self, auth_state: AuthStateUser) -> FormalName:
        return getattr(__class__, self.config)(self, bytes(auth_state.email).decode('utf-8'))
