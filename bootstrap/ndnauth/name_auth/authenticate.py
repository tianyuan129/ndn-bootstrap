from typing import Tuple, Dict
from abc import abstractmethod

from ..protocol import *
from ..auth_state import AuthState

class Authenticator(object):
    def __init__(self, config: Dict):
        pass
        
    @abstractmethod
    async def actions_before_authenticate(self, auth_state: AuthState) -> Tuple[AuthState, ErrorMessage]:
        pass

    @abstractmethod
    async def actions_continue_authenticate(self, auth_state: AuthState) -> Tuple[AuthState, ErrorMessage]:
        pass
