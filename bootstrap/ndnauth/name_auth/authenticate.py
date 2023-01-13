from typing import Tuple, Dict
from abc import abstractmethod

from ..protocol import *
from ..auth_state import *

class Authenticator(object):
    def __init__(self, config: Dict):
        pass
        
    @abstractmethod
    async def after_receive_boot_params(self, auth_state: AuthState) -> Tuple[AuthState, ErrorMessage]:
        pass

    @abstractmethod
    async def after_receive_idproof_params(self, auth_state: AuthState) -> Tuple[AuthState, ErrorMessage]:
        pass
