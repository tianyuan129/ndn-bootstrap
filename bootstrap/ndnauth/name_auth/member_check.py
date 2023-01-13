from typing import Dict
from abc import abstractmethod

from ..protocol import *
from ..auth_state import *


class MembershipChecker(object):
    def __init__(self, config: Dict):
        pass

    @abstractmethod
    async def check(self, auth_state: AuthState) -> AuthState:
        pass