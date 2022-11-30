from typing import Dict
from abc import abstractmethod

from ..protocol import *

from datetime import datetime

class MembershipChecker(object):
    def __init__(self, config: Dict):
        pass

    @abstractmethod
    async def check(self, auth_id: str) -> bool:
        pass
