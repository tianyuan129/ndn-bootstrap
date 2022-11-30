from typing import Dict
from abc import abstractmethod

from ..protocol import *

from ndn.encoding import FormalName

class NameAssigner(object):
    def __init__(self, config: Dict):
        pass
        
    @abstractmethod
    def assign(self, auth_id: str) -> FormalName:
        pass