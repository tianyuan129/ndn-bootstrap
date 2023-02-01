from typing import Tuple
from abc import abstractmethod, ABC

from .protocol_v3 import *
from ..crypto_tools import *
from .cert_state import *

class Verifier(ABC):
    @abstractmethod
    async def process(self, cert_state: CertState)-> Tuple[ChallengeResponse, ErrorMessage]:
        pass