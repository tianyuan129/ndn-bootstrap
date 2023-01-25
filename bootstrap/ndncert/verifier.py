from typing import Dict, Tuple
from abc import abstractmethod, ABC

from ndn.encoding import Name
from ndn.appv2 import NDNApp, Validator
from ndn.app_support.light_versec import Checker
from .protocol_v3 import *
from ..crypto_tools import *
from .cert_state import *

class Verifier(ABC):
    @abstractmethod
    async def process(self, cert_state: CertState)-> Tuple[ChallengeResponse, ErrorMessage]:
        pass