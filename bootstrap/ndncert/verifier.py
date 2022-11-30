from typing import Dict, Tuple
from abc import abstractmethod

from ndn.encoding import Name
from ndn.appv2 import NDNApp, Validator
from ndn.app_support.light_versec import Checker
from .protocol_v3 import *
from ..crypto_tools import *
from .cert_state import *

class Verifier(object):
    def __init__(self, app: NDNApp, config: Dict, checker: Checker, validator: Validator):
        pass
    
    @abstractmethod
    async def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        pass
        
    @abstractmethod
    async def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        pass