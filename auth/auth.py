from typing import Tuple, Dict, Any
from abc import ABC, abstractmethod

from proto.ndncert_proto import *
from ca_storage import *


class Authenticator(object):
    @abstractmethod
    def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        pass

    @abstractmethod
    def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        pass