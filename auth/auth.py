from typing import Tuple, Dict, Any
from abc import ABC, abstractmethod

from proto.ndncert_proto import *
from ca_storage import *
from util.sending_email import *

from ndn.encoding import Name, FormalName
from ndn.app_support.security_v2 import parse_certificate, derive_cert

class Authenticator(object):
    @abstractmethod
    def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        pass

    @abstractmethod
    def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        pass
    
    @staticmethod
    def autopass(config: Dict, cert_state: CertState) -> bool:
        return True

    @staticmethod
    def autofail(config: Dict, cert_state: CertState) -> bool:
        return False

    @staticmethod
    def autofail_but_notify(config: Dict, cert_state: CertState) -> bool:
        operator_email = config['auth_config']['operator_email']
        print(f'Sending email to the operator {operator_email}')
        
        ca_name = config['prefix_config']['prefix_name'] + '/CA'
        cert_name = parse_certificate(cert_state.csr).name
        identity_fac = 'Identity Factor: ' + bytes(cert_state.iden_key).decode('utf-8')
        identity_val = ', Identity Value: ' + bytes(cert_state.iden_value).decode('utf-8')

        SendingEmail(operator_email, ca_name, Name.to_str(cert_name), 
                     identity_fac + identity_val, 'auth/operator-email.conf')
        return False
