from typing import Tuple, Dict
from abc import abstractmethod
import plyvel, logging

from ..proto.ndncert_proto import *
from ..proto.ca_storage import *
from ..utils.sending_email import *

from ndn.encoding import Name
from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS

from datetime import datetime

class Authenticator(object):
    def __init__(self, app: NDNApp, config: Dict, auth_mean: str, db_dir: str):
        self.config = config
        self.auth_mean = auth_mean
        self.app = app
        self.db_dir = db_dir
        
    @abstractmethod
    async def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        pass

    @abstractmethod
    async def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        pass

    def autopass(self, cert_state: CertState) -> bool:
        return True

    def autofail(self, cert_state: CertState) -> bool:
        return False

    def autofail_but_notify(self, cert_state: CertState) -> bool:
        operator_email = self.config['auth_config']['operator_email']
        logging.info(f'Sending email to the operator {operator_email}')
        
        ca_name = self.config['prefix_config']['prefix_name'] + '/CA'
        cert_name = parse_certificate(cert_state.csr).name
        identity_fac = 'Identity Factor: ' + bytes(cert_state.iden_key).decode('utf-8')
        identity_val = ', Identity Value: ' + bytes(cert_state.iden_value).decode('utf-8')

        SendingEmail(operator_email, ca_name, Name.to_str(cert_name), 
                     identity_fac + identity_val, 'auth/operator-email.conf')
        return False
    
    
    def accept_from_approval_list(self, cert_state: CertState) -> bool:
        cert_name = parse_certificate(cert_state.csr).name
        identity_name = cert_name[:-4]

        # clean up all expired bindings
        db = plyvel.DB(self.db_dir)
        db_result = db.get(b'approved_bindings')
        if db_result:
            approved_bindings = IdentityBindingList.parse(db_result)
            approved_bindings.bindings = [binding for binding in approved_bindings.bindings
                                          if binding.timestamp and
                                             binding.timestamp > int(datetime.utcnow().timestamp())]
            db.put(b'approved_bindings', approved_bindings.encode())                       
        db.close()

        if db_result:
            for binding in approved_bindings.bindings:
                # the following must excat match
                # auth mean, iden_key, iden_value, name
                if binding.auth_mean == cert_state.auth_mean and \
                   binding.iden_key == cert_state.iden_key and \
                   binding.iden_value == cert_state.iden_value and \
                   binding.name == identity_name:
                    return True
        return False

    def accept_from_semantic(self, target_auth, cert_state: CertState) -> bool:
        if 'semantic_check' not in self.config['auth_config'][self.auth_mean]:
            # bypass
            return True
        semantic_policy = self.config['auth_config'][self.auth_mean]['semantic_check']
        cert_name = parse_certificate(cert_state.csr).name

        # semantic check
        translator = getattr(target_auth, semantic_policy['translator'])
        translated_name = translator(target_auth, bytes(cert_state.iden_value).decode('utf-8'))
        lvs = semantic_policy['lvs']
        checker = Checker(compile_lvs(lvs), DEFAULT_USER_FNS)
        if checker.check(cert_name, translated_name):
            return True
        else:
            # cast to corresponding func
            user_func = getattr(target_auth, semantic_policy['if_lvs_fail']['user_func'])
            return user_func(target_auth, cert_state)

    def accept_from_membership(self, target_auth, cert_state: CertState) -> bool:
        if 'membership_check' not in self.config['auth_config'][self.auth_mean]:
            # bypass
            return True
        # membership check
        membership_policy = self.config['auth_config'][self.auth_mean]['membership_check']
        user_func = getattr(target_auth, membership_policy['user_func'])
        return user_func(target_auth, cert_state)

    def accept(self, target_auth, cert_state: CertState) -> bool:
        # check for manual approval list
        if self.accept_from_approval_list(self, cert_state):
            return True
        if not self.accept_from_semantic(self, target_auth, cert_state):
            return False
        if not self.accept_from_membership(self, target_auth, cert_state):
            return False
        return True
