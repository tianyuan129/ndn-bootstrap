from typing import Tuple, Dict, Any
from abc import ABC, abstractmethod
import plyvel

from proto.ndncert_proto import *
from ca_storage import *
from util.sending_email import *

from ndn.encoding import Name, FormalName
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS

class Authenticator(object):
    def __init__(self, config: Dict, auth_mean: str):
        self.config = config
        self.auth_mean = auth_mean
        
        
    @abstractmethod
    def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        pass

    @abstractmethod
    def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        pass

    def autopass(self, cert_state: CertState) -> bool:
        return True

    def autofail(self, cert_state: CertState) -> bool:
        return False

    def autofail_but_notify(self, cert_state: CertState) -> bool:
        operator_email = self.config['auth_config']['operator_email']
        print(f'Sending email to the operator {operator_email}')
        
        ca_name = self.config['prefix_config']['prefix_name'] + '/CA'
        cert_name = parse_certificate(cert_state.csr).name
        identity_fac = 'Identity Factor: ' + bytes(cert_state.iden_key).decode('utf-8')
        identity_val = ', Identity Value: ' + bytes(cert_state.iden_value).decode('utf-8')

        SendingEmail(operator_email, ca_name, Name.to_str(cert_name), 
                     identity_fac + identity_val, 'auth/operator-email.conf')
        return False
    
    
    def accept_from_approval_list(target_auth, cert_state: CertState) -> bool:
        cert_name = parse_certificate(cert_state.csr).name
        identity_name = cert_name[:-4]
        
        # check for manual approval list
        db = plyvel.DB(target_auth.db_dir)
        db_result = db.get(b'manual_approved')
        db.close()
        if db_result:
            manual_approved = ManualApprovalList.parse(db_result)
            for approval in manual_approved.approvals:
                # the following must excat match
                # auth mean, iden_key, iden_value, identity name
                
                approved_csr_name = parse_certificate(cert_state.csr).name
                approved_identity_name = approved_csr_name[:-4]
                if approval.state.auth_mean == cert_state.auth_mean and \
                   approval.state.iden_key == cert_state.iden_key and \
                   approval.state.iden_value == cert_state.iden_value and \
                   approved_identity_name == identity_name:
                    return True
        return False

    def accept_from_semantic(self, target_auth, cert_state: CertState) -> bool:
        cert_name = parse_certificate(cert_state.csr).name

        # semantic check
        semantic_policy = self.config['auth_config'][self.auth_mean]['semantic_check']
        translator = getattr(target_auth, semantic_policy['translator'])
        translated_name = translator(target_auth, bytes(cert_state.iden_value).decode('utf-8'))
        lvs = semantic_policy['lvs']
        checker = Checker(compile_lvs(lvs), DEFAULT_USER_FNS)
        if checker.check(cert_name, translated_name):
            return True
        else:
            # cast to corresponding func
            user_func = getattr(target_auth, semantic_policy[self.auth_mean]['user_func'])
            return user_func(target_auth.config, cert_state)

    def accept_from_membership(self, target_auth, cert_state: CertState) -> bool:
        # membership check
        membership_policy = self.config['auth_config'][self.auth_mean]['membership_check']
        user_func = getattr(target_auth, membership_policy['user_func'])
        return user_func(target_auth.config, cert_state)

    def accept(self, target_auth, cert_state: CertState) -> bool:
        # check for manual approval list
        if self.accept_from_approval_list(target_auth, cert_state):
            return True
        if not self.accept_from_semantic(self, target_auth, cert_state):
            return False
        if not self.accept_from_membership(self, target_auth, cert_state):
            return False
        return True
