from ast import operator
from curses import flash
from typing import Tuple, Dict, Any
from datetime import datetime

from os import urandom
import os
from math import floor
import plyvel

from ndn.encoding import Name, FormalName
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS

from proto.ndncert_proto import *
from util.ndncert_crypto import *
from ca_storage import *
from util.sending_email import *

from Cryptodome.Cipher import AES

from auth.auth import Authenticator

class EmailAuthenticator(Authenticator):
    def __init__(self, ca_cert_data, keychain, requests_storage: Dict[bytes, Any], config: Dict):
        self.ca_cert_data = ca_cert_data
        self.keychain = keychain
        self.storage = requests_storage
        self.ca_name = self.ca_cert_data.name[:-4]
        self.config = config
        self.db_dir = os.path.expanduser('~/.ndncert-ca-python/')
        Authenticator.__init__(self, self.config, 'email')
        
    
    def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        cert_state.auth_mean = request.selected_challenge
        cert_state.iden_key = request.parameter_key
        cert_state.iden_value = request.parameter_value
        
        response = ChallengeResponse()
        response.status = STATUS_CHALLENGE
        response.challenge_status = CHALLENGE_STATUS_NEED_CODE.encode()
        response.remaining_tries = 1
        response.remaining_time = 300
        
        email = bytes(cert_state.iden_value).decode("utf-8")
        secret = "2345"
        cert_name = parse_certificate(cert_state.csr).name
        
        
        # acceptor fails early
        if not self.accept(self, self, cert_state):
            errs = ErrorMessage()
            errs.code = ERROR_NAME_NOT_ALLOWED[0]
            errs.info = ERROR_NAME_NOT_ALLOWED[1].encode()
            return None, errs
        
        # print(f'email = {email}')
        SendingEmail(email, secret, Name.to_str(self.ca_name) + '/CA', Name.to_str(cert_name), 'auth/email/user-auth.conf')
        
        cert_state.auth_key = "code".encode()
        cert_state.auth_value = secret.encode()
        cert_state.status = STATUS_CHALLENGE
        
        self.storage[cert_state.id] = cert_state
        return response, None

    def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState) -> Tuple[ChallengeResponse, ErrorMessage]:
        if cert_state.auth_key == request.parameter_key:
            if cert_state.auth_value == request.parameter_value:
                print(f'Success, should issue certificate')
                cert_state.status = STATUS_CHALLENGE
                csr_data = parse_certificate(cert_state.csr)

                signer = self.keychain.get_signer({'cert': self.ca_cert_data.name})
                issued_cert_name, issued_cert = derive_cert(csr_data.name[:-3], 'ndncert-python', csr_data.content, signer, datetime.utcnow(), 10000)
                cert_state.issued_cert = issued_cert
                
                response = ChallengeResponse()
                response.status = STATUS_PENDING
                response.issued_cert_name = Name.encode(issued_cert_name)
                ca_prefix = self.ca_name
                ca_prefix.append('CA')
                response.forwarding_hint = Name.to_bytes(ca_prefix)

                self.storage[cert_state.id] = cert_state
                return response, None
            else:
                print(f'Wrong, fail immediately')
                errs = ErrorMessage()
                errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
                errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1].encode()
                return None, errs
        else:
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            return None, errs

    def plain_split(self, identity_value: str) -> FormalName: 
        index = identity_value.rindex("@")
        return Name.from_str('/' + str(identity_value[:index]) + '/' + str(identity_value[index + 1:]))
    
    # map the inputs to the function blocks
    actions = {
        STATUS_BEFORE_CHALLENGE : actions_before_challenge,
        STATUS_CHALLENGE : actions_continue_challenge
    }