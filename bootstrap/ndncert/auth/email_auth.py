from typing import Tuple, Dict
from datetime import datetime

import logging, os
from random import randint

from ndn.encoding import Name, FormalName, Component
from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate, derive_cert

from ..proto.ndncert_proto import *
from ..utils.ndncert_crypto import *
from ..proto.ca_storage import *
from ..proto.types import GetSigner
from ..utils.sending_email import *

from .auth import Authenticator


class EmailAuthenticator(Authenticator):
    def __init__(self, app: NDNApp, cache: Dict, config: Dict, db_dir: str, get_signer: GetSigner):
        self.cache = cache
        self.config = config 
        ca_name_str = config['prefix_config']['prefix_name'] + '/CA'
        self.ca_name = Name.from_str(ca_name_str)
        self.get_signer = get_signer
        self.app = app
        Authenticator.__init__(self, app, config, 'email', db_dir)

   
    async def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        cert_state.auth_mean = request.selected_challenge
        cert_state.iden_key = request.parameter_key
        cert_state.iden_value = request.parameter_value
        
        response = ChallengeResponse()
        response.status = STATUS_CHALLENGE
        response.challenge_status = CHALLENGE_STATUS_NEED_CODE.encode()
        response.remaining_tries = 1
        response.remaining_time = 300
        
        email = bytes(cert_state.iden_value).decode("utf-8")
        EMAIL_CHALLANGE_CODE_SIZE = 6
        secret = ''
        for i in range(EMAIL_CHALLANGE_CODE_SIZE):
            secret += str(randint(0,9))
        logging.info(f'Secret for Request ID {cert_state.id.hex()} is {secret}')
        cert_name = parse_certificate(cert_state.csr).name

        # acceptor fails early
        if not self.accept(self, self, cert_state):
            errs = ErrorMessage()
            errs.code = ERROR_NAME_NOT_ALLOWED[0]
            errs.info = ERROR_NAME_NOT_ALLOWED[1].encode()
            return None, errs
        
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, 'user-auth.conf')
        SendingEmail(email, secret, Name.to_str(self.ca_name) + '/CA', 
                     Name.to_str(cert_name), filename)
        
        cert_state.auth_key = CHALLENGE_EMAIL_PARAMETER_KEY_CODE.encode()
        cert_state.auth_value = secret.encode()
        cert_state.status = STATUS_CHALLENGE
        
        self.cache[cert_state.id] = cert_state
        return response, None

    async def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        if cert_state.auth_key == request.parameter_key:
            if cert_state.auth_value == request.parameter_value:
                logging.info(f'Identity verification succeed, should issue certificate')
                cert_state.status = STATUS_CHALLENGE
                csr_data = parse_certificate(cert_state.csr)

                # signer suggester must take a full name as input, so let's mock one
                mock_name = []
                mock_name[:] = csr_data.name[:]
                mock_name[-2] = Component.from_str('ndncert-python') 
                issued_cert_name, issued_cert = derive_cert(csr_data.name[:-2], 'ndncert-python',
                                                            csr_data.content, self.get_signer(mock_name),
                                                            datetime.utcnow(), 10000)
                cert_state.issued_cert = issued_cert
                response = ChallengeResponse()
                response.status = STATUS_SUCCESS
                response.issued_cert_name = Name.encode(issued_cert_name)
                ca_prefix = self.ca_name
                ca_prefix.append('CA')
                response.forwarding_hint = Name.to_bytes(ca_prefix)

                self.cache[cert_state.id] = cert_state
                return response, None
            else:
                errs = ErrorMessage()
                errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
                errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1].encode()
                logging.error('Identity verification failed, returning errors '
                              f'{ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
                return None, errs
        else:
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            return None, errs

    # plain_split: alice@gmail.com -> /alice/gmail.com
    def plain_split(self, identity_value: str) -> FormalName: 
        index = identity_value.rindex("@")
        return Name.from_str('/' + str(identity_value[:index]) + 
                             '/' + str(identity_value[index + 1:]))
    
    # domain_split: alice@gmail.com -> /alice/gmail/com
    def domain_split(self, identity_value: str) -> FormalName: 
        index = identity_value.rindex("@")
        user_part = str(identity_value[:index])
        domain_part = str(identity_value[index + 1:])
        domain_comps = [Component.from_str(seg) for seg in domain_part.rsplit('.')]
        return [Component.from_str(user_part)] + domain_comps

    # domain_split: alice@gmail.com -> /com/gmail/alice
    def domain_split_reverse(self, identity_value: str) -> FormalName: 
        splitted = self.domain_split(identity_value)
        splitted.reverse()
        return splitted
        
    # map the inputs to the function blocks
    actions = {
        STATUS_BEFORE_CHALLENGE : actions_before_challenge,
        STATUS_CHALLENGE : actions_continue_challenge
    }