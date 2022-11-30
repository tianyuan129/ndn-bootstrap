from typing import Optional, Dict, Coroutine

import logging, sys
from os import urandom
import asyncio
from datetime import datetime

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, Component
from ndn.app_support.security_v2 import parse_certificate, KEY_COMPONENT, derive_cert
from ndn.app_support.keychain_register import attach_keychain_register
from ndn.app_support.light_versec import Checker
from ndn.security import KeychainSqlite3

from ..protocol import *
from ...crypto_tools import *
from ..name_auth import *
from ..name_assign import *
from ..auth_state import AuthState
from ...keychain_register import attach_keychain_register_appv1

class NameAuthAssign(object):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3,
                 checker: Checker, validator: Validator):
        #todo: customize the storage type
        self.requests = {}
        self.cache = {}
        self.config = config
        self.aa_prefix = self.config['prefix_config']['prefix_name']
        # self.tib = tib
        self.keychain = keychain
        self.checker = checker
        self.data_validator = validator

        try:
            aa_id = self.keychain[self.aa_prefix]
            aa_cert = aa_id.default_key().default_cert().data
            self.aa_cert_data = parse_certificate(aa_cert)
        except:
            aa_id = self.keychain.touch_identity(self.aa_prefix)
            aa_cert = aa_id.default_key().default_cert().data
            self.aa_cert_data = parse_certificate(aa_cert)

        self.app = app
        app.keychain = self.keychain
        attach_keychain_register_appv1(self.keychain, self.app)

        # initialize membership checker, authenticator, and name assigner
        self.membership_checkers = {}
        self.authenticators = {}
        self.name_assigners = {}
        
        
        auth_configs = config['auth_config']
        for auth_type in auth_configs:
            config_section = auth_configs[auth_type]

            # locate the corresponding membership checker
            checker_type_str = auth_type.capitalize() + 'MembershipChecker'
            membership_checker_type = getattr(sys.modules[__name__], checker_type_str)
            membership_checker = object.__new__(membership_checker_type, config_section['membership_checker'])
            membership_checker.__init__(config_section['membership_checker'])
            self.membership_checkers[auth_type] = membership_checker
            
            authenticator_type_str = auth_type.capitalize() + 'Authenticator'
            authenticator_type = getattr(sys.modules[__name__], authenticator_type_str)
            authenticator = object.__new__(authenticator_type, config_section['authenticator'])
            authenticator.__init__(config_section['authenticator'])
            self.authenticators[auth_type] = authenticator

            name_assigner_type_str = auth_type.capitalize() + 'NameAssigner'
            name_assigner_type = getattr(sys.modules[__name__], name_assigner_type_str)
            name_assigner = object.__new__(name_assigner_type, config_section['name_assigner'])
            name_assigner.__init__(config_section['name_assigner'])
            self.name_assigners[auth_type] = name_assigner

    def _get_signer(self, name):
        suggested_keylocator = self.checker.suggest(name, self.keychain)
        if suggested_keylocator is None:
            logging.error(f'No proper keylocator for {Name.to_str(name)}')
            return None
        else:
            return self.keychain.tpm.get_signer(suggested_keylocator[:-2], suggested_keylocator)
        
    async def on_new_interest(self, name: FormalName, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}')
        request = NewRequest.parse(_app_param)
        ecdh = ECDH()
        auth_state = AuthState()
        response = NewResponse()

        # extracting fields
        id = urandom(8)
        salt = urandom(32)
        pub = request.ecdh_pub
        pubkey = request.pubkey
        auth_type = bytes(request.auth_type).decode('utf-8')
        auth_id = bytes(request.auth_id).decode('utf-8')

        # if authentication type not available
        if not auth_type in self.config['auth_config']:
            logging.error(f'Authentication type not available')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            self.app.put_data(name, errs.encode(), freshness_period = 10000, signer = self._get_signer(name))
            return
        membership_checker = self.membership_checkers[auth_type]
        allowed = await membership_checker.check(auth_id)
        if not allowed:
            logging.error(f'Authentication id permission denied')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            self.app.put_data(name, errs.encode(), freshness_period = 10000,
                                signer = self._get_signer(name))
            return
        
        import base64
        logging.info(f'Received PubKey: {base64.b64encode(pubkey)}')
        # generating new authentication state
        ecdh.encrypt(bytes(pub), salt, id)
        auth_state.aes_key = ecdh.derived_key
        auth_state.status = STATUS_BEFORE_AUTHENTICATION
        auth_state.id = id
        auth_state.pubkey = pubkey
        auth_state.auth_type = auth_type
        auth_state.auth_id = request.auth_id
        self.requests[id] = auth_state
        logging.info(f'Request ID: {id.hex()}')
    
        authenticator = self.authenticators[auth_type]
        auth_state_ret, err = await authenticator.actions_before_authenticate(auth_state)
        if err is not None:
            self.app.put_data(name, err.encode(), freshness_period = 10000, signer = self._get_signer(name))
            return
        else:
            self.requests[id] = auth_state_ret
            response.ecdh_pub = ecdh.pub_key_encoded
            response.salt = salt
            response.request_id = id
            response.parameter_key = auth_state.auth_key
            self.app.put_data(name, response.encode(), freshness_period = 10000, signer = self._get_signer(name))

    async def on_authenticate_interest(self, name: FormalName, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}')
        message_in = EncryptedMessage.parse(_app_param)
        request_id = name[len(Name.from_str(self.aa_prefix)) + 2][-8:]

        try:
            self.requests[request_id]
        except KeyError:
            logging.error(f'No AuthState for Request ID: {request_id.hex()}')
            return
        auth_state = self.requests[request_id]
        response = AuthenticateResponse()

        # checking iv counters
        payload = get_encrypted_message(bytes(auth_state.aes_key), bytes(auth_state.id), message_in)
        request = AuthenticateRequest.parse(payload)
        if request.parameter_key == auth_state.auth_key:
            auth_state.auth_value = request.parameter_value
            authenticator = self.authenticators[auth_state.auth_type]
            auth_state_ret, err = await authenticator.actions_continue_authenticate(auth_state)
            if err is not None:
                self.app.put_data(name, err.encode(), freshness_period = 10000, signer = self._get_signer(name))
                return
    
            name_assigner = self.name_assigners[auth_state_ret.auth_type]
            auth_id_str = bytes(auth_state_ret.auth_id).decode('utf-8')
            assigned_name = name_assigner.assign(auth_id_str)

            key_id = Component.from_bytes(auth_state_ret.id)
            proof_of_possess_idname = [Component.from_str('32=authenticate')] + assigned_name
            proof_of_possess_keyname = proof_of_possess_idname + [KEY_COMPONENT, key_id]
            proof_of_possess_name_mocked = proof_of_possess_keyname + Name.from_str('/NA/v=0')
            proof_of_possess_name, proof_of_possess = \
                derive_cert(proof_of_possess_keyname, 'NA',
                            auth_state_ret.pubkey,
                            self._get_signer(proof_of_possess_name_mocked),
                            datetime.utcnow(), 10000)

            logging.info(f'Proof-of-Possession Name: {Name.to_str(proof_of_possess_name)}')
            auth_state_ret.proof_of_possess = proof_of_possess
            auth_state_ret.status = STATUS_SUCCESS
            self.requests[request_id] = auth_state_ret

            response.status = auth_state_ret.status
            response.proof_of_possess = auth_state_ret.proof_of_possess
            plaintext = response.encode()
            
            try:
                message_out, auth_state_ret.iv_random, auth_state_ret.iv_counter =\
                    gen_encrypted_message(bytes(auth_state.aes_key), bytes(auth_state.id), 
                    plaintext, auth_state_ret.iv_random, auth_state_ret.iv_counter)
            except:
                message_out, auth_state_ret.iv_random, auth_state_ret.iv_counter =\
                    gen_encrypted_message(bytes(auth_state.aes_key), bytes(auth_state.id), 
                    plaintext, None, None)                

            self.requests[request_id] = auth_state_ret
            self.app.put_data(name, message_out.encode(), freshness_period = 10000, signer = self._get_signer(name))

    def register(self):
        logging.debug(f'Registers for {Name.to_str(self.aa_prefix + "/AA")}')
        
        @self.app.route(self.aa_prefix + '/AA')
        def _on_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            # dispatch to corresponding handlers
            if Name.is_prefix(self.aa_prefix + '/AA/NEW', name):
                asyncio.create_task(self.on_new_interest(name, _app_param))
                return
            if Name.is_prefix(self.aa_prefix + '/AA/AUTHENTICATE', name):
                asyncio.create_task(self.on_authenticate_interest(name, _app_param))
                return
            