from typing import Optional, Dict

import logging, sys
from os import urandom
import asyncio
from datetime import datetime

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, Component
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import Checker
from ndn.security import KeychainSqlite3

from ..protocol_v3 import *
from ..possession_verifier import PossessionVerifier
from ...crypto_tools import ECDH, EncryptedMessage, gen_encrypted_message, get_encrypted_message
from ..cert_state import CertState
from ...keychain_register import attach_keychain_register_appv1

class CertIssuer(object):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3,
                 checker: Checker, validator: Validator):
        #todo: customize the storage type
        self.requests = {}
        self.cache = {}
        self.config = config
        self.ca_prefix = self.config['prefix_config']['prefix_name']
        self.keychain = keychain
        self.app = app
        app.keychain = self.keychain
        self.checker = checker
        self.data_validator = validator
        attach_keychain_register_appv1(self.keychain, self.app)
        
        self.verifiers = {}
        for auth_mean in self.config['auth_config']:
            verifier_type_str = auth_mean.capitalize() + 'Verifier'
            verifier_type = getattr(sys.modules[__name__], verifier_type_str)
            verifier = object.__new__(verifier_type, self.app, self.config, self.data_validator)
            verifier.__init__(self.app, self.config, self.data_validator)
            self.verifiers[auth_mean] = verifier

        try:
            ca_id = self.keychain[self.ca_prefix]
            ca_cert = ca_id.default_key().default_cert().data
            self.ca_cert_data = parse_certificate(ca_cert)
        except:
            ca_id = self.keychain.touch_identity(self.ca_prefix)
            ca_cert = ca_id.default_key().default_cert().data
            self.ca_cert_data = parse_certificate(ca_cert)

    def _get_signer(self, name):
        suggested_keylocator = self.checker.suggest(name, self.keychain)
        if suggested_keylocator is None:
            logging.error(f'No proper keylocator for {Name.to_str(name)}')
            return None
        else:
            return self.keychain.tpm.get_signer(suggested_keylocator[:-2], suggested_keylocator)

    async def on_new_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}, {param}')
        request = NewRequest.parse(_app_param)
        ecdh = ECDH()
        pub = request.ecdh_pub
        csr_data = parse_certificate(request.cert_request)
        logging.info(f'CSR name: {Name.to_str(csr_data.name)}')
        
        response = NewResponse()
        response.ecdh_pub = ecdh.pub_key_encoded
        response.salt = urandom(32)
        response.request_id = urandom(8)
        for auth_method in self.config['auth_config']:
            response.challenges.append(str(auth_method).encode())

        self.app.put_data(name, response.encode(), freshness_period = 10000,
                          signer = self._get_signer(name))

        cert_state = CertState()
        ecdh.encrypt(bytes(pub), response.salt, response.request_id)
        cert_state.aes_key = ecdh.derived_key
        cert_state.status = STATUS_BEFORE_CHALLENGE
        cert_state.id = response.request_id
        cert_state.csr = request.cert_request
        self.requests[response.request_id] = cert_state
        logging.info(f'Request ID: {response.request_id.hex()}')
        
    async def on_challenge_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}, {param}')
        message_in = EncryptedMessage.parse(_app_param)
        request_id = name[len(Name.from_str(self.ca_prefix)) + 2][-8:]

        try:
            cert_state = self.requests[request_id]
        except KeyError:
            logging.error(f'No CertState for Request ID: {request_id.hex()}')
            return

        payload = get_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), message_in)
        request = ChallengeRequest.parse(payload)
        if cert_state.auth_mean is None:
            cert_state.auth_mean = request.selected_challenge
        challenge_type = bytes(cert_state.auth_mean).decode('utf-8')
        
        # if challenge not available
        if not challenge_type in self.config['auth_config']:
            logging.error(f'Challenge not available')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            self.app.put_data(name, errs.encode(), freshness_period = 10000,
                              signer = self._get_signer(name))
            return
        
        
        params_in = {}
        params_in[bytes(request.parameter_key).decode('utf-8')] = request.parameter_value
        status = cert_state.status
        if status == STATUS_BEFORE_CHALLENGE:
            cert_state, params_out, err = await self.verifiers[challenge_type].actions_before_challenge(cert_state, params_in)
        elif status == STATUS_CHALLENGE:
            cert_state, params_out, err = await self.verifiers[challenge_type].actions_continue_challenge(cert_state, params_in)
        else:
            pass
        if err is not None:
            self.app.put_data(name, err.encode(), freshness_period = 10000, signer = self._get_signer(name))
            return
        response = ChallengeResponse()
        response.status = cert_state.status
        if params_out is not None:
            for param_key in params_out:
                response.parameter_key = param_key.encode()
                response.parameter_value = params_out[param_key]
            
        if response.status == STATUS_SUCCESS:
            # signer suggester must take a full name as input, so let's mock one
            mock_name = []
            csr_data = parse_certificate(cert_state.csr)
            mock_name[:] = csr_data.name[:]
            mock_name[-2] = Component.from_str('ndncert-python')
            issued_cert_name, issued_cert = derive_cert(csr_data.name[:-2], 'ndncert-python', 
                                                        csr_data.content, self._get_signer(mock_name),
                                                        datetime.utcnow(), 10000)
            cert_state.issued_cert = issued_cert
            response.issued_cert_name = Name.encode(issued_cert_name)
            fw_hint = self.ca_prefix + '/CA'
            response.forwarding_hint = Name.encode(Name.from_str(fw_hint))
            issued_cert = parse_certificate(cert_state.issued_cert)
            self.cache[Name.to_bytes(issued_cert.name)] = cert_state.issued_cert
            # create an window for cert retrieval
            logging.debug(f'Register a short-lived interest filter to allow retrieve '
                            f'{Name.to_str(issued_cert.name)}...')
            asyncio.ensure_future(self.serve_cert(issued_cert.name))
        response.status = cert_state.status
        if cert_state.auth_status is not None:
            response.challenge_status = cert_state.auth_status
        plaintext = response.encode()
        try:
            message_out, cert_state.iv_random, cert_state.iv_counter =\
                gen_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), 
                plaintext, cert_state.iv_random, cert_state.iv_counter)
        except:
            message_out, cert_state.iv_random, cert_state.iv_counter =\
                gen_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), 
                plaintext, None, None)
                
        self.app.put_data(name, message_out.encode(), freshness_period = 10000,
                            signer = self._get_signer(name))
        self.requests[request_id] = cert_state

    def _on_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        # dispatch to corresponding handlers
        if Name.is_prefix(self.ca_prefix + '/CA/NEW', name):
            asyncio.create_task(self.on_new_interest(name, param, _app_param))
            return
        if Name.is_prefix(self.ca_prefix + '/CA/CHALLENGE', name):
            asyncio.create_task(self.on_challenge_interest(name, param, _app_param))
            return
        
        # check whether can respond from cert cache
        try:
            self.cache[Name.to_bytes(name)]
        except KeyError:
            return
        self.app.put_raw_packet(self.cache[Name.to_bytes(name)])

    async def serve_cert(self, name: FormalName):
        self.app.set_interest_filter(name, lambda int_name, param, _app_param:
            self.app.put_raw_packet(self.cache[Name.to_bytes(int_name)])
        )
        await asyncio.sleep(5)
        self.app.unset_interest_filter(name)
        logging.info(f'Unregister the interest filter for {Name.to_str(name)}...')
        logging.debug(f'Clear the cache...')
        self.cache.pop(Name.to_bytes(name))

    def register(self):
        logging.debug(f'Registers for {Name.to_str(self.ca_prefix + "/CA")}')
        
        @self.app.route(self.ca_prefix + '/CA')
        def _on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr] | None):
            logging.debug(f'{Name.to_str(name)}')
            # dispatch to corresponding handlers
            if Name.is_prefix(self.ca_prefix + '/CA/NEW', name):
                asyncio.create_task(self.on_new_interest(name, param, _app_param))
                return
            elif Name.is_prefix(self.ca_prefix + '/CA/CHALLENGE', name):
                asyncio.create_task(self.on_challenge_interest(name, param, _app_param))
                return
            else:
                # check whether can respond from cert cache
                logging.debug(f'{Name.to_str(name)}')
                try:
                    self.cache[Name.to_bytes(name)]
                except KeyError:
                    return
                self.app.put_raw_packet(self.cache[Name.to_bytes(name)])