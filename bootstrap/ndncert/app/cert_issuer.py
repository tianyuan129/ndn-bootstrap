from typing import Optional, Dict, Tuple

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
from ...crypto_tools import ECDH, EncryptedMessage, gen_encrypted_message, get_encrypted_message
from ..cert_state import CertState
from ..possession_verifier import PossessionVerifier
from ..challenge_encoder import ChallengeEncoder, get_parameter_keys

class CertIssuer(object):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3,
                 checker: Checker, validator: Validator):
        #todo: customize the storage type
        self.challenge_encoders = {}
        self.cert_cache = {}
        self.config = config
        self.anchor_name = self.config['identity_config']['anchor_name']
        self.ca_name = self.config['identity_config']['issuer_name']
        self.keychain = keychain
        self.app = app
        app.keychain = self.keychain
        self.checker = checker
        self.data_validator = validator
        
        self.verifiers = {}
        for verifier_method in self.config['verifier_config']:
            verifier_type_str = verifier_method.capitalize() + 'Verifier'
            verifier_type = getattr(sys.modules[__name__], verifier_type_str)
            verifier = object.__new__(verifier_type, self.app, self.config, self.data_validator)
            verifier.__init__(self.app, self.config, self.data_validator)
            self.verifiers[verifier_method] = verifier

        try:
            ca_id = self.keychain[self.ca_name]
            ca_cert = ca_id.default_key().default_cert().data
            self.ca_cert_data = parse_certificate(ca_cert)
        except:
            ca_id = self.keychain.touch_identity(self.ca_name)
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
        for verifier_type in self.config['verifier_config']:
            response.challenges.append(verifier_type)
        
        # Initialize a challenge encoder for this requester
        encoder = ChallengeEncoder(response.request_id)
        ecdh.encrypt(bytes(pub), response.salt, response.request_id)
        encoder.cert_state.aes_key = ecdh.derived_key
        encoder.cert_state.status = STATUS_BEFORE_CHALLENGE
        encoder.cert_state.id = response.request_id
        encoder.cert_state.csr = request.cert_request
        self.challenge_encoders[response.request_id] = encoder
        logging.info(f'Request ID: {response.request_id.hex()}')
        self.app.put_data(name, response.encode(), freshness_period = 10000,
                          signer = self._get_signer(name))
        
    async def on_challenge_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}, {param}')
        message_in = EncryptedMessage.parse(_app_param)
        request_id = name[len(Name.from_str(self.anchor_name)) + 2][-8:]
        if request_id not in self.challenge_encoders:
            logging.error(f'No CertState for Request ID: {request_id.hex()}')
            return
        else:
            encoder = self.challenge_encoders[request_id]
        payload = get_encrypted_message(bytes(encoder.cert_state.aes_key), bytes(encoder.cert_state.id), message_in)
        encoder.parse_challenge_request(payload)
        
        # if challenge not available
        selected_challenge_str = encoder.cert_state.selected_challenge
        if selected_challenge_str not in self.config['verifier_config']:
            logging.error(f'Challenge not available')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1]
            self.app.put_data(name, errs.encode(), freshness_period = 10000,
                              signer = self._get_signer(name))
            return

        encoder.cert_state, err = await self.verifiers[selected_challenge_str].process(encoder.cert_state)
        if err is not None:
            self.app.put_data(name, err.encode(), freshness_period = 10000, signer = self._get_signer(name))
        else:
            # issue the certificate
            if encoder.cert_state.status == STATUS_SUCCESS:
                mock_name = []
                csr_data = parse_certificate(encoder.cert_state.csr)
                mock_name[:] = csr_data.name[:]
                mock_name[-2] = Component.from_str('ndncert-python')
                issued_cert_name, issued_cert = derive_cert(csr_data.name[:-2], 'ndncert-python', 
                                                            csr_data.content, self._get_signer(mock_name),
                                                            datetime.utcnow(), int(self.config['validity_period']['cert']))
                encoder.cert_state.issued_cert_name = Name.encode(issued_cert_name)
                forwarding_hint = self.anchor_name + '/CA'
                encoder.cert_state.forwarding_hint = Name.encode(Name.from_str(forwarding_hint))
                issued_cert_data = parse_certificate(issued_cert)
                self.cert_cache[Name.to_bytes(issued_cert_data.name)] = issued_cert
                # serving the issued certificate for short time
                logging.info(f'Register a short-lived interest filter to allow retrieve '
                                f'{Name.to_str(issued_cert_data.name)}...')
                asyncio.ensure_future(self.serve_cert(issued_cert_data.name))     
  
            # prepare the challenge response
            parameter_keys = get_parameter_keys(selected_challenge_str, encoder.cert_state.status, 'response')
            payload = encoder.prepare_challenge_response(parameter_keys)
            message_out, encoder.cert_state.iv_random, encoder.cert_state.iv_counter =\
                gen_encrypted_message(bytes(encoder.cert_state.aes_key), bytes(encoder.cert_state.id), 
                payload, encoder.cert_state.iv_random, encoder.cert_state.iv_counter)
            # update and put challenge response
            self.challenge_encoders[request_id] = encoder
            self.app.put_data(name, message_out.encode(), freshness_period = 10000, signer = self._get_signer(name))

    def _on_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        # dispatch to corresponding handlers
        if Name.is_prefix(self.ca_name + '/CA/NEW', name):
            asyncio.create_task(self.on_new_interest(name, param, _app_param))
            return
        if Name.is_prefix(self.ca_name + '/CA/CHALLENGE', name):
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
            self.app.put_raw_packet(self.cert_cache[Name.to_bytes(int_name)])
        )
        await asyncio.sleep(5)
        self.app.unset_interest_filter(name)
        logging.info(f'Unregister the interest filter for {Name.to_str(name)}...')
        logging.debug(f'Clear the cache...')
        self.cert_cache.pop(Name.to_bytes(name))

    def route(self):
        logging.debug(f'Registers for {Name.to_str(self.anchor_name + "/CA")}')
        @self.app.route(self.anchor_name + '/CA')
        def _on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr] | None):
            logging.debug(f'{Name.to_str(name)}')
            # dispatch to corresponding handlers
            if Name.is_prefix(self.anchor_name + '/CA/NEW', name):
                asyncio.create_task(self.on_new_interest(name, param, _app_param))
                return
            elif Name.is_prefix(self.anchor_name + '/CA/CHALLENGE', name):
                asyncio.create_task(self.on_challenge_interest(name, param, _app_param))
                return
            elif Name.to_bytes(name) in self.cache:
                self.app.put_raw_packet(self.cache[Name.to_bytes(name)])
            else:
                pass