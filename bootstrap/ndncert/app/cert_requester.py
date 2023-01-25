from typing import Tuple
import logging

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, Component, FormalName, tlv_model
from ndn.app_support.light_versec import Checker

from ..protocol_v3 import *
from ..challenge_encoder import *
from ...types import *
from ...crypto_tools import *

class CertRequester(object):
    def __init__(self, app: NDNApp, checker: Checker, validator: Validator):
        self.app = app
        self.checker = checker
        self.data_validator = validator

    async def request_signing_with_possession(self, ca_prefix: NonStrictName, csr: bytes, signer,
                                              issued_cert: bytes, prover: Prover) -> Tuple[FormalName, FormalName]:
        # NEW
        new_request = NewRequest()
        ecdh = ECDH()
        new_request.ecdh_pub = ecdh.pub_key_encoded
        new_request.cert_request = csr
        self.iv_random_last = b''
        self.counter_last = 0
        
        ca_prefix = Name.normalize(ca_prefix)
        interest_name = ca_prefix + Name.from_str('/CA/NEW')
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = new_request.encode(), validator = self.data_validator,
            must_be_fresh=True, can_be_prefix=False, lifetime=6000, signer=signer)
        try:
            NewResponse.parse(content)
        except tlv_model.DecodeError:
            err = ErrorMessage.parse(content)
            err_info = bytes(err.info).decode("utf-8")
            raise ProtoError(f'Err code {err.code}: {err_info}')
        
        new_response = NewResponse.parse(content)
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')
        logging.debug(f'Request ID {new_response.request_id.hex()}')
        
        # diffie-hellman
        request_id = new_response.request_id
        salt = new_response.salt
        ecdh_pub = new_response.ecdh_pub
        ecdh.encrypt(bytes(ecdh_pub), bytes(salt), bytes(request_id))
        aes_key = ecdh.derived_key
        
        # select challenge
        if 'possession' not in new_response.challenges:
            raise Exception('Proof-of-Possession Challenge not available')
        
        # initialize an encoder
        encoder = ChallengeEncoder(request_id)
        encoder.cert_state.status = STATUS_BEFORE_CHALLENGE
        encoder.cert_state.selected_challenge = 'possession'
        encoder.cert_state.put_parameter('issued-cert', issued_cert)
        parameter_keys = get_parameter_keys('possession', encoder.cert_state.status, 'request')
        payload = encoder.prepare_challenge_request(parameter_keys)
        # encrypt the message
        message_out, self.iv_random, iv_counter =\
            gen_encrypted_message(bytes(aes_key), request_id, payload, None, None)
        # express the interest
        interest_name = ca_prefix + Name.from_str('/CA/CHALLENGE')
        interest_name = interest_name + [Component.from_bytes(request_id)] 
        
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = message_out.encode(), validator = self.data_validator,
            must_be_fresh=True, can_be_prefix=False, lifetime=6000, signer=signer)
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')

        # if this is an error message
        try:
            message_in = EncryptedMessage.parse(content)
        except tlv_model.DecodeError:
            err = ErrorMessage.parse(content)
            err_info = bytes(err.info).decode("utf-8")
            raise ProtoError(f'Err code {err.code}: {err_info}')
        # an normal challenge response
        random_part = message_in.iv[:8]
        counter_part = message_in.iv[-4:]
        counter = int.from_bytes(counter_part, 'big')
        if len(self.iv_random_last):
            if random_part != self.iv_random_last:
                raise ProtoError(f'Random part of AES IV not equal')
            else: 
                pass
        if self.counter_last > 0:
            if counter < self.counter_last:
                raise ProtoError(f'Counter part should be monotonically increasing')
            else:
                pass

        payload = get_encrypted_message(bytes(aes_key), request_id, message_in)
        encoder.parse_challenge_response(payload)
        proof = prover(encoder.cert_state.get_parameter('nonce'))
        encoder.cert_state.put_parameter('proof', proof)
        
        parameter_keys = get_parameter_keys('possession', encoder.cert_state.status, 'request')
        payload = encoder.prepare_challenge_request(parameter_keys)
        # encrypt the message
        message_out, _, iv_counter = gen_encrypted_message(bytes(aes_key), request_id, payload, bytes(self.iv_random), iv_counter)
        interest_name = ca_prefix + Name.from_str('/CA/CHALLENGE')
        interest_name = interest_name + [Component.from_bytes(request_id)]
        _, _, content = await self.app.express_interest(
            interest_name, app_param = message_out.encode(), validator = self.data_validator,
            must_be_fresh=True, can_be_prefix=False, lifetime=6000, signer=signer)
        
        # if this is an error message
        try:
            message_in = EncryptedMessage.parse(content)
        except tlv_model.DecodeError:
            err = ErrorMessage.parse(content)
            err_info = bytes(err.info).decode("utf-8")
            raise ProtoError(f'Err code {err.code}: {err_info}')
        payload = get_encrypted_message(bytes(aes_key), request_id, message_in)
        encoder.parse_challenge_response(payload)
        return Name.from_bytes(encoder.cert_state.issued_cert_name), Name.from_bytes(encoder.cert_state.forwarding_hint)