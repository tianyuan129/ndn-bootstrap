from typing import Tuple
import logging

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, Component, FormalName, VarBinaryStr, tlv_model

from ..protocol import *
from ...crypto_tools import *
from ...types import Prover, ProtoError
from ..auth_state import *


class NameRequster(object):
    def __init__(self, app: NDNApp, validator: Validator):
        self.app = app
        self.data_validator = validator

    async def request_signing(self, aa_prefix: FormalName, pubkey: bytes, signer,
                              auth_type: str, auth_id: str, prover: Prover) -> Tuple[int, VarBinaryStr]:
        # NEW
        new_request = NewRequest()
        ecdh = ECDH()
        new_request.ecdh_pub = ecdh.pub_key_encoded
        new_request.pubkey = pubkey
        new_request.auth_type = auth_type.encode()
        new_request.auth_id = auth_id.encode()

        self.iv_random_last = b''
        self.counter_last = 0

        import base64
        print(base64.b64encode(new_request.pubkey))
        interest_name = aa_prefix + Name.from_str('/AA/NEW')
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = new_request.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000, signer=signer,
            validator=self.data_validator)
        try:
            new_response = NewResponse.parse(content)
        except tlv_model.DecodeError:
            err = ErrorMessage.parse(content)
            err_info = bytes(err.info).decode("utf-8")
            raise ProtoError(f'Err code {err.code}: {err_info}')
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')
        
        # diffie-hellman
        request_id = new_response.request_id
        salt = new_response.salt
        ecdh_pub = new_response.ecdh_pub
        ecdh.encrypt(bytes(ecdh_pub), bytes(salt), bytes(request_id))
        aes_key = ecdh.derived_key
        
        # authentication
        authenticate_request = AuthenticateRequest()
        authenticate_request.parameter_key = AUTHENTICATION_EMAIL_PARAMETER_KEY_CODE.encode()
        authenticate_request.parameter_value = prover(None)
        
        # encrypt the message
        message_out, self.iv_random, iv_counter =\
            gen_encrypted_message(bytes(aes_key), request_id, authenticate_request.encode(),
                                  None, None)

        # express the interest
        interest_name = aa_prefix + Name.from_str('/AA/AUTHENTICATE')
        interest_name = interest_name + [Component.from_bytes(request_id)] 
        
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = message_out.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000, signer=signer,
            validator=self.data_validator)
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')

        message_in = EncryptedMessage.parse(content)
        # checking iv counters
        payload = get_encrypted_message(aes_key, request_id, message_in)
        try:
            authenticate_response = AuthenticateResponse.parse(payload)
        except tlv_model.DecodeError:
            err = ErrorMessage.parse(content)
            err_info = bytes(err.info).decode("utf-8")
            raise ProtoError(f'Err code {err.code}: {err_info}')

        # if this is an error message
        try:
            message_in = EncryptedMessage.parse(content)
        except tlv_model.DecodeError:
            err = ErrorMessage.parse(content)
            err_info = bytes(err.info).decode("utf-8")
            raise ProtoError(f'Err code {err.code}: {err_info}')
        else:   
            return authenticate_response.status, authenticate_response.proof_of_possess