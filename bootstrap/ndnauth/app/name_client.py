from typing import Tuple, Optional
import logging
from Cryptodome.PublicKey import ECC

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, Component, FormalName, VarBinaryStr, tlv_model, NonStrictName, BinaryStr, InterestParam
from ndn.app_support.security_v2 import parse_certificate, KEY_COMPONENT, self_sign
from ndn.security import Sha256WithEcdsaSigner
from ndn.utils import gen_nonce_64

from ..protocol import *
from ...crypto_tools import *
from ...types import Prover, ProtoError
from ..auth_state import *
from ..mode_encoder import UserModeEncoder


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
        
        
        
class NameRequster2(object):
    def __init__(self, app: NDNApp, validator: Validator):
        self.app = app
        self.data_validator = validator

    # def _boot_params_enc(self, ecdh, email, csr):
    #     boot_params_inner = BootParamsResponseUserInner()
    #     boot_params = BootParamsResponseUser()
    #     boot_params_inner.ecdh_pub = ecdh.pub_key_encoded
    #     boot_params_inner.email = email.encode()
    #     boot_params_inner.cert_request = csr
    #     boot_params.inner = boot_params_inner
    #     return boot_params.encode()

    # def _boot_response_dec(self, data_name, content, ecdh, nonce):
    #     boot_response = BootResponseUser.parse(content)
    #     ecdh.encrypt(bytes(boot_response.ecdh_pub), bytes(boot_response.salt), nonce.to_bytes(8, 'big'))
    #     from base64 import b64encode
    #     logging.debug(f'Shared Secret: {b64encode(ecdh.derived_key)}')
 
    # def _idproof_params_enc(self, ecdh, nonce):
    #     idproof_params = IdProofParamsUser()
    #     encrypted_message = gen_encrypted_message2(bytes(ecdh.derived_key), nonce.to_bytes(8, 'big'), '1234'.encode())
    #     idproof_params.encrypted_code = encrypted_message
    #     return idproof_params.encode()

    # def _idproof_response_dec(self, content):
    #     idproof_response = IdProofResponse.parse(content)
    #     return idproof_response.proof_of_possess
        
    async def authenticate(self, controller_prefix: NonStrictName,
                           local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                           email: str, prover: Prover) -> Tuple[VarBinaryStr]:

        nonce = gen_nonce_64()
        encoder = UserModeEncoder(nonce)

        # create a key pair first
        pri_key = ECC.generate(curve=f'P-256')
        pub_key = bytes(pri_key.public_key().export_key(format='DER'))
        key_der = pri_key.export_key(format='DER', use_pkcs8=False)
        # create a dummy signer
        tmpkey_name = Name.from_str('/a/b/c') + [KEY_COMPONENT, Component.from_number(nonce, Component.TYPE_GENERIC)]
        signer = Sha256WithEcdsaSigner(tmpkey_name, key_der)
        _, csr_buf = self_sign(tmpkey_name, pub_key, signer)

        # /<local-prefix>/NAA/BOOT/<nonce>/MSG
        bootstap_params_name = Name.from_str(local_prefix + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        @self.app.route(bootstap_params_name)
        def _on_boot_params_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            self.app.put_data(name, encoder.prepare_boot_params(email=email, csr=csr_buf),
                              freshness_period = 10000, signer = signer)

        # /<local-prefix>/NAA/PROOF/<nonce>/MSG
        idproof_params_name = Name.from_str(local_prefix + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        @self.app.route(idproof_params_name)
        def _on_idproof_params_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            self.app.put_data(name, encoder.prepare_idproof_params(code='1234'),
                              freshness_period = 10000, signer = signer)

        interest_name = Name.from_str(controller_prefix + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('NOTIFY')]
        connect_info = ConnectvityInfo()
        connect_info.local_prefix = Name.to_bytes(Name.from_str(local_prefix))
        if local_forwarder is not None:
            connect_info.local_forwarder = Name.to_bytes(Name.from_str(local_forwarder))
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = connect_info.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000)

        # /<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>        
        encoder.parse_boot_response(content)
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')
        
        # /<controller-prefix>/NAA/PROOF/<nonce>/NOTIFY/<ParametersSha256Digest>
        interest_name = Name.from_str(controller_prefix + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('NOTIFY')]
        data_name, _, content = await self.app.express_interest(
            interest_name, must_be_fresh=True, can_be_prefix=False, lifetime=6000)
        # /<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')
        encoder.parse_idproof_response(content)
        return encoder.auth_state.proof_of_possess