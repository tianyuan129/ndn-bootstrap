from abc import abstractmethod
import logging

from ndn.app_support.security_v2 import parse_certificate

from .protocol import *
from .auth_state import *
from ..crypto_tools import *

def find_encoder(tlv_type):
    _encoders = {
                    TLV_BOOT_PARAMS_RES_USER_TYPE: 'UserModeEncoder',
                    TLV_BOOT_PARAMS_RES_SERVER_TYPE: 'ServerModeEncoder'
                }
    return _encoders[tlv_type]

class ModeEncoder(object):
    @abstractmethod
    def boot_params_dec(self, data_name, content) -> AuthState:
        pass
    @abstractmethod
    def parse_boot_params(self, content) -> bytes | None:
        pass
    @abstractmethod
    def prepare_boot_params(self, **kwargs) -> bytes:
        pass
    @abstractmethod
    def parse_boot_response(self, content) -> bytes | None:
        pass
    abstractmethod
    def prepare_boot_response(self, **kwargs) -> bytes:
        pass
    @abstractmethod
    def prepare_idproof_params(self, **kwargs):
        pass
    @abstractmethod
    def prepare_idproof_response(self, **kwargs):
        pass
    @abstractmethod
    def parse_idproof_params(self, content) -> bytes | None:
        pass
    @abstractmethod
    def parse_idproof_response(self, content) -> bytes | None:
        pass

class UserModeEncoder(ModeEncoder):
    def __init__(self, nonce):
        self.ecdh = ECDH()
        self.auth_state = AuthStateUser()
        self.auth_state.nonce = nonce
        pass

    def parse_boot_params(self, content):
        boot_params = BootParamsResponseUser.parse(content)
        self.salt = urandom(32)
        from base64 import b64encode
        logging.debug(f'Received Diffie-Hellman Public Share: {b64encode(boot_params.inner.ecdh_pub)}')
        # generating new authentication state
        self.ecdh.encrypt(boot_params.inner.ecdh_pub, self.salt, self.auth_state.nonce.to_bytes(8, 'big'))
        logging.debug(f'Shared Secret: {b64encode(self.ecdh.derived_key)}')
        
        pubkey = parse_certificate(boot_params.inner.cert_request).content
        email_str = bytes(boot_params.inner.email).decode('utf-8')
        logging.debug(f'Received PublicKey: {b64encode(pubkey)}')
        logging.debug(f'Received Email: {email_str}')
        # this aims for longer term storage
        self.auth_state.derived_key = self.ecdh.derived_key
        self.auth_state.pub_key = pubkey
        self.auth_state.email = boot_params.inner.email

    def prepare_boot_params(self, **kwargs):
        boot_params_inner = BootParamsResponseUserInner()
        boot_params = BootParamsResponseUser()
        boot_params_inner.ecdh_pub = self.ecdh.pub_key_encoded
        boot_params_inner.email = kwargs['email'].encode()
        boot_params_inner.cert_request = kwargs['csr']
        boot_params.inner = boot_params_inner
        return boot_params.encode()
    
    def parse_boot_response(self, content):
        boot_response = BootResponseUser.parse(content)
        self.salt = boot_response.salt
        self.ecdh.encrypt(bytes(boot_response.ecdh_pub), bytes(self.salt),
                          self.auth_state.nonce.to_bytes(8, 'big'))
        from base64 import b64encode
        logging.debug(f'Shared Secret: {b64encode(self.ecdh.derived_key)}')

    def prepare_boot_response(self, **kwargs):
        boot_response = BootResponseUser()
        boot_response.ecdh_pub = self.ecdh.pub_key_encoded
        boot_response.salt = self.salt
        return boot_response.encode()
    
    def prepare_idproof_params(self, **kwargs):
        idproof_params = IdProofParamsUser()
        encrypted_message = \
            gen_encrypted_message2(bytes(self.ecdh.derived_key), 
                                   self.auth_state.nonce.to_bytes(8, 'big'),
                                   kwargs['proof'].encode())
        idproof_params.encrypted_code = encrypted_message
        return idproof_params.encode()

    def prepare_idproof_response(self, **kwargs):
        idproof_response = IdProofResponse()
        idproof_response.proof_of_possess = kwargs['proof_of_possess']
        return idproof_response.encode()
    
    def parse_idproof_params(self, content):
        idproof_params = IdProofParamsUser.parse(content)
        self.auth_state.ciphertext_code = idproof_params.encrypted_code
    
    def parse_idproof_response(self, content):
        idproof_response = IdProofResponse.parse(content)
        self.auth_state.proof_of_possess = idproof_response.proof_of_possess
    
class ServerModeEncoder(ModeEncoder):
    def __init__(self, nonce):
        self.auth_state = AuthStateServer()
        self.auth_state.nonce = nonce
        pass

    def parse_boot_params(self, content):
        boot_params = BootParamsResponseServer.parse(content)
        self.auth_state.x509_chain = boot_params.inner.x509_chain

    def prepare_boot_params(self, **kwargs):
        boot_params_inner = BootParamsResponseServerInner()
        boot_params = BootParamsResponseServer()
        boot_params_inner.x509_chain = kwargs['x509_chain']
        boot_params.inner = boot_params_inner
        return boot_params.encode()
    
    def parse_boot_response(self, content):
        boot_response = BootResponseServer.parse(content)
        self.auth_state.rand = boot_response.rand
        return self.auth_state.rand

    def prepare_boot_response(self, **kwargs):
        boot_response = BootResponseServer()
        boot_response.rand = self.auth_state.rand
        return boot_response.encode()
    
    def prepare_idproof_params(self, **kwargs):
        idproof_params = IdProofParamsServer()
        idproof_params.signed_rand = kwargs['proof']
        return idproof_params.encode()

    def prepare_idproof_response(self, **kwargs):
        idproof_response = IdProofResponse()
        idproof_response.proof_of_possess = kwargs['proof_of_possess']
        return idproof_response.encode()
    
    def parse_idproof_params(self, content):
        idproof_params = IdProofParamsServer.parse(content)
        self.auth_state.signed_rand = idproof_params.signed_rand
    
    def parse_idproof_response(self, content):
        idproof_response = IdProofResponse.parse(content)
        self.auth_state.proof_of_possess = idproof_response.proof_of_possess