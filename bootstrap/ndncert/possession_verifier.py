from typing import Tuple, Dict

import logging, os

from ndn.encoding import Name, parse_data
from ndn.app import NDNApp, Validator
from ndn.app_support.security_v2 import parse_certificate
from .protocol_v3 import *
from ..crypto_tools import *
from .cert_state import *
from .verifier import *

from Cryptodome.Hash import SHA256
from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric import padding

class PossessionVerifier(Verifier):
    def __init__(self, app: NDNApp, config: Dict, validator: Validator):
        ca_name_str = config['identity_config']['issuer_name'] + '/CA'
        self.app = app
        self.config = config
        self.ca_name = Name.from_str(ca_name_str)
        self.data_validator = validator
        
    @staticmethod
    def _verify_raw_signature(pub_key, nonce, proof) -> bool:
        if isinstance(pub_key, rsa.RSAPublicKey):
            try:
                pub_key.verify(
                    proof,
                    nonce,
                    padding.PKCS1v15(),
                    SHA256()
                )
                return True
            except exceptions.InvalidSignature:
                return False
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            try:
                chosen_hash = SHA256()
                hasher = Hash(chosen_hash)
                hasher.update(nonce)
                digest = hasher.finalize()
                pub_key.verify(
                    proof,
                    digest,
                    ec.ECDSA(utils.Prehashed(chosen_hash))
                )
                return True
            except exceptions.InvalidSignature:
                return False 
        
    async def actions_before_challenge(self, cert_state: CertState) -> Tuple[CertState, ErrorMessage]:        
        credential_buf = cert_state.get_parameter('issued-cert')
        credential_name, _, _, sig_ptrs = parse_data(credential_buf)

        # obtain public key
        signing_cert = sig_ptrs.signature_info.key_locator.name
        logging.info(f'Verifying credential: {Name.to_str(credential_name)} <= {Name.to_str(signing_cert)} ...')
        valid = await self.data_validator(credential_name, sig_ptrs)
        if not valid:
            errs = ErrorMessage()
            errs.code = ERROR_NAME_NOT_ALLOWED[0]
            errs.info = ERROR_NAME_NOT_ALLOWED[1]
            logging.info(f'Credential {Name.to_str(credential_name)} is not allowed in trust model')
            return cert_state, errs
        else:
            nonce = os.urandom(16)
            cert_state.status = STATUS_CHALLENGE
            cert_state.challenge_status = CHALLENGE_STATUS_NEED_PROOF
            cert_state.put_parameter(CHALLENGE_POSS_PARAMETER_KEY_NONCE, nonce)
            return cert_state, None

    async def actions_continue_challenge(self, cert_state: CertState) -> Tuple[CertState, ErrorMessage]:
        proof = cert_state.get_parameter('proof')
        nonce = cert_state.get_parameter('nonce')
        issued_cert_buf = cert_state.get_parameter('issued-cert')
        # verify signaure
        credential = parse_certificate(issued_cert_buf)
        pub_key = load_der_public_key(bytes(credential.content))
        if self._verify_raw_signature(pub_key, nonce, proof):
            logging.info(f'Identity verification succeed, should issue certificate')
            cert_state.status = STATUS_SUCCESS
            return cert_state, None
        else:
            cert_state.status = STATUS_FAILURE
            errs = ErrorMessage()
            errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
            errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1]
            logging.info(f'Identity verification failed, returning errors '
                            f'{ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
            return cert_state, errs

    async def process(self, cert_state: CertState) -> Tuple[CertState, ErrorMessage]:
        if cert_state.status == STATUS_BEFORE_CHALLENGE:
            return await self.actions_before_challenge(cert_state)
        elif cert_state.status == STATUS_CHALLENGE:
            return await self.actions_continue_challenge(cert_state)
        else:
            raise Exception('Unexpected certification status')