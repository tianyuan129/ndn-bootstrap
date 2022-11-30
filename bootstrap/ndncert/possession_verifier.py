from typing import Tuple, Dict
from datetime import datetime

import logging, os

from ndn.encoding import Name, Component, parse_data
from ndn.appv2 import NDNApp
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from .protocol_v3 import *
from ..crypto_tools import *
from ..types import GetSigner
from .cert_state import *
from .verifier import *

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

class PossessionVerifier(Verifier):
    def __init__(self, app: NDNApp, config: Dict, validator: Validator):
        ca_name_str = config['prefix_config']['prefix_name'] + '/CA'
        self.app = app
        self.config = config
        self.ca_name = Name.from_str(ca_name_str)
        self.data_validator = validator
        self._param_cache = {}
    
    @staticmethod
    def _verify_raw_ecdsa(pubkey, nonce, proof) -> bool:
        verifier = DSS.new(pubkey, 'fips-186-3', 'der')
        h = SHA256.new()
        h.update(nonce)
        try:
            verifier.verify(h, proof)
            return True
        except ValueError:
            return False

    async def actions_before_challenge(self, cert_state: CertState, params_in: Dict) -> Tuple[CertState, Dict, ErrorMessage]:        
        # parsing the issued credential
        if CHALLENGE_POSS_PARAMETER_KEY_ISSUEDCERT in params_in:
            cert_state.auth_key = CHALLENGE_POSS_PARAMETER_KEY_ISSUEDCERT
            cert_state.auth_value = params_in[CHALLENGE_POSS_PARAMETER_KEY_ISSUEDCERT]
        credential_name, _, _, sig_ptrs = parse_data(cert_state.auth_value)
        credential = parse_certificate(cert_state.auth_value)
        credential_name = credential.name

        # obtain public key
        signing_cert = sig_ptrs.signature_info.key_locator.name
        logging.info(f'Verifying credential: {Name.to_str(credential_name)} <= {Name.to_str(signing_cert)} ...')
        valid = await self.data_validator(credential_name, sig_ptrs)
        if not valid:
            errs = ErrorMessage()
            errs.code = ERROR_NAME_NOT_ALLOWED[0]
            errs.info = ERROR_NAME_NOT_ALLOWED[1].encode()
            logging.info(f'Credential {Name.to_str(credential_name)} is not allowed in trust model')
            return cert_state, None, errs
        else:
            secret = os.urandom(16)
            cert_state.status = STATUS_CHALLENGE
            cert_state.auth_status = CHALLENGE_STATUS_NEED_PROOF
            param_secret = Parameter()
            param_secret.key = CHALLENGE_POSS_PARAMETER_KEY_NONCE.encode()
            param_secret.value = secret
            cert_state.parameters.append(param_secret)
            self._param_cache[CHALLENGE_POSS_PARAMETER_KEY_NONCE] = secret
            return cert_state, {CHALLENGE_POSS_PARAMETER_KEY_NONCE: secret}, None

    async def actions_continue_challenge(self, cert_state: CertState, params_in: Dict) -> Tuple[CertState, Dict, ErrorMessage]:
        if CHALLENGE_POSS_PARAMETER_KEY_PROOF in params_in:
            param_proof = Parameter()
            param_proof.key = CHALLENGE_POSS_PARAMETER_KEY_PROOF.encode()
            param_proof.value = params_in[CHALLENGE_POSS_PARAMETER_KEY_PROOF]
            cert_state.parameters.append(param_proof)
            # verify signaure
            credential = parse_certificate(cert_state.auth_value)
            pub_key = ECC.import_key(credential.content)
            
            secret = self._param_cache[CHALLENGE_POSS_PARAMETER_KEY_NONCE]
            if self._verify_raw_ecdsa(pub_key, secret, bytes(param_proof.value)):
                logging.info(f'Identity verification succeed, should issue certificate')
                cert_state.status = STATUS_SUCCESS
                return cert_state, None, None
            else:
                errs = ErrorMessage()
                errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
                errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1].encode()
                logging.info(f'Identity verification failed, returning errors '
                             f'{ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
                return cert_state, None, errs
        else:
            cert_state.status = STATUS_FAILURE
            return cert_state, None, errs
