from typing import Tuple, Dict, Any
from datetime import datetime

import logging, os

from ndn.encoding import Name, Component, parse_data
from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ..proto.ndncert_proto import *
from ..utils.ndncert_crypto import *
from ..proto.ca_storage import *
from ..proto.types import GetSigner
from ..utils.sending_email import *

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

from .auth import Authenticator

class PossessionAuthenticator(Authenticator):
    def __init__(self, app: NDNApp, cache: Dict[bytes, Any],
                 config: Dict, db_dir: str, get_signer: GetSigner):
        self.cache = cache
        ca_name_str = config['prefix_config']['prefix_name'] + '/CA'
        self.ca_name = Name.from_str(ca_name_str)
        self.get_signer = get_signer
        self.config = config
        Authenticator.__init__(self, app, self.config, 'possession', db_dir)
    
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

    async def actions_before_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        cert_state.auth_mean = request.selected_challenge
        cert_state.iden_key = request.parameter_key
        cert_state.iden_value = request.parameter_value
        
        # parsing the issued credential
        credential_name, _, _, sig_ptrs = parse_data(cert_state.iden_value)
        credential = parse_certificate(cert_state.iden_value)
        credential_name = credential.name

        # obtain public key
        signing_cert = sig_ptrs.signature_info.key_locator.name
        logging.info(f'Verifying credential: {Name.to_str(credential_name)} '
                     f'<= {Name.to_str(signing_cert)} ...')
        valid = await self.app.data_validator(credential_name, sig_ptrs)
        if not valid:
            errs = ErrorMessage()
            errs.code = ERROR_NAME_NOT_ALLOWED[0]
            errs.info = ERROR_NAME_NOT_ALLOWED[1].encode()
            logging.info(f'Credential {Name.to_str(credential_name)} '
                         'is not allowed in trust model')
            return None, errs
        else:
            secret = os.urandom(16)
            response = ChallengeResponse()
            response.status = STATUS_CHALLENGE
            response.challenge_status = CHALLENGE_STATUS_NEED_PROOF.encode()
            response.remaining_tries = 1
            response.remaining_time = 300
            response.parameter_key = CHALLENGE_POSS_PARAMETER_KEY_NONCE.encode()
            response.parameter_value = secret
            # cert_name = parse_certificate(cert_state.csr).name

            # write back
            cert_state.auth_key = CHALLENGE_POSS_PARAMETER_KEY_NONCE.encode()
            cert_state.auth_value = secret
            cert_state.status = STATUS_CHALLENGE
            self.cache[cert_state.id] = cert_state
            return response, None

    async def actions_continue_challenge(self, request: ChallengeRequest, cert_state: CertState)\
        -> Tuple[ChallengeResponse, ErrorMessage]:
        if request.parameter_key == CHALLENGE_POSS_PARAMETER_KEY_PROOF.encode():
            # verify signaure
            credential = parse_certificate(cert_state.iden_value)
            pub_key = ECC.import_key(credential.content)
            nonce = cert_state.auth_value
            proof = request.parameter_value
            if self._verify_raw_ecdsa(pub_key, bytes(nonce), bytes(proof)):
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
                logging.info(f'Identity verification failed, returning errors '
                             f'{ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
                return None, errs
        else:
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            return None, errs
    
    # map the inputs to the function blocks
    actions = {
        STATUS_BEFORE_CHALLENGE : actions_before_challenge,
        STATUS_CHALLENGE : actions_continue_challenge
    }