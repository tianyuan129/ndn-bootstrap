from email import message
from typing import Optional, Dict, Callable, Any, Coroutine, List
from os import urandom

from ndn.app import NDNApp
from ndn.encoding import Name, Component, InterestParam, BinaryStr, FormalName
from ndn.app_support.security_v2 import parse_certificate, CertificateV2Value
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS, LvsModel
from ndn.utils import gen_nonce

from proto.ndncert_proto import *
from util.ndncert_crypto import *

from auth import *

from ca_storage import *

Selector = Callable[[List[bytes]], Tuple[bytes, bytes, bytes]]

Verifier = Callable[[bytes, bytes, bytes], Tuple[bytes, bytes]]

class Client(object):
    def __init__(self, app: NDNApp, trust_anchor: CertificateV2Value, trust_schema: LvsModel):
        #todo: customize the storage type
        self.trust_anchor = trust_anchor
        self.trust_schema = trust_schema
        self.app = app
    
    async def _process_challenge_response(self, ca_prefix: FormalName, request_id: bytes,
                                          ecdh: ECDH, iv_counter: bytes, signer,
                                          message_in: EncryptedMessage, verifier: Verifier) -> Tuple[FormalName, FormalName]:
        aes_key = ecdh.derived_key
        plaintext = get_encrypted_message(bytes(aes_key), request_id, message_in)
        challenge_response = ChallengeResponse.parse(plaintext)
        if challenge_response.status == STATUS_CHALLENGE:
            auth_key, auth_value = await verifier(challenge_response.challenge_status,
                                                  challenge_response.parameter_key,
                                                  challenge_response.parameter_value)
            challenge_request = ChallengeRequest()
            challenge_request.parameter_key = auth_key
            challenge_request.parameter_value = auth_value
            
            # encrypt the message
            message_out, iv_counter = gen_encrypted_message(bytes(aes_key), iv_counter, 
                request_id, challenge_request.encode())
            interest_name = ca_prefix + Name.from_str('/CA/CHALLENGE')
            interest_name = interest_name + [Component.from_bytes(request_id)]
            data_name, meta_info, content = await self.app.express_interest(
                interest_name, app_param = message_out.encode(), must_be_fresh=True, 
                can_be_prefix=False, lifetime=6000, signer=signer)

            return await self._process_challenge_response(ca_prefix, request_id, 
                                                          ecdh, iv_counter, signer, 
                                                          EncryptedMessage.parse(content), verifier)
            
        if challenge_response.status == STATUS_PENDING:
            return challenge_response.issued_cert_name, challenge_response.forwarding_hint
        

    async def request_signing(self, ca_prefix: FormalName, csr: bytes, signer, selector: Selector, verifier: Verifier) -> Tuple[FormalName, FormalName]:
        # NEW
        new_request = NewRequest()
        ecdh = ECDH()
        new_request.ecdh_pub = ecdh.pub_key_encoded
        new_request.cert_request = csr
        
        interest_name = ca_prefix + Name.from_str('/CA/NEW')
        data_name, meta_info, content = await self.app.express_interest(
            interest_name, app_param = new_request.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000, signer=signer)
        
        new_response = NewResponse.parse(content)
        print(f'Receiving Data {Name.to_str(data_name)}')
        
        # diffie-hellman
        request_id = new_response.request_id
        salt = new_response.salt
        ecdh_pub = new_response.ecdh_pub
        ecdh.encrypt(bytes(ecdh_pub), bytes(salt), bytes(request_id))
        aes_key = ecdh.derived_key
        
        # select challenge
        challenges = [challenge for challenge in new_response.challenges]
        selected, param_key, param_value = await selector(challenges)
        
        # CHALLENGE
        challenge_request = ChallengeRequest()
        challenge_request.selected_challenge = selected
        challenge_request.parameter_key = param_key
        challenge_request.parameter_value = param_value
        
        # encrypt the message
        iv_counter = 0
        message_out, iv_counter = gen_encrypted_message(bytes(aes_key), iv_counter, 
            request_id, challenge_request.encode())

        # express the interest
        interest_name = ca_prefix + Name.from_str('/CA/CHALLENGE')
        interest_name = interest_name + [Component.from_bytes(request_id)] 
        
        data_name, meta_info, content = await self.app.express_interest(
            interest_name, app_param = message_out.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000, signer=signer)
        print(f'{Name.to_str(data_name)}')

        return await self._process_challenge_response(ca_prefix, request_id, 
                                                      ecdh, iv_counter, signer, 
                                                      EncryptedMessage.parse(content), verifier)
        
    
            

        
    