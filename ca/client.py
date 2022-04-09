from typing import Callable, Tuple, List

from ndn.app import NDNApp, InterestNack, InterestTimeout, InterestCanceled, ValidationFailure
from ndn.encoding import Name, Component, FormalName

from proto.ndncert_proto import *
from proto.types import *
from util.ndncert_crypto import *

class Client(object):
    def __init__(self, app: NDNApp):
        self.app = app
    
    async def _process_challenge_response(self, ca_prefix: FormalName, request_id: bytes,
                                          ecdh: ECDH, iv_counter: bytes, signer,
                                          message_in: EncryptedMessage, verifier: Verifier,
                                          selected) -> Tuple[FormalName, FormalName]:
        random_part = message_in.iv[:8]
        counter_part = message_in.iv[-4:]
        counter = int.from_bytes(counter_part, 'big')
        try:
            assert random_part == self.iv_random_last
        except AttributeError:
            self.iv_random_last = random_part
        except AssertionError:
            print(f'Random part of AES IV not equal')
      
        try:
            assert counter >= self.counter_last
        except AttributeError:
            self.counter_last = counter
        except AssertionError:
            print(f'Counter part should be monotonically increasing')  
        
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
            challenge_request.selected_challenge = selected
            
            # encrypt the message
            message_out, _, iv_counter = gen_encrypted_message(bytes(aes_key), request_id, challenge_request.encode(),
                bytes(self.iv_random), iv_counter)
            interest_name = ca_prefix + Name.from_str('/CA/CHALLENGE')
            interest_name = interest_name + [Component.from_bytes(request_id)]
            try:
                data_name, meta_info, content = await self.app.express_interest(
                    interest_name, app_param = message_out.encode(), must_be_fresh=True, 
                    can_be_prefix=False, lifetime=6000, signer=signer)
            except InterestNack as e:
                print(f'Nacked with reason={e.reason}')
            except InterestTimeout:
                print(f'Timeout')
            except InterestCanceled:
                print(f'Canceled')
            except ValidationFailure:
                print(f'Data failed to validate')

            print(f'Receiving Data {Name.to_str(data_name)}')
            return await self._process_challenge_response(ca_prefix, request_id, 
                                                          ecdh, iv_counter, signer, 
                                                          EncryptedMessage.parse(content), verifier,
                                                          selected)
            
        if challenge_response.status == STATUS_SUCCESS:
            return challenge_response.issued_cert_name, challenge_response.forwarding_hint

    async def request_signing(self, ca_prefix: FormalName, csr: bytes, signer, selector: Selector, verifier: Verifier) -> Tuple[FormalName, FormalName]:
        # NEW
        new_request = NewRequest()
        ecdh = ECDH()
        new_request.ecdh_pub = ecdh.pub_key_encoded
        new_request.cert_request = csr
        
        interest_name = ca_prefix + Name.from_str('/CA/NEW')
        try:
            data_name, _, content = await self.app.express_interest(
                interest_name, app_param = new_request.encode(), must_be_fresh=True, 
                can_be_prefix=False, lifetime=6000, signer=signer)
        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print(f'Timeout')
        except InterestCanceled:
            print(f'Canceled')
        except ValidationFailure:
            print(f'Data failed to validate')

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
        message_out, self.iv_random, iv_counter = gen_encrypted_message(bytes(aes_key), request_id, 
            challenge_request.encode(), None, None)

        # express the interest
        interest_name = ca_prefix + Name.from_str('/CA/CHALLENGE')
        interest_name = interest_name + [Component.from_bytes(request_id)] 
        
        try:
            data_name, _, content = await self.app.express_interest(
                interest_name, app_param = message_out.encode(), must_be_fresh=True, 
                can_be_prefix=False, lifetime=6000, signer=signer)
            print(f'Receiving Data {Name.to_str(data_name)}')
        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print(f'Timeout')
        except InterestCanceled:
            print(f'Canceled')
        except ValidationFailure:
            print(f'Data failed to validate')

        return await self._process_challenge_response(ca_prefix, request_id, 
                                                      ecdh, iv_counter, signer,
                                                      EncryptedMessage.parse(content), verifier,
                                                      selected)
        
    
            

        
    