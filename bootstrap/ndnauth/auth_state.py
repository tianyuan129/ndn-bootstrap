from .protocol import *

class AuthState(TlvModel):
    id = BytesField(1)
    status = UintField(2)

    aes_key = BytesField(3)
    iv_counter = UintField(4)

    pubkey = BytesField(5)

    auth_type = BytesField(6)
    auth_id = BytesField(7)
    auth_cache = BytesField(8)

    auth_key = BytesField(9)
    auth_value = BytesField(10)
    
    proof_of_possess = BytesField(11)