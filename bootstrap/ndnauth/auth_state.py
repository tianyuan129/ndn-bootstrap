from .protocol import *
    
class AuthState(TlvModel):
    nonce = BytesField(1) # this should be the primary key
    proof_of_possess = BytesField(11)
    is_member = UintField(12)
    is_authenticated = UintField(13)

class AuthStateUser(AuthState):
    pub_key = BytesField(3)
    derived_key = BytesField(4)
    email = BytesField(5)
    plaintext_code = BytesField(6)
    ciphertext_code = EncryptedMessage()

class AuthStateServer(AuthState):
    common_name = BytesField(8)
    x509_chain = BytesField(9)
    rand = BytesField(10)
    signed_rand = BytesField(11)