from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key
from ecdsa import SigningKey, VerifyingKey, NIST256p

import logging

class ECDH:
    def __init__(self):
        #default curve is secp256r1
        self.ecc_curve = NIST256p
        self.prv_key = SigningKey.generate(curve=self.ecc_curve)
        
        self.pub_key = self.prv_key.get_verifying_key()
        self.pub_key_encoded = self.pub_key.to_string(encoding = 'uncompressed')
        self.private_key = load_pem_private_key(self.prv_key.to_pem(), password = None,backend = default_backend())
        self.public_key = load_pem_public_key(self.pub_key.to_pem(), backend = default_backend())
        self.derived_key = None
        
        
    def encrypt(self, public_key, salt, info):
        client_pub = VerifyingKey.from_string(public_key,curve = self.ecc_curve)
        client_pub_encoded = client_pub.to_string(encoding = 'uncompressed')
        
        pk = load_pem_public_key(client_pub.to_pem(), backend = default_backend())
        shared_key = self.private_key.exchange(ec.ECDH(), pk)
        self.derived_key = HKDF(
            algorithm = hashes.SHA256(),
            length = 16,
            salt = salt,
            info = info,
            backend = default_backend()
        ).derive(shared_key)