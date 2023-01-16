from typing import Tuple, Dict

import logging, os
from random import randint
from cryptography import x509, exceptions
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric import padding

from ..protocol import *
from ..auth_state import AuthStateServer
from ...crypto_tools import *
from .authenticate import  Authenticator
from ...crypto_tools import *

class ServerAuthenticator(Authenticator):
    def __init__(self, config: Dict):
        self.config = config

    async def after_receive_boot_params(self, auth_state: AuthStateServer) -> Tuple[AuthStateServer, ErrorMessage]:
        loaded_chain = x509.load_pem_x509_certificates(bytes(auth_state.x509_chain))
        auth_state.pub_key = loaded_chain[0].public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        auth_state.rand = urandom(8)
        return auth_state, None

    async def after_receive_idproof_params(self, auth_state: AuthStateServer) -> Tuple[AuthStateServer, ErrorMessage]:
        # cert = x509.load_pem_x509_certificates(bytes(auth_state.x509_chain))
        # pubkey = cert[0].public_key()
        pub_key = load_pem_public_key(bytes(auth_state.pub_key))
        errs = None
        if isinstance(pub_key, rsa.RSAPublicKey):
            try:
                pub_key.verify(
                    bytes(auth_state.signed_rand),
                    bytes(auth_state.rand),
                    padding.PSS(
                        mgf=padding.MGF1(SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    SHA256()
                )
                logging.info(f'Identity verification succeed, should issue proof-of-possession')
                auth_state.is_authenticated = True
            except exceptions.InvalidSignature:
                logging.info('bad signature rsa')
                auth_state.is_authenticated = False
                errs = ErrorMessage()
                errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
                errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1].encode()
                logging.error('Identity verification failed, returning errors {ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            try:
                chosen_hash = SHA256()
                hasher = Hash(chosen_hash)
                hasher.update(bytes(auth_state.rand))
                digest = hasher.finalize()
                pub_key.verify(
                    bytes(auth_state.signed_rand),
                    digest,
                    ec.ECDSA(utils.Prehashed(chosen_hash))
                )
                logging.info(f'Identity verification succeed, should issue proof-of-possession')
                auth_state.is_authenticated = True
            except exceptions.InvalidSignature:
                logging.info('bad signature ecdsa')
                auth_state.is_authenticated = False
                errs = ErrorMessage()
                errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
                errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1].encode()
                logging.error('Identity verification failed, returning errors {ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
        else:
            raise TypeError
        return auth_state, errs