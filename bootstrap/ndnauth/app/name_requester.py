from typing import Tuple, Optional
import logging, sys

from Cryptodome.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.primitives.asymmetric import padding

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, Component, FormalName, VarBinaryStr, NonStrictName, BinaryStr, InterestParam, parse_tl_num
from ndn.app_support.security_v2 import KEY_COMPONENT, self_sign
from ndn.security import Sha256WithEcdsaSigner, Sha256WithRsaSigner
from ndn.utils import gen_nonce_64

from ..protocol import *
from ...crypto_tools import *
from ...types import Prover, ProtoError
from ..auth_state import *
from ..mode_encoder import *
        
class NameRequster(object):
    def __init__(self, app: NDNApp, validator: Validator):
        self.app = app
        self.data_validator = validator
        
    def _check_error(self, content):
        tlv_type, _  = parse_tl_num(content)
        if tlv_type is TLV_ERROR_CODE:
            err = ErrorMessage.parse(content)
            raise ProtoError(bytes(err.info).decode('utf-8'))        
        
    async def authenticate_base(self, nonce, controller_prefix: NonStrictName,
                                local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                mode: str, prover: Prover, **kwargs) -> Tuple[VarBinaryStr]:
        encoder_type = getattr(sys.modules[__name__], mode.capitalize() + 'ModeEncoder')
        encoder = object.__new__(encoder_type, nonce)
        encoder.__init__(nonce)

        # /<local-prefix>/NAA/BOOT/<nonce>/MSG
        bootstap_params_name = Name.from_str(local_prefix + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        @self.app.route(bootstap_params_name)
        def _on_boot_params_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            self.app.put_data(name, encoder.prepare_boot_params(**kwargs),
                              freshness_period = 10000, signer = kwargs['signer'])
        interest_name = Name.from_str(controller_prefix + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('NOTIFY')]
        connect_info = ConnectvityInfo()
        connect_info.local_prefix = Name.to_bytes(Name.from_str(local_prefix))
        if local_forwarder is not None:
            connect_info.local_forwarder = Name.to_bytes(Name.from_str(local_forwarder))
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = connect_info.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000,
            validator=self.data_validator)
        # /<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>
        # boot response may contain useful information for idproof
        self._check_error(content)
        boot_parse_ret = encoder.parse_boot_response(content)
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')

        # /<local-prefix>/NAA/PROOF/<nonce>/MSG
        idproof_params_name = Name.from_str(local_prefix + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        proof = prover(boot_parse_ret)
        @self.app.route(idproof_params_name)
        def _on_idproof_params_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            self.app.put_data(name, encoder.prepare_idproof_params(proof=proof),
                              freshness_period = 10000, signer = kwargs['signer'])
        # /<controller-prefix>/NAA/PROOF/<nonce>/NOTIFY/<ParametersSha256Digest>
        interest_name = Name.from_str(controller_prefix + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('NOTIFY')]
        data_name, _, content = await self.app.express_interest(
            interest_name, must_be_fresh=True, can_be_prefix=False, lifetime=6000,
            validator=self.data_validator)
        # /<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')
        self._check_error(content)
        encoder.parse_idproof_response(content)
        return encoder.auth_state.proof_of_possess
        
    async def authenticate_user(self, controller_prefix: NonStrictName,
                                local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                email: str, prover: Prover) -> Tuple[VarBinaryStr, Sha256WithEcdsaSigner]:
        # create a key pair first
        nonce = gen_nonce_64()
        pri_key = ECC.generate(curve=f'P-256')
        pub_key = bytes(pri_key.public_key().export_key(format='DER'))
        key_der = pri_key.export_key(format='DER', use_pkcs8=False)
        # create a dummy signer
        tmpkey_name = Name.from_str(local_prefix) + [KEY_COMPONENT, Component.from_number(nonce, Component.TYPE_GENERIC)]
        signer = Sha256WithEcdsaSigner(tmpkey_name, key_der)
        _, csr_buf = self_sign(tmpkey_name, pub_key, signer)
        pop_buf = await self.authenticate_base(nonce, controller_prefix, local_prefix, 
                                               local_forwarder, 'user', prover,
                                               email=email, csr=csr_buf, signer = signer)
        return pop_buf, signer

    async def authenticate_server(self, controller_prefix: NonStrictName,
                                  local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                  x509_chain: bytes, x509_prv_key: bytes) -> Tuple[VarBinaryStr, Sha256WithRsaSigner | Sha256WithEcdsaSigner]:
        # create a key pair first
        nonce = gen_nonce_64()
        prvkey = load_pem_private_key(x509_prv_key, password=None)
        prvkey_der = prvkey.private_bytes(
            encoding=Encoding.DER, format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        tmpkey_name = Name.from_str(local_prefix) + [KEY_COMPONENT, Component.from_number(nonce, Component.TYPE_GENERIC)]
        if isinstance(prvkey, rsa.RSAPrivateKey):
            signer = Sha256WithRsaSigner(tmpkey_name, prvkey_der)
        elif isinstance(prvkey, ec.EllipticCurvePrivateKey):
            signer = Sha256WithEcdsaSigner(tmpkey_name, prvkey_der)
        else:
            raise TypeError

        def prover(rand: bytes) -> bytes:
            chosen_hash = SHA256()
            hasher = Hash(chosen_hash)
            hasher.update(rand)
            digest = hasher.finalize()
            if isinstance(prvkey, rsa.RSAPrivateKey):
                return prvkey.sign(
                    digest,
                    padding.PSS(
                        mgf=padding.MGF1(SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    utils.Prehashed(chosen_hash)
                )
            elif isinstance(prvkey, ec.EllipticCurvePrivateKey):
                return prvkey.sign(
                    digest,
                    ec.ECDSA(utils.Prehashed(chosen_hash))
                )
            else:
                raise TypeError
        pop_buf = await self.authenticate_base(nonce, controller_prefix, local_prefix, 
                                               local_forwarder, 'server', prover,
                                               x509_chain=x509_chain, signer = signer)
        return pop_buf, signer