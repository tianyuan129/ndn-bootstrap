from typing import Tuple, Optional
import logging, sys
from Cryptodome.PublicKey import ECC

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, Component, FormalName, VarBinaryStr, tlv_model, NonStrictName, BinaryStr, InterestParam
from ndn.app_support.security_v2 import parse_certificate, KEY_COMPONENT, self_sign
from ndn.security import Sha256WithEcdsaSigner
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
        
    async def authenticate_base(self, nonce, controller_prefix: NonStrictName,
                                local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                mode: str, prover: Prover, **kwargs) -> Tuple[VarBinaryStr]:
        encoder_type = getattr(sys.modules[__name__], mode.capitalize() + 'ModeEncoder')
        encoder = object.__new__(encoder_type, nonce)
        encoder.__init__(nonce)
        # create a key pair first
        pri_key = ECC.generate(curve=f'P-256')
        pub_key = bytes(pri_key.public_key().export_key(format='DER'))
        key_der = pri_key.export_key(format='DER', use_pkcs8=False)
        # create a dummy signer
        tmpkey_name = Name.from_str('/a/b/c') + [KEY_COMPONENT, Component.from_number(nonce, Component.TYPE_GENERIC)]
        signer = Sha256WithEcdsaSigner(tmpkey_name, key_der)
        _, csr_buf = self_sign(tmpkey_name, pub_key, signer)

        # /<local-prefix>/NAA/BOOT/<nonce>/MSG
        bootstap_params_name = Name.from_str(local_prefix + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        @self.app.route(bootstap_params_name)
        def _on_boot_params_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            self.app.put_data(name, encoder.prepare_boot_params(**kwargs),
                              freshness_period = 10000, signer = signer)
        interest_name = Name.from_str(controller_prefix + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('NOTIFY')]
        connect_info = ConnectvityInfo()
        connect_info.local_prefix = Name.to_bytes(Name.from_str(local_prefix))
        if local_forwarder is not None:
            connect_info.local_forwarder = Name.to_bytes(Name.from_str(local_forwarder))
        data_name, _, content = await self.app.express_interest(
            interest_name, app_param = connect_info.encode(), must_be_fresh=True, 
            can_be_prefix=False, lifetime=6000)
        # /<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>
        # boot response may contain useful information for idproof
        boot_parse_ret = encoder.parse_boot_response(content)
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')

        # /<local-prefix>/NAA/PROOF/<nonce>/MSG
        idproof_params_name = Name.from_str(local_prefix + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        @self.app.route(idproof_params_name)
        def _on_idproof_params_interest(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            self.app.put_data(name, encoder.prepare_idproof_params(proof=prover(boot_parse_ret)),
                              freshness_period = 10000, signer = signer)
        # /<controller-prefix>/NAA/PROOF/<nonce>/NOTIFY/<ParametersSha256Digest>
        interest_name = Name.from_str(controller_prefix + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('NOTIFY')]
        data_name, _, content = await self.app.express_interest(
            interest_name, must_be_fresh=True, can_be_prefix=False, lifetime=6000)
        # /<controller-prefix>/NAA/BOOT/<nonce>/NOTIFY/<ParametersSha256Digest>
        logging.debug(f'Receiving Data {Name.to_str(data_name)}')
        encoder.parse_idproof_response(content)
        return encoder.auth_state.proof_of_possess
        
    async def authenticate_user(self, controller_prefix: NonStrictName,
                                local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                email: str, prover: Prover) -> Tuple[VarBinaryStr]:
        # create a key pair first
        nonce = gen_nonce_64()
        pri_key = ECC.generate(curve=f'P-256')
        pub_key = bytes(pri_key.public_key().export_key(format='DER'))
        key_der = pri_key.export_key(format='DER', use_pkcs8=False)
        # create a dummy signer
        tmpkey_name = Name.from_str(local_prefix) + [KEY_COMPONENT, Component.from_number(nonce, Component.TYPE_GENERIC)]
        signer = Sha256WithEcdsaSigner(tmpkey_name, key_der)
        _, csr_buf = self_sign(tmpkey_name, pub_key, signer)
        return await self.authenticate_base(nonce, controller_prefix, local_prefix, 
                                            local_forwarder, 'user', prover,
                                            email=email, csr=csr_buf)
