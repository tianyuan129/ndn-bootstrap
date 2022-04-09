# Trust Infomation Base (TIB), I invented a new word because I don't want mess up with the current PIB.
# TIB = {PIB, Keychain, Trust Anchor, Trust Schema}
# Therefore, one entity only have one Tib per trust zone
# Implementation wise, TIB = {Keychain, Validator}
# Functions that TIB should provide:
#     1. Given trust anchor and initial trust schema, bootstrap to a specific trust zone
#       1.1. given a name, generate a key and try to get authentication (in the form of tmp cert)
#       1.2. using the tmp cert as proof-of-possesion challenge to apply a cert from NDNCERT CA
#     2. Signing the data/interest
#       2.1. using trust schema to locate a proper signing key
#       2.2. signing the data/interest packet
#     3. Verifying the data/interest
#       3.1. using trust schema to validate the received data/interest packet
#     4. (Extra) Starting a new trust zone
#       4.1. configuring necessary pieces to become a trust zone controller

from typing import Optional, Tuple
import os
from ndn.encoding import Name, FormalName, TlvModel, BytesField, ModelField
from ndn.app_support.security_v2 import parse_certificate, sign_req
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS, LvsModel, lvs_validator
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app import NDNApp

from ca import Ca, Client, Selector, Verifier
from util.config import get_yaml
from proto.types import *
from .lvs_template import define_minimal_trust_zone

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS, pkcs1_15

TLV_TIB_BUNDLE_ANCHOR = 301
TLV_TIB_BUNDLE_SCHEMA = 303

class TibBundle(TlvModel):
    anchor = BytesField(TLV_TIB_BUNDLE_ANCHOR)
    schema = ModelField(TLV_TIB_BUNDLE_SCHEMA, LvsModel)

class Tib(object):
    # this will load the app with data_validator
    def __init__(self, app: NDNApp, bundle: TibBundle, path: Optional[str]):
        self.anchor = bundle.anchor
        self.anchor_data = parse_certificate(self.anchor)
        self.schema = bundle.schema
        self.checker = Checker(bundle.schema, DEFAULT_USER_FNS)

        # initialize pib and tpm
        self._backend_init(path)

        # pass keychain to apps      
        self.app = app
        app.keychain = self.keychain
        validator = lvs_validator(self.checker, self.app, self.anchor)
        app.data_validator = validator
    
    def _backend_init(self, path: str):
        if path is None:
            anchor_name = self.anchor_data.name
            # /<prefix>/KEY/<keyid>/<issuer>/<version>
            anchor_prefix = anchor_name[:-4]
            dir_str = '~/.ndn/tib/' + Name.to_bytes(anchor_prefix).hex()
            self.basedir = os.path.expanduser(dir_str)
        else:
            self.basedir = os.path.expanduser(path)
        
        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir)
        tpm_path = os.path.join(self.basedir, 'privKeys')
        pib_path = os.path.join(self.basedir, 'pib.db')
        self.keychain = KeychainSqlite3(pib_path, TpmFile(tpm_path))

    async def bootstrap(self, id_name: FormalName, selector: Selector, verifier: Verifier):
        client = Client(self.app)
        
        anchor_name = self.anchor_data.name
        # /<prefix>/KEY/<keyid>/<issuer>/<version>
        auth_prefix = anchor_name[:-4]
        
        if not Name.is_prefix(auth_prefix, id_name):
            raise InvalidName

        # the name used for authentication
        id_authname = []
        id_authname[:] = id_name[:]
        id_authname.insert(len(auth_prefix), 'auth')
        
        authid = self.keychain.touch_identity(id_authname)
        authid_key = authid.default_key()
        authid_cert_data = parse_certificate(authid_key.default_cert().data)
        authid_signer = self.keychain.get_signer({'cert': authid_cert_data.name})
        _, csr = sign_req(authid_key.name, authid_cert_data.content, authid_signer)
        issued_cert_name, forwarding_hint = await client.request_signing(auth_prefix, bytes(csr), 
            authid_signer, selector, verifier)
        
        print(f'{Name.to_str(issued_cert_name)}')
        data_name, _, _, raw_pkt = await self.app.express_interest(
            issued_cert_name, forwarding_hint=[forwarding_hint], 
            can_be_prefix=False, lifetime=6000, need_raw_packet=True
        )
        try:
            retrieved_cert = parse_certificate(raw_pkt)
            print(f'Installing tmp certificate: {Name.to_str(retrieved_cert.name)}')
        except:
            print(f'Not a certificate: {Name.to_str(data_name)}')
            return
        # installing the tmp cert 
        self.keychain.import_cert(authid_key.name, issued_cert_name, raw_pkt)
        
        # todo: applying acutal cert from the real ndncert
        # always select proof-of-possession challenge from NDNCERT
        async def _select_possession(list: List[bytes]) -> Tuple[bytes, bytes, bytes]:    
            for challenge in list:
                if challenge == 'possession':
                    return challenge, 'issued-cert'.encode(), authid_key.default_cert().data
            raise ProtoError
        
        # use the authid_signer to sign the nonce
        async def _verify_possession(challenge_status: bytes, param_key: bytes, param_value: bytes) -> Tuple[bytes, bytes]:
            try:
                assert bytes(challenge_status).decode() == 'need-proof'
                assert bytes(param_key).decode() == 'nonce'
                assert param_value is not None
            except AssertionError:
                raise ProtoError
            
            wire = bytearray(70)
            assert authid_signer.write_signature_value(wire, [memoryview(param_value)]) == len(wire)        
            return 'proof'.encode(), bytes(wire)   
        
        formal_id = self.keychain.touch_identity(id_name)
        formal_key = formal_id.default_key()
        formal_cert_data = parse_certificate(formal_key.default_cert().data)
        formal_signer = self.keychain.get_signer({'cert': formal_cert_data.name})
        _, csr = sign_req(formal_key.name, formal_cert_data.content, formal_signer)
        issued_cert_name, forwarding_hint = await client.request_signing(auth_prefix, bytes(csr), 
            formal_signer, _select_possession, _verify_possession)
                 
        print(f'{Name.to_str(issued_cert_name)}')
        data_name, _, _, raw_pkt = await self.app.express_interest(
            issued_cert_name, forwarding_hint=[forwarding_hint], 
            can_be_prefix=False, lifetime=6000, need_raw_packet=True
        )

        try:
            retrieved_cert = parse_certificate(raw_pkt)
            print(f'Installing final certificate: {Name.to_str(retrieved_cert.name)}')
        except:
            print(f'Not a certificate: {Name.to_str(data_name)}')
            return

        # installing the formal cert
        self.keychain.import_cert(formal_key.name, issued_cert_name, raw_pkt)
        
    async def construct_minimal_trust_zone(self, local_app: NDNApp, id_name: FormalName, **kwargs) -> Tuple[TibBundle, Ca]:
        local_anchor_id = self.keychain.touch_identity(id_name)
        local_anchor_key = local_anchor_id.default_key()
        local_anchor_data = parse_certificate(local_anchor_key.default_cert().data)
        local_anchor_signer = self.keychain.get_signer({'cert': local_anchor_data.name})
        
        
        local_issuer_str = 'formal-issuer'
        variable_pattern = '/"{formal_issuer}"'
        variable_pattern.format(formal_issuer = local_issuer_str)
        
        local_lvs = define_minimal_trust_zone(local_anchor_id.name)
        
        
        
        # generate TIB bundle
        bundle = TibBundle()
        bundle.anchor = local_anchor_key.default_cert().data
        bundle.schema = compile_lvs(local_lvs)
        
        config = []
        if 'authenticator' in kwargs:
            config_path = kwargs['authenticator']
            config = get_yaml(config_path)
        # start local Authenticator
        ca = Ca(local_app, config)
        ca.go()
        
        #todo: start local NDNCERT
        
        
        
        return bundle, ca 
        