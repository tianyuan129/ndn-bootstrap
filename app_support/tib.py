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

from typing import Optional
import os
from ndn.encoding import Name, FormalName, TlvModel, BytesField, ModelField
from ndn.app_support.security_v2 import parse_certificate, sign_req
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS, LvsModel, lvs_validator
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app import NDNApp

from ca.client import Client, Selector, Verifier

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
        client = Client(self.app, self.anchor_data, self.schema)
        
        anchor_name = self.anchor_data.name
        # /<prefix>/KEY/<keyid>/<issuer>/<version>
        auth_prefix = anchor_name[:-4]
        
        newid = self.keychain.touch_identity(id_name)
        newid_key = newid.default_key()
        newid_cert_data = parse_certificate(newid_key.default_cert().data)
        newid_signer = self.keychain.get_signer({'cert': newid_cert_data.name})
        
        csr_name, csr = sign_req(newid_key.name, newid_cert_data.content, newid_signer)
        issued_cert_name, forwarding_hint = await client.request_signing(auth_prefix, bytes(csr), 
            newid_signer, selector, verifier)
        
        print(f'{Name.to_str(issued_cert_name)}')
        data_name, meta_info, content, raw_pkt = await self.app.express_interest(
            issued_cert_name, forwarding_hint=[forwarding_hint], 
            can_be_prefix=False, lifetime=6000, need_raw_packet=True
        )

        retrieved_cert = parse_certificate(raw_pkt)
        print(f'{Name.to_str(retrieved_cert.name)}')
        # self.keychain.import_cert()
        
        