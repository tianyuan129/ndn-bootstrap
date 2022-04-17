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
from base64 import b64encode, b64decode
import asyncio
from math import ceil
from Cryptodome.PublicKey import ECC
import logging, os
from ndn.encoding import Name, Component, parse_data, make_data,  \
     NonStrictName, FormalName, TlvModel, BytesField, ModelField, MetaInfo, \
     InterestParam, BinaryStr
from ndn.app_support.security_v2 import parse_certificate, sign_req
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS, LvsModel, lvs_validator
from ndn.security import TpmFile, KeychainSqlite3, verify_ecdsa
from ndn.utils import timestamp
from ndn.app import NDNApp

from ..ndncert.app.client import Client, Selector, Verifier
from ..ndncert.proto.ndncert_proto import ChallengeRequest
from ..ndncert.proto.types import *
from .lvs_template import define_minimal_trust_zone

TLV_TIB_BUNDLE_ANCHOR = 301
TLV_TIB_BUNDLE_SCHEMA = 303

# a bundle Data packet should have the following name
# /<prefix>/BUNDLE/<keyid>/<version>
class TibBundle(TlvModel):
    anchor = BytesField(TLV_TIB_BUNDLE_ANCHOR)
    schema = ModelField(TLV_TIB_BUNDLE_SCHEMA, LvsModel)

class NoSigningKey(Exception):
    """
    Raised when no appropriate signing key is available
    """
    pass
class TibError(Exception):
    """
    Raised when not calling TIB functions properly
    """
    pass

class Tib(object):
    # this will load the app with data_validator
    def __init__(self, app: NDNApp, path: str, **kwargs):
        # loading the accepted signed bundle
        filename = os.path.join(path, 'trust-zone.bundle')
        self.base_dir = path
        bundle_str = ''
        with open(filename, 'r') as bundle_file:
            for line in bundle_file.readlines():
                bundle_str += line
        
        # verify signature again to prevent manupulation
        signed_bundle_wire = b64decode(bundle_str)
        result, bundle = Tib.accept_signed_bundle(signed_bundle_wire)
        if not result:
            logging.fatal(f'Signed Bundle cannot be verified, quit')
            return
        self.anchor = bundle.anchor

        self.anchor_data = parse_certificate(self.anchor)
        anchor_name = self.anchor_data.name
        self.zone_prefix = anchor_name[:-4]
        self.schema = bundle.schema
        self.checker = Checker(bundle.schema, DEFAULT_USER_FNS)
        logging.info(f'Initializing TIB for {Name.to_str(self.zone_prefix)}...')
        logging.info(f'Trust Anchor: {Name.to_str(anchor_name)}...')
         
        # Tib path will be used for pib, tpm
        if 'keychain' in kwargs:
            logging.warning(f"Using application's own keychain")
            keychain = kwargs['keychain']
            if type(keychain) is KeychainSqlite3:
                self.keychain = keychain
            else:
                raise TibError('Keychain must be KeychainSqlite3 type')
        else:
            # initialize pib and tpm
            if not os.path.exists(self.base_dir):
                os.makedirs(self.base_dir)
            tpm_path = os.path.join(self.base_dir, 'privKeys')
            pib_path = os.path.join(self.base_dir, 'pib.db')
            if KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_path):
                logging.info(f'Intializing keychain at {self.base_dir}...')
            else:
                logging.info(f'Found keychain at {self.base_dir}...')
            self.keychain = KeychainSqlite3(pib_path, TpmFile(tpm_path))

        # pass keychain to apps      
        self.app = app
        app.keychain = self.keychain
        validator = lvs_validator(self.checker, self.app, self.anchor)
        
        # a validator wrapper is needed to attach specific trust schema to trust zone namespace
        async def _validator_wrapper(name, sig_ptrs):
            if Name.is_prefix(self.zone_prefix, name):
                logging.debug(f'Trust Zone data, checking...')
                return await validator(name, sig_ptrs)
            elif Name.is_prefix('/localhost', name):
                logging.debug(f'NFD management data, bypass {Name.to_str(name)}...')
                return True
            elif Name.is_prefix('/localhop', name):
                logging.debug(f'NFD management data, bypass {Name.to_str(name)}...')
                return True
            else:
                logging.debug(f'Neither schema defined nor NFD management data')
                return True
        app.data_validator = _validator_wrapper
        
        # initialzing key handles
        self._key_handles = []
    
    # this function will only creates the directory, not initializing the keychain
    @staticmethod
    def initialize(signed_bundle: bytes, path = None) -> Tuple[bool, str]:
        result, bundle = Tib.accept_signed_bundle(signed_bundle)
        if not result:
            logging.fatal(f'Signed Bundle cannot be verified, quit')
            return

        anchor_data = parse_certificate(bundle.anchor)
        anchor_name = anchor_data.name
        zone_prefix = anchor_name[:-4]
        if not path:
            path = '~/.ndn/tib/' + Name.to_bytes(zone_prefix).hex()
            path = os.path.expanduser(path)
        if os.path.exists(path):
            logging.fatal(f'Tib {path} already exists')
            return False, path
        else:
            os.makedirs(path)
            
        # saving the bundle
        filename = os.path.join(path, 'trust-zone.bundle')
        max_width = 70
        with open(filename, 'w') as bundle_file:
            bundle_str = b64encode(signed_bundle).decode("utf-8")
            for i in range(0, ceil(len(bundle_str) / max_width)):
                line = bundle_str[i * max_width : (i + 1) * max_width] + '\n'
                bundle_file.write(line)
        return True, path

    def install_trusted_bundle(self, bundle: TibBundle):
        if bundle.anchor is not None:
            self.anchor = bundle.anchor
            self.anchor_data = parse_certificate(self.anchor)
            anchor_name = self.anchor_data.name
            if self.zone_prefix != anchor_name[:-4]:
                raise TibError(f'Zone prefix conflict: {Name.to_str(self.zone_prefix)} '
                               f'-> {Name.to_str(anchor_name[:-4])}')
        if bundle.schema is not None:
            self.schema = bundle.schema
            self.checker = Checker(bundle.schema, DEFAULT_USER_FNS)
            validator = lvs_validator(self.checker, self.app, self.anchor)
            # a validator wrapper is needed to attach specific trust schema to trust zone namespace
            async def _validator_wrapper(name, sig_ptrs):
                if Name.is_prefix(self.zone_prefix, name):
                    logging.debug(f'Trust Zone data, checking...')
                    return await validator(name, sig_ptrs)
                elif Name.is_prefix('/localhost', name):
                    logging.debug(f'NFD management data, bypass {Name.to_str(name)}...')
                    return True
                elif Name.is_prefix('/localhop', name):
                    logging.debug(f'NFD management data, bypass {Name.to_str(name)}...')
                    return True
                else:
                    logging.debug(f'Neither schema defined nor NFD management data')
                    return True
            self.app.data_validator = _validator_wrapper

    @staticmethod
    def accept_signed_bundle(wire: bytes) -> Tuple[bool, TibBundle]:
        _, _, content, sig_ptrs = parse_data(wire)
        bundle = TibBundle.parse(content)
        anchor_cert_data = parse_certificate(bundle.anchor)
        pubkey = ECC.import_key(anchor_cert_data.content)
        return verify_ecdsa(pubkey, sig_ptrs), bundle
    
    async def register_keys(self):
        for id_name in self.keychain:
            key_prefix = id_name + [Component.from_str('KEY')]
            
            if key_prefix not in self._key_handles:
                logging.debug(f'TIB registers for {Name.to_str(key_prefix)}')
                @self.app.route(key_prefix)
                def _on_cert_retrieval(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
                    for id_name in self.keychain:
                        identity = self.keychain[id_name]
                        for key_name in identity:
                            key = identity[key_name]
                            for cert_name in key:
                                logging.debug(f'If {Name.to_str(cert_name)} satisfies the Interest {Name.to_str(name)}')
                                if Name.is_prefix(name, cert_name) or name == cert_name:
                                    cert = key[cert_name].data
                                    logging.debug(f'Returning {Name.to_str(cert_name)}...')
                                    self.app.put_raw_packet(cert)
                self._key_handles.append(key_prefix)

        await asyncio.sleep(1)
        asyncio.create_task(self.register_keys())
    
    async def bootstrap(self, id_name: FormalName, selector: Selector, verifier: Verifier,
                        need_auth = False, need_issuer = False):
        client = Client(self.app)
        
        anchor_name = self.anchor_data.name
        # /<prefix>/KEY/<keyid>/<issuer>/<version>
        zone_prefix = anchor_name[:-4]
        
        if not Name.is_prefix(zone_prefix, id_name):
            raise InvalidName(f'Authenticator prefix {Name.to_str(zone_prefix)} is not a ' + 
                              f'prefix of identity name {Name.to_str(id_name)}')

        # the name used for authentication
        if need_auth or need_issuer:
            id_authname = []
            id_authname[:] = id_name[:]
            id_authname.insert(len(zone_prefix), 'auth')
            
            authid = self.keychain.touch_identity(id_authname)
            authid_key = authid.default_key()
            authid_cert_data = parse_certificate(authid_key.default_cert().data)
            authid_signer = self.keychain.get_signer({'cert': authid_cert_data.name})
            _, csr = sign_req(authid_key.name, authid_cert_data.content, authid_signer)
            auth_prefix = zone_prefix + [Component.from_str('auth')] \
                          if need_auth else zone_prefix
            issued_cert_name, forwarding_hint = await client.request_signing(auth_prefix, bytes(csr), 
                authid_signer, selector, verifier)
            
            logging.debug(f'Retrieving certificate {Name.to_str(issued_cert_name)}...')
            data_name, _, _, raw_pkt = await self.app.express_interest(
                issued_cert_name, forwarding_hint=[forwarding_hint], 
                can_be_prefix=False, lifetime=6000, need_raw_packet=True
            )
            try:
                retrieved_cert = parse_certificate(raw_pkt)
                logging.info(f'Installing tmp certificate: {Name.to_str(retrieved_cert.name)}')
            except:
                logging.error(f'Not a certificate: {Name.to_str(data_name)}')
                return
            # installing the tmp cert 
            self.keychain.import_cert(authid_key.name, issued_cert_name, raw_pkt)

        # always select proof-of-possession challenge from NDNCERT
        async def _select_possession(list: List[bytes]) -> Tuple[bytes, bytes, bytes]:    
            for challenge in list:
                if challenge == 'possession':
                    return challenge, 'issued-cert'.encode(), authid_key[issued_cert_name].data
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

        _selector = _select_possession if need_auth or need_issuer else selector
        _verifier = _verify_possession if need_auth or need_issuer else verifier
        issuer_prefix = zone_prefix + [Component.from_str('cert')] \
                          if need_issuer else zone_prefix
            
        issued_cert_name, forwarding_hint = await client.request_signing(issuer_prefix, bytes(csr), 
            formal_signer, _selector, _verifier)
            
        logging.debug(f'Retrieving certificate {Name.to_str(issued_cert_name)}...')
        data_name, _, _, raw_pkt = await self.app.express_interest(
            issued_cert_name, forwarding_hint=[forwarding_hint], 
            can_be_prefix=False, lifetime=6000, need_raw_packet=True
        )

        try:
            retrieved_cert = parse_certificate(raw_pkt)
            logging.info(f'Installing final certificate: {Name.to_str(retrieved_cert.name)}')
        except:
            logging.error(f'Not a certificate: {Name.to_str(data_name)}')
            return

        # installing the formal cert
        self.keychain.import_cert(formal_key.name, issued_cert_name, raw_pkt)

    # it will modify keychains
    @staticmethod
    def construct_minimal_trust_zone(id_name: FormalName, keychain: KeychainSqlite3, need_auth = False, need_issuer = False):
        try:
            local_anchor_id = keychain[id_name]
        except:
            local_anchor_id = keychain.touch_identity(id_name)
        local_anchor_key = local_anchor_id.default_key()
        
        local_lvs = define_minimal_trust_zone(local_anchor_id.name, 
            need_auth=need_auth, need_issuer=need_issuer)
        # generate TIB bundle
        bundle = TibBundle()
        bundle.anchor = local_anchor_key.default_cert().data
        bundle.schema = compile_lvs(local_lvs)
        
        # sign the bundle
        trust_anchor_data = parse_certificate(bundle.anchor)
        bundle_name = trust_anchor_data.name[:-4]
        bundle_name += [Component.from_str('BUNDLE')]
        bundle_name += [Component.from_version(timestamp())]
        bundle_signer = keychain.get_signer({'cert': trust_anchor_data.name})
        # bundle's freshness period should relatively long so can stay in the content store
        meta_info = MetaInfo.from_dict({'freshness_period': 10000})
        return local_lvs, make_data(bundle_name, meta_info, bundle.encode(), signer=bundle_signer)
    
    def suggest_signer(self, name: NonStrictName):
        # locate the matching signing certificate  
        signer_name = self.checker.suggest(name, self.keychain)
        if signer_name is None:
            raise NoSigningKey
        return self.keychain.get_signer({'cert': signer_name})
    
    def sign_data(self, name: NonStrictName, content: bytes, **kwargs):
        # locate the matching signing certificate
        signer = self.suggest_signer(name)
        return self.app.prepare_data(name, content = content, signer = signer, **kwargs)
        
    def sign_bundle_data(self, bundle_wire: bytes):
        # parsing to obtain the zone prefix
        bundle = TibBundle.parse(bundle_wire)
        trust_anchor_data = parse_certificate(bundle.anchor)
        bundle_name = []
        # copy till to the keyid
        bundle_name[:] = trust_anchor_data.name[:-2]
        # replace KEY => BUNDLE
        bundle_name[-2] = Component.from_str('BUNDLE')
        # append version
        bundle_name.append(Component.from_version(timestamp()))
        
        logging.debug(f'Generating bundle {Name.to_str(bundle_name)}...')        
        return self.sign_data(bundle_name, bundle_wire)
    
    
    def get_path(self):
        return self.base_dir