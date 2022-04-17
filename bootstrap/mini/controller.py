from datetime import datetime
import logging, os, asyncio
from typing import Dict

from ndn.encoding import Name, Component, NonStrictName
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import compile_lvs


from ..tib import Tib, TibBundle
from ..app_support.ca_tib import CaWithTib
from ..ndncert.utils.config import get_yaml
from ..app_support.simple_rdr import RdrProducer

app = NDNApp()

class ZoneController(object):
    def __init__(self, app: NDNApp, path: str, zone_name: NonStrictName,
                 config_file: str, need_auth = False, need_issuer = False):
        self.zone_name = Name.normalize(zone_name)
        
        pib_file = os.path.join(path, 'pib.db')
        tpm_dir = os.path.join(path, 'privKeys')
        KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
        keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
        
        # if you need separate authenticator and cert issuer
        self.lvs, self.signed_bundle = Tib.construct_minimal_trust_zone(self.zone_name,
            keychain, need_auth = need_auth, need_issuer = need_issuer)
        tib_base = os.path.join(path, 'controller-tib')
        Tib.initialize(self.signed_bundle, tib_base)
        self.tib = Tib(app, tib_base, keychain = keychain)

        # also need to get the signer, could be useful
        self.anchor_signer_name = keychain[zone_name].default_key() \
                                                .default_cert().name
        self.anchor_signer = keychain.get_signer({'cert': self.anchor_signer_name})
        self.app = app

        # register keys in TIB
        asyncio.create_task(self.tib.register_keys())
        
        # initialize ndncert
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, 'ca-template.conf')        
        config = get_yaml(filename)

        # load authentication config
        auth_config = get_yaml(config_file)

        # overwrite config
        if not (need_auth and need_issuer):
            # we still a ca controlled by anchor
            config['prefix_config']['prefix_name'] = Name.to_str(self.zone_name)
            config['db_config']['base'] = os.path.join(self.tib.get_path(), 'anchor')

            # the anchor controlled ca may does authentication
            if not need_auth:
                config['auth_config'] = auth_config['auth_config']
            
            print(config)
            # the anchor controlled ca may issue final certificate
            if not need_issuer:
                if config['auth_config']:
                    config['auth_config']['possession'] = {'user_func': 'autopass'} 
                else:
                    config['auth_config'] = {'possession': {'user_func': 'autopass'}}
            
            print(config)
            self.ca = CaWithTib(app, config, self.tib)
            self.ca.register()
            
        # use rdr to host bundle
        self.rdrpro = RdrProducer(app, self.zone_name + [Component.from_str('BUNDLE')],
                                    self.tib, register_route = True)

        # If we have separate authenticator and cert issuer, we need to set them up
        # or we can manually bootstrap the authenticator and cert issuer in code
        if need_auth:
            auth_id = self.tib.keychain.touch_identity(self.zone_name + [Component.from_str('auth')])
            auth_self_cert_data = auth_id.default_key().default_cert().data
            auth_self_cert = parse_certificate(auth_self_cert_data)
            
            # derive a one week cert
            auth_derived_cert_name, auth_derived_cert_data = \
                derive_cert(auth_id.default_key().name, 'Anchor',
                            auth_self_cert.content, self.anchor_signer,
                            datetime.utcnow(), 168 * 3600)
            logging.info("Deriving authenticator's certificate " 
                        f"{Name.to_str(auth_derived_cert_name)}...")
            self.tib.keychain.import_cert(auth_id.default_key().name, 
                                          auth_derived_cert_name,
                                          auth_derived_cert_data)
            # start the NDNCERT CA for authenticator
            config = get_yaml(filename)
            config['prefix_config']['prefix_name'] = Name.to_str(auth_id.name)
            config['db_config']['base'] = os.path.join(self.tib.get_path(), 'auth')
            config['auth_config'] = auth_config['auth_config']
            print(config)
            
            # using the same tib so we don't need reconfiguration
            self.ca_auth = CaWithTib(app, config, self.tib)
            self.ca_auth.register()
        
        if need_issuer:
            # manually bootstrap the cert issuer
            issuer_id = self.tib.keychain.touch_identity(self.zone_name + [Component.from_str('cert')])
            issuer_self_cert_data = issuer_id.default_key().default_cert().data
            issuer_self_cert = parse_certificate(issuer_self_cert_data)
            
            # derive a one week cert
            issuer_derived_cert_name,  issuer_derived_cert_data = \
                derive_cert(issuer_id.default_key().name, 'Anchor',
                            issuer_self_cert.content, self.anchor_signer, 
                            datetime.utcnow(), 168 * 3600)
            logging.info("Deriving cert issuer's certificate "
                        f"{Name.to_str(issuer_derived_cert_name)}...")
            self.tib.keychain.import_cert(issuer_id.default_key().name,
                                          issuer_derived_cert_name,
                                          issuer_derived_cert_data)
            # start the NDNCERT CA for cert issuer
            config = get_yaml(filename)
            config['prefix_config']['prefix_name'] = Name.to_str(issuer_id.name)
            config['db_config']['base'] = os.path.join(self.tib.get_path(), 'cert')
            if config['auth_config']:
                config['auth_config']['possession'] = {'user_func': 'autopass'} 
            else:
                config['auth_config'] = {'possession': {'user_func': 'autopass'}}
                    
            self.ca_issuer = CaWithTib(app, config, self.tib)
            self.ca_issuer.register()

    def save_bundle(self, filepath):
        logging.debug(f'Signed bundle size: {len(self.signed_bundle)} bytes')
        max_width = 70
        from base64 import b64encode
        from math import ceil
        with open(filepath, 'w') as bundle_file:
            bundle_str = b64encode(self.signed_bundle).decode("utf-8")
            lines_needed = ceil(len(bundle_str) / max_width)
            for i in range(0, lines_needed):
                line = bundle_str[i * max_width : (i + 1) * max_width]  + '\n'
                bundle_file.write(line)

    def update_schema(self, new_lvs: str):
        self.lvs = new_lvs
        new_schema = compile_lvs(self.lvs)
        new_bundle = TibBundle()
        new_bundle.schema = new_schema
        # we ignore the trust anchor if not updated
        self.rdrpro.produce(new_bundle.encode(), freshness_period = 3600)

    def update_anchor(self, new_anchor: bytes):
        new_bundle = TibBundle()
        new_bundle.anchor = new_anchor
        # we ignore the schema if not updated
        self.rdrpro.produce(new_bundle.encode(), freshness_period = 3600)

    def get_zone_lvs(self):
        return self.lvs