from tempfile import TemporaryDirectory
from datetime import datetime

import logging, os, asyncio
from ndn.encoding import Name
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS, LvsModel

from ndncert.security_support.tib import Tib, TibBundle
from ndncert.security_support.lvs_template import define_minimal_trust_zone,\
    define_generic_cert, define_generic_data_rule
from ndncert.app.ca import Ca
from ndncert.utils.config import get_yaml
from ndncert.utils.simple_rdr import RdrProducer

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')

app = NDNApp()
    
def save_bundle(file, filepath):
    logging.debug(f'Signed bundle size: {len(file)} bytes')
    max_width = 70
    from base64 import b64encode
    from math import ceil
    with open(filepath, 'w') as bundle_file:
        bundle_str = b64encode(file).decode("utf-8")
        lines_needed = ceil(len(bundle_str) / max_width)
        for i in range(0, lines_needed):
            line = bundle_str[i * max_width : (i + 1) * max_width]  + '\n'
            bundle_file.write(line)    

async def async_main(tmpdirname):
    pib_file = os.path.join(tmpdirname, 'pib.db')
    tpm_dir = os.path.join(tmpdirname, 'privKeys')
    KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
    keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
    
    zone_name = Name.from_str('/ndn/local/ucla')
    # need_tmpcert if you need separate authenticator and cert issuer
    signed_bundle = Tib.construct_minimal_trust_zone(zone_name,
        keychain, need_tmpcert = True, need_issuer = True)
    
    # also need to get the signer, could be useful
    anchor_signer_name = keychain[zone_name].default_key() \
                                            .default_cert().name
    anchor_signer = keychain.get_signer({'cert': anchor_signer_name})
    
    tib_base = os.path.join(tmpdirname, 'tib-test')
    Tib.initialize(signed_bundle, tib_base)
    tib = Tib(app, tib_base, keychain = keychain)
    await tib.register_keys()
    
    # also write to the local dir to enable out-of-band sharing
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, 'ndn-local-ucla.bundle')
    save_bundle(signed_bundle, filename)
    
    # If we have separate authenticator and cert issuer, we need to set them up
    # There are several approaches to bootstrap authenticator and cert issuer, 
    # which is outside the scope of this work. This example assumes both the 
    # authenticator and cert issuer is the trust anchor.

    # filename = os.path.join(dirname, 'ndncert-ca.conf')        
    # config = get_yaml(filename)
    # print(config)
    # ca = Ca(app, config, tib)
    # ca.go()
    
    # or we can manually bootstrap the authenticator and cert issuer in code
    auth_id = keychain.touch_identity('/ndn/local/ucla/auth')
    auth_self_cert_data = auth_id.default_key().default_cert().data
    auth_self_cert = parse_certificate(auth_self_cert_data)
    
    # derive a one week cert
    auth_derived_cert_name, auth_derived_cert_data = \
         derive_cert(auth_id.default_key().name, 'Anchor',
                     auth_self_cert.content, anchor_signer,
                     datetime.utcnow(), 168 * 3600)
    logging.info("Deriving authenticator's certificate" 
                 f"{Name.to_str(auth_derived_cert_name)}...")
    keychain.import_cert(auth_id.default_key().name, auth_derived_cert_name,
                         auth_derived_cert_data)
    # start the NDNCERT CA for authenticator
    filename = os.path.join(dirname, 'ndncert-ca-auth.conf')        
    config = get_yaml(filename)
    print(config)
    
    # using the same tib so we don't need reconfiguration
    ca_auth = Ca(app, config, tib)
    ca_auth.go()
    
    # manually bootstrap the cert issuer
    issuer_id = keychain.touch_identity('/ndn/local/ucla/cert')
    issuer_self_cert_data = issuer_id.default_key().default_cert().data
    issuer_self_cert = parse_certificate(issuer_self_cert_data)
    
    # derive a one week cert
    issuer_derived_cert_name,  issuer_derived_cert_data = \
        derive_cert(issuer_id.default_key().name, 'Anchor',
                    issuer_self_cert.content, anchor_signer, 
                    datetime.utcnow(), 168 * 3600)
    logging.info("Deriving cert issuer's certificate"
                 f"{Name.to_str(issuer_derived_cert_name)}...")
    keychain.import_cert(issuer_id.default_key().name, issuer_derived_cert_name,
                         issuer_derived_cert_data)
    # start the NDNCERT CA for cert issuer
    filename = os.path.join(dirname, 'ndncert-ca-issuer.conf')        
    config = get_yaml(filename)
    ca_issuer = Ca(app, config, tib)
    ca_issuer.go()

    # use rdr to host bundle
    rdr_pro = RdrProducer(app, Name.from_str('/ndn/local/ucla/BUNDLE'),
                          tib, register_route = True)
    async def update_bundle_after(wait_in_seconds):
        await asyncio.sleep(wait_in_seconds)
        updated_lvs = define_minimal_trust_zone(zone_name,
            need_tmpcert = True, need_issuer = True)
        # let's update schema so we can have EntityClass 2
        
        updated_lvs += define_generic_cert(zone_name, '/suffix1/suffix2',
                                   signee = 'EntityClass2', signer = 'Issuer')
        # define app data produced by EntityClass
        # DataClassi: rule applied to EntityClassi
        updated_lvs += define_generic_data_rule('DataClass2', zone_name,
            # allow entity class publish data at one level deeper
            variable_pattern = '/suffix1/suffix2/_',
            #don't have constraints#,
            signer = 'EntityClass2')
        # a little formatting
        updated_lvs.replace('\n\n', '\n')
        logging.info(updated_lvs)
        
        updated_schema = compile_lvs(updated_lvs)
        updated_bundle = TibBundle()
        updated_bundle.schema = updated_schema
        # we ignore the trust anchor if not updated
        
        rdr_pro.produce(updated_bundle.encode(), freshness_period = 3600)
    
    asyncio.create_task(update_bundle_after(5))

    
if __name__ == "__main__":
    with TemporaryDirectory() as tmpdirname:
        app.run_forever(after_start=async_main(tmpdirname))
