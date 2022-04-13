from tempfile import TemporaryDirectory
from base64 import b64encode
from math import ceil
from datetime import datetime

import logging, os, asyncio
from ndn.encoding import Name, Component
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate, derive_cert

from ndncert.app_support.tib import Tib
from ndncert.app.ca import Ca
from ndncert.util.config import get_yaml

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')

app = NDNApp()
    
def save_bundle(file, filepath):
    max_width = 70
    with open(filepath, 'w') as bundle_file:
        bundle_str = b64encode(file).decode("utf-8")
        for i in range(0, ceil(len(bundle_str) / max_width)):
            line = bundle_str[i * max_width : (i + 1) * max_width] + '\n'
            bundle_file.write(line)    

async def async_main(tmpdirname):
    pib_file = os.path.join(tmpdirname, 'pib.db')
    tpm_dir = os.path.join(tmpdirname, 'privKeys')
    KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
    keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
    
    zone_name = Name.from_str('/ndn/local/ucla')
    # need_tmpcert if you need separate authenticator and cert issuer
    signed_bundle = Tib.construct_minimal_trust_zone(zone_name, keychain,
        need_tmpcert = True, need_issuer = True)
    
    # also need to get the signer, could be useful
    anchor_signer_name = keychain[zone_name].default_key().default_cert().name
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
    # which is outside the scope of this work.
    # This example assumes both the authenticator and cert issuer is the trust anchor.
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
    auth_derived_cert_name,  auth_derived_cert_data = derive_cert(auth_id.default_key().name, 'Anchor',
        auth_self_cert.content, anchor_signer, datetime.utcnow(), 168 * 3600)
    logging.info(f"Deriving authenticator's certificate {Name.to_str(auth_derived_cert_name)}...")
    keychain.import_cert(auth_id.default_key().name, auth_derived_cert_name, auth_derived_cert_data)
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
    issuer_derived_cert_name,  issuer_derived_cert_data = derive_cert(issuer_id.default_key().name, 'Anchor',
        issuer_self_cert.content, anchor_signer, datetime.utcnow(), 168 * 3600)
    logging.info(f"Deriving cert issuer's certificate {Name.to_str(issuer_derived_cert_name)}...")
    keychain.import_cert(issuer_id.default_key().name, issuer_derived_cert_name, issuer_derived_cert_data)
    # start the NDNCERT CA for cert issuer
    filename = os.path.join(dirname, 'ndncert-ca-issuer.conf')        
    config = get_yaml(filename)
    ca_issuer = Ca(app, config, tib)
    ca_issuer.go()

if __name__ == "__main__":
    with TemporaryDirectory() as tmpdirname:
        app.run_forever(after_start=async_main(tmpdirname))
