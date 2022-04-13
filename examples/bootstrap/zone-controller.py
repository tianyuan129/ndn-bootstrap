from typing import Tuple, List
from tempfile import TemporaryDirectory
from base64 import b64encode
from math import ceil

import logging, os
from ndn.encoding import Name
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app import NDNApp
from ndn.app_support.security_v2 import sign_req
from ndn.app_support.light_versec import compile_lvs

from ndncert.app_support.tib import Tib, TibBundle
from ndncert.app.ca import Ca
from ndncert.util.config import get_yaml

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

app = NDNApp()
    
def main(tmpdirname) -> int:
    pib_file = os.path.join(tmpdirname, 'pib.db')
    tpm_dir = os.path.join(tmpdirname, 'privKeys')
    KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
    keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
    
    zone_name = Name.from_str('/ndn/local/ucla')
    # need_tmpcert if you need separate authenticator and cert issuer
    signed_bundle = Tib.construct_minimal_trust_zone(zone_name, keychain)
    tib_base = os.path.join(tmpdirname, 'tib-test')
    Tib.initialize(signed_bundle, tib_base)
    tib = Tib(app, tib_base, keychain = keychain)
    
    # also write to the local dir to enable out-of-band sharing
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, 'ndn-local-ucla.bundle')
    max_width = 70
    with open(filename, 'w') as bundle_file:
        bundle_str = b64encode(signed_bundle).decode("utf-8")
        for i in range(0, ceil(len(bundle_str) / max_width)):
            line = bundle_str[i * max_width : (i + 1) * max_width] + '\n'
            bundle_file.write(line)

    # the bundle has to exist after the program exited, so save to real path
    
    # If we have separate authenticator and cert issuer, we need to set them up
    # There are several approaches to bootstrap authenticator and cert issuer, 
    # which is outside the scope of this work.
    # This example assumes both the authenticator and cert issuer is the trust anchor.
    filename = os.path.join(dirname, 'ndncert-ca.conf')        
    config = get_yaml(filename)
    print(config)
    ca = Ca(app, config, tib)
    ca.go()
    
if __name__ == "__main__":
    with TemporaryDirectory() as tmpdirname:
        app.run_forever(after_start=main(tmpdirname))
