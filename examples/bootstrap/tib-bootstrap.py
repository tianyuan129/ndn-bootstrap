from base64 import b64decode
from typing import Tuple, List
from tempfile import TemporaryDirectory

import logging, os
from ndn.encoding import Name, parse_data
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app import NDNApp
from ndn.app_support.security_v2 import sign_req, parse_certificate
from ndn.app_support.light_versec import compile_lvs
from ndn.security.validator import verify_ecdsa

from ndncert.app_support.tib import Tib, TibBundle

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')

app = NDNApp()

async def select_first(list: List[bytes]) -> Tuple[bytes, bytes, bytes]:
    return list[0], "email".encode(), "tianyuan@tianyuan.ndn".encode()
    
    
async def email_verifier(challenge_status: bytes, param_key: bytes, param_value: bytes) -> Tuple[bytes, bytes]:
    assert param_key is None
    assert param_value is None
    assert bytes(challenge_status).decode() == "need-code"
    val = input("Enter your code: ")
    print(val)

    return "code".encode(), val.encode()
    
def main() -> int:
    with TemporaryDirectory() as tmpdirname:
        
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, 'ndn-local-ucla.bundle')
        bundle_str = ''
        with open(filename, 'r') as bundle_file:
            for line in bundle_file.readlines():
                bundle_str += line
                
        signed_bundle_wire = b64decode(bundle_str)
        tib_base = os.path.join(tmpdirname, 'tib-test')
        Tib.initialize(signed_bundle_wire, tib_base)
        # TIB will create keychain on application's behalf and load to app
        tib = Tib(app, path=tib_base)
        async def bootstrap():
            await tib.bootstrap(Name.from_str('/ndn/local/ucla/tianyuan'), select_first, email_verifier)
            app.shutdown()

        app.run_forever(bootstrap())
    
    
if __name__ == "__main__":
    main()
