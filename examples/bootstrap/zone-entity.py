from base64 import b64decode
from typing import Tuple, List
from tempfile import TemporaryDirectory
import argparse

import logging, os, sys, asyncio
from ndn.app import NDNApp
from bootstrap.mini.entity import ZoneEntity

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')

app = NDNApp()

def process_cmd_opts():
    """
    Parse, process, and return cmd options.
    """
    def parse_cmd_opts():
        parser = argparse.ArgumentParser(description='zone-controller')
        parser.add_argument('-a', '--auth',
                            help='Need a separate authenticator to issue temporary certificates '
                                 'as the proof of name possesion',
                            action='store_true')
        parser.add_argument('-i', '--issuer',
                            help='Need a separate cert issuer to issue real certificates',
                            action='store_true')
        args = parser.parse_args()
        return args
    args = parse_cmd_opts()
    return args

async def select_first(list: List[bytes]) -> Tuple[bytes, bytes, bytes]:
    return list[0], "email".encode(), "tianyuan@tianyuan.ndn".encode()

async def email_verifier(challenge_status: bytes, param_key: bytes, param_value: bytes) -> Tuple[bytes, bytes]:
    assert param_key is None
    assert param_value is None
    assert bytes(challenge_status).decode() == "need-code"
    val = input("Enter your code: ")
    print(val)

    return "code".encode(), val.encode()
    
async def async_main(cmdline_args, tmpdirname):
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, 'ndn-local-ucla.bundle')
    bundle_str = ''
    with open(filename, 'r') as bundle_file:
        for line in bundle_file.readlines():
            bundle_str += line
            
    signed_bundle_wire = b64decode(bundle_str)    
    entity = ZoneEntity(app, tmpdirname, signed_bundle_wire)  
    await entity.bootstrap_to('/ndn/local/ucla/tianyuan', select_first, email_verifier,
                              cmdline_args.auth, cmdline_args.issuer)
    asyncio.create_task(entity.rdr_discover_bundle(5))

def main () -> int:
    cmdline_args = process_cmd_opts()
    with TemporaryDirectory() as tmpdirname:
        app.run_forever(after_start=async_main(cmdline_args, tmpdirname))
    return 0
if __name__ == "__main__":
    sys.exit(main())
