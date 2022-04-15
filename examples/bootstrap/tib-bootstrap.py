from base64 import b64decode
from typing import Tuple, List
from tempfile import TemporaryDirectory

import logging, os, asyncio
from ndn.encoding import Name, Component, parse_data
from ndn.app import NDNApp, InterestTimeout, InterestNack

from ndncert.app_support.tib import Tib, TibBundle
from ndncert.utils.simple_rdr import RdrConsumer

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
    
async def async_main(tmpdirname) :        
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
    await tib.bootstrap(Name.from_str('/ndn/local/ucla/tianyuan'), select_first, email_verifier,
                        need_tmpcert=True, need_issuer=True)
    rdr_con = RdrConsumer(app, Name.from_str('/ndn/local/ucla/BUNDLE'))
    
    # get the original bundle version
    name, _, _, _ = parse_data(signed_bundle_wire)
    initial_version = Component.to_number(name[-1])
    async def solicit_bundle_after(installed_version, wait_in_seconds):
        await asyncio.sleep(wait_in_seconds)
        try:
            latest_verison = await rdr_con.get_latest_version()
        except (InterestTimeout, InterestNack) as e:
            logging.debug(f'Interest failed because of {e}')
        if latest_verison > installed_version:
            try:
                name, _, content = await rdr_con.get_versioned_data(latest_verison)
            except (InterestTimeout, InterestNack) as e:
                logging.debug(f'Interest failed because of {e.reason}')            
            logging.info(f'Installing bundle {Name.to_str(name)}...')
            fetched_bundle = TibBundle.parse(content)
            tib.install_trusted_bundle(fetched_bundle)
        asyncio.create_task(solicit_bundle_after(latest_verison, wait_in_seconds))
    
    asyncio.create_task(solicit_bundle_after(initial_version, 5))
    
if __name__ == "__main__":
    with TemporaryDirectory() as tmpdirname:
        app.run_forever(after_start=async_main(tmpdirname))