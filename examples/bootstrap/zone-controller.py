from tempfile import TemporaryDirectory
import argparse
from typing import Optional

import logging, os, sys, asyncio
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, MetaInfo
from ndn.app import NDNApp


from bootstrap.tib import define_generic_cert, define_generic_data_rule
from bootstrap.mini.controller import ZoneController
from bootstrap.app_support.ca_tib import CaWithTib

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')

app = NDNApp()

# @app.route('/example/testApp')
# def on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
#     print(f'>> I: {Name.to_str(name)}, {param}')
#     content = "Hello, world!".encode()
#     app.put_data(name, content=content, freshness_period=10000)
#     print(f'<< D: {Name.to_str(name)}')
#     print(MetaInfo(freshness_period=10000))
#     print(f'Content: (size: {len(content)})')
#     print('')

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

            
async def control(cmdline_args, tmpdirname):
    zone_name = Name.from_str('/ndn/local/ucla')
    controller = ZoneController(app, tmpdirname, zone_name,
                                cmdline_args.auth, cmdline_args.issuer)
    # controller.ca.register()
    
    # controller.register_route(cmdline_args.auth, cmdline_args.issuer)
    # also write to the local dir to enable out-of-band sharing
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, 'ndn-local-ucla.bundle')
    controller.save_bundle(filename)

    async def update_bundle_after(wait_in_seconds):
        await asyncio.sleep(wait_in_seconds)
        updated_lvs = controller.get_zone_lvs()
        signer = 'Issuer' if cmdline_args.issuer else 'Anchor'
        updated_lvs += define_generic_cert(zone_name, 
                                            '/suffix1/suffix2',
                                            signee = 'EntityClass2',
                                            signer = signer)
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
        controller.update_schema(updated_lvs)
    asyncio.create_task(update_bundle_after(5))

def main () -> int:
    cmdline_args = process_cmd_opts()
    with TemporaryDirectory() as tmpdirname:
        app.run_forever(after_start=control(cmdline_args, tmpdirname))
    return 0
if __name__ == "__main__":
    sys.exit(main())
