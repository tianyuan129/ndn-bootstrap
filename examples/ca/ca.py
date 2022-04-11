import argparse
from ndncert.util.config import get_yaml
import logging
import pkg_resources
from ndn.app import NDNApp
import os

# from app_support.tib import Tib, TibBundle
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app_support.light_versec import compile_lvs
from ndncert.ca.ca import Ca
from ndncert.app_support.tib import Tib, TibBundle

app = NDNApp()

def process_cmd_opts():
    """
    Parse, process, and return cmd options.
    """
    def print_version():
        pkg_name = 'ndncert-ca-python'
        version = pkg_resources.require(pkg_name)[0].version
        print(pkg_name + ' ' + version)

    def parse_cmd_opts():
        parser = argparse.ArgumentParser(description='ndncert-ca-python')
        parser.add_argument('-v', '--version',
                            help='print current version and exit', action='store_true')
        parser.add_argument('-c', '--config',
                            help='path to config file')
        parser.add_argument('-r', '--ca_name',
                            help="""CA's routable prefix. If this option is specified, it 
                                    overrides the prefix in the config file""")
        args = parser.parse_args()
        return args

    args = parse_cmd_opts()
    if args.version:
        print_version()
        exit(0)
    return args


def process_config(cmdline_args):
    """
    Read and process config file. Some config options are overridden by cmdline args.
    """
    config = cmdline_args.config
    if config is None:
        config = 'ndncert-ca.conf'
    config = get_yaml(config)
    if cmdline_args.ca_name != None:
        config['prefix_config']['prefix_name'] = cmdline_args.ca_name
    return config


def config_logging(config: dict):
    log_levels = {
        'CRITICAL': logging.CRITICAL,
        'ERROR': logging.ERROR,
        'WARNING': logging.WARNING,
        'INFO': logging.INFO,
        'DEBUG': logging.DEBUG
    }

    # default level is INFO
    if config['level'] not in log_levels:
        log_level = logging.INFO
    else:
        log_level = log_levels[config['level']]
    
    # default is stdout
    log_file = config['file'] if 'file' in config else None

    if not log_file:
        logging.basicConfig(format='[%(asctime)s]%(levelname)s:%(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=log_level)
    else:
        logging.basicConfig(filename=log_file,
                            format='[%(asctime)s]%(levelname)s:%(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=log_level)

def main() -> int:
    cmdline_args = process_cmd_opts()
    config = process_config(cmdline_args)
    print(config)
    config_logging(config['logging_config'])


    basedir = os.path.expanduser('~/.ndn-tib-test/')
    tpm_path = os.path.join(basedir, 'privKeys')
    pib_path = os.path.join(basedir, 'pib.db')
    keychain = KeychainSqlite3(pib_path, TpmFile(tpm_path))
    anchor_id = keychain['/ndn']
    anchor_key = anchor_id.default_key()
    
    lvs = r'''
    #KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
    #NewResponse: /site/CA/_func/_ & { _func: "NEW"} <= #anchor
    #ChaResponse: /site/CA/_func/_/_param & { _func: "CHALLENGE" } <= #anchor
    #TmpCert: /site/"auth"/_/#KEY <= #anchor
    #anchor: /site/#KEY & { site: "ndn" }
    '''
    bundle = TibBundle()
    bundle.anchor = anchor_key.default_cert().data
    bundle.schema = compile_lvs(lvs)
    
    # load the NDNApp with validator and keychain
    tib = Tib(app, bundle, '~/.ndn-tib-test/')

    try:
        Ca(app, config).go()
    except FileNotFoundError:
        print('Error: could not connect to NFD.')
    return 0

if __name__ == "__main__":
    app.run_forever(after_start=main())