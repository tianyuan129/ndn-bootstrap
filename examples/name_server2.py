import logging, os, sys, yaml
from datetime import datetime
from ndn.app import NDNApp
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS, lvs_validator

from bootstrap.ndnauth.app.name_aa import NameAuthAssign
from bootstrap.config import get_yaml

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')


app = NDNApp()
basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
tpm_path = os.path.join(basedir, 'keys/.ndn/ndnsec-key-file')
pib_path = os.path.join(basedir, 'keys/.ndn/pib.db')
tpm = TpmFile(tpm_path)
KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_path)
keychain = KeychainSqlite3(pib_path, tpm)

lvs_text = '''
#KEY: "KEY"/_/_/_
#site: "ndn"/"site1"
#root: #site/#KEY
#auth_signer: #site/"auth-signer"/#KEY <= #root
#BootResponse: #site/"NAA"/"BOOT"/nonce/NOTIFY/_ <= #auth_signer
#IdProofResponse: #site/"NAA"/"PROOF"/nonce/NOTIFY <= #auth_signer
#proof_of_possession1: "32=authenticate"/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession2: "32=authenticate"/_/_/_/#KEY <= #auth_signer
'''

lvs_model = compile_lvs(lvs_text)
checker = Checker(lvs_model, DEFAULT_USER_FNS)

try:
    cert_data = keychain['/ndn/site1'].default_key().default_cert().data
    cert_name = parse_certificate(cert_data).name
except:
    keychain.touch_identity('/ndn/site1')
    cert_data = keychain['/ndn/site1'].default_key().default_cert().data
    cert_name = parse_certificate(cert_data).name
 
try:
    auth_signer_key = keychain['/ndn/site1/auth-signer'].default_key()
except:
    auth_signer_key = keychain.touch_identity('/ndn/site1/auth-signer').default_key()
    
    
auth_signer_default_cert = parse_certificate(auth_signer_key.default_cert().data)
if not checker.check(auth_signer_default_cert.name, 
                     auth_signer_default_cert.signature_info.key_locator.name):
    auth_signer_pubkey = auth_signer_default_cert.content
    auth_signer_cert_name, auth_signer_cert_data = \
        derive_cert(auth_signer_key.name, 'root', auth_signer_pubkey,
                    tpm.get_signer(cert_name[:-2], cert_name), datetime.utcnow(), 10000)
    keychain.import_cert(auth_signer_key.name, auth_signer_cert_name, auth_signer_cert_data)
    auth_signer_key.set_default_cert(auth_signer_cert_name)

config_path = os.path.join(basedir, 'name_server2.conf')
config = get_yaml(config_path)

aa = NameAuthAssign(app, config, keychain, checker, lvs_validator(checker, app, cert_data))
    
def main () -> int:
    app.run_forever(after_start=aa.register())
    return 0
if __name__ == "__main__":
    sys.exit(main())
