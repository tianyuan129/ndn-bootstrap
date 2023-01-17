import logging, os, sys, yaml
from datetime import datetime
from ndn.app import NDNApp
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS, lvs_validator

from bootstrap.ndncert.app.cert_issuer import CertIssuer
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
keychain = KeychainSqlite3(pib_path, tpm)

lvs_text = '''
#KEY: "KEY"/_/_/_
#site: "ndn"/"site1"
#root: #site/#KEY
#auth_signer: #site/"auth-signer"/#KEY <= #root
#cert_signer: #site/"cert-signer"/#KEY <= #root
#proof_of_possession1: "32=authenticate"/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession2: "32=authenticate"/_/_/_/#KEY <= #auth_signer
#proof_of_possession3: "32=authenticate"/_/_/#KEY <= #auth_signer
#proof_of_possession4: "32=authenticate"/_/#KEY <= #auth_signer
#NewResponse1: #site/"AA"/"NEW"/_ <= #auth_signer
#AuthenticateResponse: #site/"AA"/"AUTHENTICATE"/_/_ <= #auth_signer
#NewResponse2: #site/"CA"/"NEW"/_ <= #cert_signer
#ChallengeResponse: #site/"CA"/"CHALLENGE"/_/_ <= #cert_signer
#EduEntity: /edu/_/_/_/#KEY <= #cert_signer
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
    cert_signer_key = keychain['/ndn/site1/cert-signer'].default_key()
except:
    cert_signer_key = keychain.touch_identity('/ndn/site1/cert-signer').default_key()
    
    
cert_signer_default_cert = parse_certificate(cert_signer_key.default_cert().data)
if not checker.check(cert_signer_default_cert.name, 
                     cert_signer_default_cert.signature_info.key_locator.name):
    cert_signer_pubkey = cert_signer_default_cert.content
    cert_signer_cert_name, cert_signer_cert_data = \
        derive_cert(cert_signer_key.name, 'root', cert_signer_pubkey,
                    tpm.get_signer(cert_name[:-2], cert_name), datetime.utcnow(), 10000)
    keychain.import_cert(cert_signer_key.name, cert_signer_cert_name, cert_signer_cert_data)
    cert_signer_key.set_default_cert(cert_signer_cert_name)

config_path = os.path.join(basedir, 'cert_server.conf')
config = get_yaml(config_path)

issuer = CertIssuer(app, config, keychain, checker, lvs_validator(checker, app, cert_data))
    
def main () -> int:
    app.run_forever(after_start=issuer.register())
    return 0
if __name__ == "__main__":
    sys.exit(main())
