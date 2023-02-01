import logging, os, sys
from ndn.encoding import Name
from ndn.app import NDNApp
from ndn.security import TpmFile, KeychainSqlite3, Sha256WithEcdsaSigner
from ndn.app_support.security_v2 import parse_certificate
from ndn.app_support.light_versec import Checker, compile_lvs, DEFAULT_USER_FNS, lvs_validator

from bootstrap.app import Entity
from bootstrap.config import get_yaml


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    # datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = NDNApp()
basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
tpm_path = os.path.join(basedir, 'details/ndnkeys/.ndn/ndnsec-key-file')
tpm = TpmFile(tpm_path)
pib_path = os.path.join(basedir, 'details/ndnkeys/.ndn/pib.db')
KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_path)
keychain = KeychainSqlite3(pib_path, tpm)
try:
    trust_anchor_data = keychain['/ndn/site1'].default_key().default_cert().data
    trust_anchor_name = parse_certificate(trust_anchor_data).name
except:
    raise Exception('No trust anchor available')

lvs_text = '''
#KEY: "KEY"/_/_/_
#site: "ndn"/"site1"
#root: #site/#KEY
#auth_signer: #site/"auth-signer"/#KEY <= #root
#cert_signer: #site/"cert-signer"/#KEY <= #root
#BootResponse: #site/"NAA"/"BOOT"/nonce/NOTIFY/_ <= #auth_signer
#IdProofResponse: #site/"NAA"/"PROOF"/nonce/NOTIFY <= #auth_signer
#proof_of_possession1: "32=authenticate"/_/_/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession2: "32=authenticate"/_/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession3: "32=authenticate"/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession4: "32=authenticate"/_/_/_/#KEY <= #auth_signer
#proof_of_possession5: "32=authenticate"/_/_/#KEY <= #auth_signer
#proof_of_possession6: "32=authenticate"/_/#KEY <= #auth_signer
#NewResponse: #site/"CA"/"NEW"/_ <= #cert_signer
#ChallengeResponse: #site/"CA"/"CHALLENGE"/_/_ <= #cert_signer
#Entity5: #site/_/_/_/_/_/#KEY <= #cert_signer
#Entity4: #site/_/_/_/_/#KEY <= #cert_signer
#Entity3: #site/_/_/_/#KEY <= #cert_signer
#Entity2: #site/_/_/#KEY <= #cert_signer
#Entity1: #site/_/#KEY <= #cert_signer
'''
async def run():
    lvs_model = compile_lvs(lvs_text)
    checker = Checker(lvs_model, DEFAULT_USER_FNS)
    entity = Entity(app, keychain, checker, lvs_validator(checker, app, trust_anchor_data))
    # user authentication and certification
    await entity.get_user_certified('/ndn/site1', '/alice', None, 
        'tianyuan@cs.ucla.edu', lambda _ : input("Please enter the email verification code: ")
    )
    
    # server authentication and certification
    x509_chain_file = open('examples/details/alice-ndn-cert.pem')
    x509_prvkey_file = open('examples/details/alice-ndn-privkey.pem')
    await entity.get_server_certified('/ndn/site1', '/alice', None,
        bytes(x509_chain_file.read(), 'utf-8'), 
        bytes(x509_prvkey_file.read(), 'utf-8')
    )
    x509_chain_file.close()
    x509_prvkey_file.close()
    app.shutdown()

def main () -> int:
    app.run_forever(after_start=run())
if __name__ == "__main__":
    sys.exit(main())
