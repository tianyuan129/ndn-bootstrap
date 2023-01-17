import logging, os, sys
from ndn.encoding import Name
from ndn.app import NDNApp
from ndn.security import TpmFile, KeychainSqlite3, Sha256WithEcdsaSigner
from ndn.app_support.security_v2 import parse_certificate
from ndn.app_support.light_versec import Checker, compile_lvs, DEFAULT_USER_FNS, lvs_validator

from bootstrap.ndnauth.app.name_requester import NameRequster
from bootstrap.config import get_yaml
from Cryptodome.PublicKey import ECC

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')


app = NDNApp()
basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
tpm_path = os.path.join(basedir, 'keys/.ndn/ndnsec-key-file')
tpm = TpmFile(tpm_path)
pib_path = os.path.join(basedir, 'keys/.ndn/pib.db')
KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_path)
keychain = KeychainSqlite3(pib_path, tpm)
try:
    trust_anchor_data = keychain['/ndn/site1'].default_key().default_cert().data
    trust_anchor_name = parse_certificate(trust_anchor_data).name
except:
    raise Exception('No trust anchor available')
# create a key pair first
pri_key = ECC.generate(curve=f'P-256')
pub_key = bytes(pri_key.public_key().export_key(format='DER'))
key_der = pri_key.export_key(format='DER', use_pkcs8=False)
# create a dummy signer
signer = Sha256WithEcdsaSigner('/32=authenticate/keylocator', key_der)

lvs_text = '''
#KEY: "KEY"/_/_/_
#site: "ndn"/"site1"
#root: #site/#KEY
#auth_signer: #site/"auth-signer"/#KEY <= #root
#cert_signer: #site/"cert-signer"/#KEY <= #root
#BootResponse: #site/"NAA"/"BOOT"/nonce/NOTIFY/_ <= #auth_signer
#IdProofResponse: #site/"NAA"/"PROOF"/nonce/NOTIFY <= #auth_signer
#proof_of_possession1: "32=authenticate"/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession2: "32=authenticate"/_/_/_/#KEY <= #auth_signer
#proof_of_possession3: "32=authenticate"/_/_/#KEY <= #auth_signer
#proof_of_possession4: "32=authenticate"/_/#KEY <= #auth_signer
'''
lvs_model = compile_lvs(lvs_text)
checker = Checker(lvs_model, DEFAULT_USER_FNS)
requester = NameRequster(app, lvs_validator(checker, app, trust_anchor_data))
keyname = ''
async def run():
    # get authentication, and pop    
    pop, prvkey_der = await requester.authenticate_user('/ndn/site1', '/alice', None,
        'tianyuan@cs.ucla.edu', lambda _ : '1234'
    )
    pop_data = parse_certificate(pop)
    logging.debug(f'Receiving PoP {Name.to_str(pop_data.name)}')
    # save the name-key binding
    logging.debug(f'Saving authentication key {Name.to_str(pop_data.name[:-2])} to TPM')
    tpm.save_key(pop_data.name[:-2], prvkey_der)
    max_width = 70
    from base64 import b64encode
    from math import ceil
    pop_path = os.path.join(basedir, 'authenticated.pop')
    with open(pop_path, 'w') as pop_file:
        pop_str = b64encode(pop).decode("utf-8")
        lines_needed = ceil(len(pop_str) / max_width)
        for i in range(0, lines_needed):
            line = pop_str[i * max_width : (i + 1) * max_width]  + '\n'
            pop_file.write(line)
    tpm.delete_key(pop_data.name[:-2])

    x509_chain_file = open('examples/low-level/alice-ndn-cert.pem')
    x509_prvkey_file = open('examples/low-level/alice-ndn-privkey.pem')
    pop = await requester.authenticate_server('/ndn/site1', '/alice', None,
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
