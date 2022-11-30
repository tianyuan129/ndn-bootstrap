import logging, os, sys, asyncio
from ndn.encoding import Name, InterestParam
from ndn.app import NDNApp
from ndn.security import TpmFile, KeychainSqlite3, Sha256WithEcdsaSigner
from ndn.app_support.security_v2 import parse_certificate
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS, lvs_validator

from bootstrap.ndncert.app.cert_requester import CertRequester
from bootstrap.types import ProtoError
from Cryptodome.PublicKey import ECC
from base64 import b64decode

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')


app = NDNApp()
basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
tpm_path = os.path.join(basedir, 'keys/.ndn/ndnsec-key-file')
tpm = TpmFile(tpm_path)
pib_path = os.path.join(basedir, 'keys/.ndn/pib.db')
keychain = KeychainSqlite3(pib_path, tpm)
try:
    trust_anchor_data = keychain['/ndn/site1'].default_key().default_cert().data
    trust_anchor_name = parse_certificate(trust_anchor_data).name
except:
    raise Exception('No trust anchor available')

# read pop
filename = os.path.join(basedir, 'authenticated.pop')
pop_str = ''
with open(filename, 'r') as pop_file:
    for line in pop_file.readlines():
        pop_str += line
pop_wire = b64decode(pop_str)
assigned_keyname = parse_certificate(pop_wire).name[:-2]
assigned_name = assigned_keyname[1:-2]
logging.info(f'get assigned name {Name.to_str(assigned_name)} from pop')

# prepare keychain
try:
    csr_data = keychain[assigned_name].default_key().default_cert().data
except:
    keychain.touch_identity(assigned_name)
    csr_data = keychain[assigned_name].default_key().default_cert().data
csr_name = parse_certificate(csr_data).name

lvs_text = '''
#KEY: "KEY"/_/_/_
#site: "ndn"/"site1"
#root: #site/#KEY
#auth_signer: #site/"auth-signer"/#KEY <= #root
#cert_signer: #site/"cert-signer"/#KEY <= #root
#proof_of_possession1: "32=authenticate"/_/_/_/_/#KEY <= #cert_signer
#proof_of_possession2: "32=authenticate"/_/_/_/#KEY <= #cert_signer
#NewResponse1: #site/"AA"/"NEW"/_ <= #cert_signer
#AuthenticateResponse: #site/"AA"/"AUTHENTICATE"/_/_ <= #cert_signer
#NewResponse2: #site/"CA"/"NEW"/_ <= #cert_signer
#ChallengeResponse: #site/"CA"/"CHALLENGE"/_/_ <= #cert_signer
#EduEntity: /edu/_/_/_/#KEY <= #cert_signer
'''

lvs_model = compile_lvs(lvs_text)
checker = Checker(lvs_model, DEFAULT_USER_FNS)
data_validator = lvs_validator(checker, app, trust_anchor_data)
async def run():
    def select_first(lst):
        if 'possession' in lst:
            return 'possession', 'issued-cert'.encode(), pop_wire
        else:
            raise ProtoError

    def pop_prover(challenge_status, param_key, param_value):
        assert bytes(challenge_status).decode() == 'need-proof'
        assert bytes(param_key).decode() == 'nonce'
        nonce_signer = tpm.get_signer(assigned_keyname)
        wire = bytearray(70)
        assert nonce_signer.write_signature_value(wire, [memoryview(param_value)]) == len(wire)
        return 'proof'.encode(), bytes(wire)
    requester = CertRequester(app, checker, data_validator)
    issued_cert_name, forwarding_hint = \
        await requester.request_signing('/ndn/site1', csr_data, tpm.get_signer(csr_name[:-2], csr_name),
                                        select_first, pop_prover)
    issued_cert_name = Name.from_bytes(bytes(issued_cert_name))
    logging.info(f'{Name.to_str(forwarding_hint)}')
    interest_param = InterestParam()
    interest_param.forwarding_hint = [forwarding_hint]
    _, _, _, issued_cert = await app.express_interest(issued_cert_name, validator=data_validator,
                                                      interest_param=interest_param,
                                                      need_raw_packet=True)
    keychain.import_cert(issued_cert_name[:-2], issued_cert_name, issued_cert)
                
def main () -> int:
    app.run_forever(after_start=run())
if __name__ == "__main__":
    sys.exit(main())
