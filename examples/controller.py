import logging, os, sys
from ndn.app import NDNApp
from ndn.encoding import Name, FormalName, Component
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS

from bootstrap.app import Controller
from bootstrap.keychain_register import attach_keychain_register_appv1

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    # datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')


app = NDNApp()
basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
tpm_path = os.path.join(basedir, 'details/ndnkeys/.ndn/ndnsec-key-file')
pib_path = os.path.join(basedir, 'details/ndnkeys/.ndn/pib.db')
tpm = TpmFile(tpm_path)
KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_path)
keychain = KeychainSqlite3(pib_path, tpm)

lvs_text = '''
#KEY: "KEY"/_/_/_
#site: "hydra"
#root: #site/#KEY
#auth_signer: #site/"auth-signer"/#KEY <= #root
#cert_signer: #site/"cert-signer"/#KEY <= #root
#BootResponse: #site/"NAA"/"BOOT"/nonce/NOTIFY/_ <= #auth_signer
#IdProofResponse: #site/"NAA"/"PROOF"/nonce/NOTIFY <= #auth_signer
#proof_of_possession5: "32=authenticate"/#site/_/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession4: "32=authenticate"/#site/_/_/_/_/#KEY <= #auth_signer
#proof_of_possession3: "32=authenticate"/#site/_/_/_/#KEY <= #auth_signer
#proof_of_possession2: "32=authenticate"/#site/_/_/#KEY <= #auth_signer
#proof_of_possession1: "32=authenticate"/#site/_/#KEY <= #auth_signer
#NewResponse: #site/"CA"/"NEW"/_ <= #cert_signer
#ChallengeResponse: #site/"CA"/"CHALLENGE"/_/_ <= #cert_signer
#Entity5: #site/_/_/_/_/_/#KEY <= #cert_signer
#Entity4: #site/_/_/_/_/#KEY <= #cert_signer
#Entity3: #site/_/_/_/#KEY <= #cert_signer
#Entity2: #site/_/_/#KEY <= #cert_signer
#Entity1: #site/_/#KEY <= #cert_signer
'''
lvs_model = compile_lvs(lvs_text)

def user_assign(email_str: str) -> FormalName:
    index = email_str.rindex("@")
    user_part = email_str[:index]
    domain_part = email_str[index + 1:]
    domain_comps = [Component.from_str(seg) for seg in domain_part.rsplit('.')]
    return Name.from_str('/hydra/32=nodes') + [Component.from_str(user_part)] + domain_comps

def server_assign(common_name: str) -> FormalName:
    return Name.from_str('/hydra/32=user/' + common_name)
    
config_path = os.path.join(basedir, 'controller.conf')
controller = Controller(app, config_path, keychain, Checker(lvs_model, DEFAULT_USER_FNS))
attach_keychain_register_appv1(keychain, app)
controller.load_name_assignment('user', user_assign)
controller.load_name_assignment('server', server_assign)
def main () -> int:
    app.run_forever(after_start=controller.route())
    return 0
if __name__ == "__main__":
    sys.exit(main())
