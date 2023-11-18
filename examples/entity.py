import logging, os, sys, aiohttp, json, asyncio
from ndn.encoding import Name
from aiohttp import web
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
    trust_anchor_data = keychain['/hydra'].default_key().default_cert().data
    trust_anchor_name = parse_certificate(trust_anchor_data).name
except:
    raise Exception('No trust anchor available')

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

id_token = '''
eyJhbGciOiJSUzI1NiIsImtpZCI6IjA1MTUwYTEzMjBiOTM5NWIwNTcxNjg3NzM3NjkyODUwOWJhYjQ0YWMiLCJ0eXA
iOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3NjQwODYwNTE4NTAtNnF
yNHA2Z3BpNmhuNTA2cHQ4ZWp1cTgzZGkzNDFodXIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI3Nj
QwODYwNTE4NTAtNnFyNHA2Z3BpNmhuNTA2cHQ4ZWp1cTgzZGkzNDFodXIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb
20iLCJzdWIiOiIxMDU5Njk3NzQxODc5NjcxMzQwNTkiLCJoZCI6ImcudWNsYS5lZHUiLCJlbWFpbCI6InJveXUyOUBn
LnVjbGEuZWR1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIzQl9ZVUlPMU1oWWZ2UmVKSm4zY25BIiw
ibmFtZSI6IlRJQU5ZVUFOIFlVIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0
FBY0hUdGNQekJoek8wVUZ5NkFoSEd5MlhWRVpwS3dXcGwxcDBpUzdVNzZHPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IlRJQ
U5ZVUFOIiwiZmFtaWx5X25hbWUiOiJZVSIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjg2OTc3MzA4LCJleHAiOjE2ODY5
ODA5MDh9.wsh9v9KSRykOsb48sppCj5-FxVCO1cRgL2MEI4JKGTloBeetmgzgWjvY-MmmLtOIhB-aoIX6iO7sCLZCFg
Oa6ijg45t73KC54e0tV4TQB5ssd5klUcUBit2YA074TdArUVcM-huO3zchNuoRJIA-1-PcFgkIQSSiwPXzMTR4DDPm6
hpUSSVpqsIyxp4ufvc-mO-ggClF741OAbcAR-kMNXDcL__pmLkjIEN3pz8XfUdhByEpx5buFbMZc_U0B9K4O6R8ubGY
hAj7gEfgbZ90_FfQubeWJ4MKQHzLDfVnBwxURvz81zhGxlBGD9NybuaRyhFd2R2J7tLEFWBx-ZQmDg
'''

CLIENT_ID = '764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com'
CLIENT_SECRET = 'd-FL95Q19q7MQmFpd7hHD0Ty'

async def exchange_token(code: str):
    async with aiohttp.ClientSession() as session:
        data = {
            'code': code,
            'redirect_uri': 'http://localhost:8085/',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'scope': 'openid',
            'grant_type': 'authorization_code',
        }
        async with session.post('https://oauth2.googleapis.com/token', data=data) as resp:
            print('Response status:', resp.status)
            token_json = await resp.text()

        print('Response tokens (JSON):')
        print(token_json)
        print()
        token_dict = json.loads(token_json)
        return token_dict['id_token']


async def oidc_prover(oidc_auth_uri):
    id_token = None
    async def handler(request: web.Request):
        global id_token
        query = request.query
        print('code=', query['code'])
        id_token = await exchange_token(query['code'])
        return web.Response(text="Done")

    print(oidc_auth_uri)
    if sys.platform == "darwin":
        os.spawnlp(os.P_NOWAIT, 'open', 'open', oidc_auth_uri)
    else:
        os.spawnlp(os.P_NOWAIT, 'xdg-open', 'xdg-open', oidc_auth_uri)

    web_app = web.Application()
    web_app.add_routes([web.get('/', handler)])
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8085)
    await site.start()
    while not id_token:
        await asyncio.sleep(0.001)  # sleep forever
    await web_app.shutdown()
    await web_app.cleanup()
    return id_token

async def run():
    lvs_model = compile_lvs(lvs_text)
    checker = Checker(lvs_model, DEFAULT_USER_FNS)
    entity = Entity(app, keychain, checker, lvs_validator(checker, app, trust_anchor_data))
    # user authentication and certification
    await entity.get_oidc_certified('/hydra', '/alice', None, 
        'royu29@g.ucla.edu', "google", oidc_prover
    )
    # await entity.get_user_certified('/hydra', '/alice', None, 
    #     'tianyuan@cs.ucla.edu', lambda _ : input("Please enter the email verification code: ")
    # )
    
    # # server authentication and certification
    # x509_chain_file = open('examples/details/alice-ndn-cert.pem')
    # x509_prvkey_file = open('examples/details/alice-ndn-privkey.pem')
    # await entity.get_server_certified('/hydra', '/alice', None,
    #     bytes(x509_chain_file.read(), 'utf-8'), 
    #     bytes(x509_prvkey_file.read(), 'utf-8')
    # )
    # x509_chain_file.close()
    # x509_prvkey_file.close()
    app.shutdown()

def main () -> int:
    app.run_forever(after_start=run())
if __name__ == "__main__":
    sys.exit(main())
