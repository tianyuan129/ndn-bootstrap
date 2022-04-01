# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
from typing import Optional

import logging, os, sys
from os import urandom

from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName
from ndn.app_support.security_v2 import parse_certificate
from ndn.security import KeychainSqlite3, TpmFile

from ndncert_proto import *
from ndncert_crypto import *

from email_challenge_actor import *

from ca_storage import *

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = NDNApp()
requests = {}
pib_file = os.path.join(os.getcwd(), 'pib.db')
tpm_dir = os.path.join(os.getcwd(), 'privKeys')
KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
ca_id = keychain.touch_identity('/ndn')
ca_cert = ca_id.default_key().default_cert().data
ca_cert_data = parse_certificate(ca_cert)
    
@app.route('/ndn/CA/NEW')
def on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
    print(f'>> I: {Name.to_str(name)}, {param}')
    request = NewRequest.parse(_app_param)
    ecdh = ECDH()
    pub = request.ecdh_pub
    csr_data = parse_certificate(request.cert_request)
    print(f'CSR name: {Name.to_str(csr_data.name)}')
    
    response = NewResponse()
    response.ecdh_pub = ecdh.pub_key_encoded
    response.salt = urandom(32)
    response.request_id = urandom(8)
    response.challenges.append("email".encode())
    
    app.put_data(name, content=response.encode(), freshness_period=10000, identity='/ndn')
    
    cert_state = CertState()
    ecdh.encrypt(bytes(pub), response.salt, response.request_id)
    cert_state.aes_key = ecdh.derived_key
    cert_state.status = STATUS_BEFORE_CHALLENGE
    cert_state.id = response.request_id
    cert_state.csr = request.cert_request
    requests[response.request_id] = cert_state
    print(f'Request ID: {response.request_id.hex()}')
    
@app.route('/ndn/CA/CHALLENGE')
def on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
    print(f'>> I: {Name.to_str(name)}, {param}')
    message_in = EncryptedMessage.parse(_app_param)
    request_id = name[-4][-8:]
    
    try:
        requests[request_id]
    except KeyError:
        print(f'Not CertState for Request ID: {response.request_id.hex()}')
        return
    cert_state = requests[request_id]
    
    payload = get_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), message_in)
    request = ChallengeRequest.parse(payload)
    
    print(len(request.selected_challenge))
    print(bytes(request.selected_challenge).decode('utf-8'))
    
    challenge_type = bytes(request.selected_challenge).decode('utf-8')
    challenge_str = challenge_type.capitalize() + 'ChallengeActor'
    # cast the corresponding challenge actor
    actor = getattr(sys.modules[__name__], challenge_str)
    # definitely not the right way to do
    actor.__init__(actor, ca_cert_data, keychain, requests)
    response, err = actor.actions[cert_state.status](actor, request, cert_state)

    cert_state.auth_mean = request.selected_challenge
    cert_state.iden_key = request.parameter_key
    cert_state.iden_value = request.parameter_value
    
    if response is not None:
        plaintext = response.encode()
        message_out, iv_counter = gen_encrypted_message(bytes(cert_state.aes_key), cert_state.iv_counter, 
                                                        bytes(cert_state.id), plaintext)
        cert_state.iv_counter = iv_counter
        app.put_data(name, content=message_out.encode(), freshness_period=10000, identity='/ndn')
    else:
        assert err is not None
        app.put_data(name, content=err.encode(), freshness_period=10000, identity='/ndn')

if __name__ == '__main__':
    ca_id = keychain.touch_identity('/ndn')
    ca_cert = ca_id.default_key().default_cert().data
    ca_cert_data = parse_certificate(ca_cert)
    app.run_forever()
