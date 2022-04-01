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
from email import message
from datetime import datetime
from typing import Optional
from urllib import response
from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, MetaInfo
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.security import KeychainSqlite3, TpmFile
from ndncert_proto import *
from ecdh import *
from ca_storage import *
import logging, os
from os import urandom
from math import floor

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

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
    
def actions_before_challenge(message_in: EncryptedMessage, cert_state: CertState) -> EncryptedMessage:
    cipher = AES.new(cert_state.aes_key, AES.MODE_GCM, nonce = message_in.iv)
    cipher.update(cert_state.id)
    payload = cipher.decrypt_and_verify(message_in.payload, message_in.tag)
    request = ChallengeRequest.parse(payload)
    
    print(len(request.selected_challenge))
    print(bytes(request.selected_challenge).decode('utf-8'))
    
    response = ChallengeResponse()
    response.status = STATUS_CHALLENGE
    response.challenge_status = CHALLENGE_STATUS_NEED_CODE.encode()
    response.remaining_tries = 3
    response.remaining_time = 300
    iv_random = urandom(8)
    iv_counter = int.from_bytes(message_in.iv[-4:], 'big')
    print(f'iv_counter: {iv_counter}')
    
    plaintext = response.encode()
    iv_counter = iv_counter + floor((len(plaintext) + 15) / 16)
    
    print(f'aes key: {cert_state.aes_key.hex()}')
    iv = bytes(iv_random) + iv_counter.to_bytes(4, 'big')
    print(f'iv: {iv.hex()}')
        
    cipher = AES.new(bytes(cert_state.aes_key), AES.MODE_GCM, nonce = bytes(iv_random) + iv_counter.to_bytes(4, 'big'))
    cipher.update(bytes(cert_state.id))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    message_out = EncryptedMessage()
    message_out.iv = bytes(iv_random) + iv_counter.to_bytes(4, 'big')
    message_out.tag = tag
    message_out.payload = ciphertext
    
    cert_state.auth_key = "code".encode()
    cert_state.auth_value = "2345".encode()
    cert_state.status = STATUS_CHALLENGE
    cert_state.iv_counter = iv_counter
    
    requests[cert_state.id] = cert_state
    return message_out

def actions_continue_challenge(message_in: EncryptedMessage, cert_state: CertState) -> EncryptedMessage:
    cipher = AES.new(cert_state.aes_key, AES.MODE_GCM, nonce = message_in.iv)
    cipher.update(cert_state.id)
    payload = cipher.decrypt_and_verify(message_in.payload, message_in.tag)
    request = ChallengeRequest.parse(payload)
    
    print(f'key = {bytes(request.parameter_key).decode("utf-8") }')
    print(f'value = {bytes(request.parameter_value).decode("utf-8") }')
    
    if cert_state.auth_key == request.parameter_key:
        if cert_state.auth_value == request.parameter_value:
            print(f'Success, should issue certificate')
            cert_state.status = STATUS_PENDING
            csr_data = parse_certificate(cert_state.csr)
            signer = keychain.get_signer({'cert': ca_cert_data.name})
            issued_cert_name, issued_cert = derive_cert(csr_data.name[:-3], 'ndncert-python', csr_data.content, signer, datetime.utcnow(), 10000)
            cert_state.issued_cert = issued_cert
            
            response = ChallengeResponse()
            response.status = STATUS_PENDING
            response.issued_cert_name = Name.encode(issued_cert_name)
            response.forwarding_hint = Name.to_bytes('/ndn/CA')
            plaintext = response.encode()
            cert_state.iv_counter = cert_state.iv_counter + floor((len(plaintext) + 15) / 16)
            
            cipher = AES.new(bytes(cert_state.aes_key), AES.MODE_GCM, nonce = urandom(8) + cert_state.iv_counter.to_bytes(4, 'big'))
            cipher.update(bytes(cert_state.id))
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            
            message_out = EncryptedMessage()
            message_out.iv = urandom(8) + cert_state.iv_counter.to_bytes(4, 'big')
            message_out.tag = tag
            message_out.payload = ciphertext
            
            requests[cert_state.id] = cert_state
            return message_out
    return None

# map the inputs to the function blocks
actions = {STATUS_BEFORE_CHALLENGE : actions_before_challenge,
           STATUS_CHALLENGE : actions_continue_challenge
}


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
    
    encrypted_message = actions[cert_state.status](message_in, cert_state)
    app.put_data(name, content=encrypted_message.encode(), freshness_period=10000, identity='/ndn')

if __name__ == '__main__':
    ca_id = keychain.touch_identity('/ndn')
    ca_cert = ca_id.default_key().default_cert().data
    ca_cert_data = parse_certificate(ca_cert)
    app.run_forever()
