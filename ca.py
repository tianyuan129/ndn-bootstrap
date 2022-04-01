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
from urllib import response
from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, MetaInfo
from ndn.app_support.security_v2 import parse_certificate
from ndn.security import KeychainSqlite3, TpmFile
from ndncert_proto import *
from ecdh import *
import logging, os
from os import urandom
from math import floor
from tempfile import TemporaryDirectory

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = NDNApp()
requests = {}

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
    
    requests[response.request_id] = ecdh
    
    response.challenges.append("email".encode())
    ecdh.encrypt(bytes(pub), response.salt, response.request_id)
    
    print(f'Request ID: {response.request_id.hex()}')
    
    app.put_data(name, content=response.encode(), freshness_period=10000, identity='/ndn')
    
@app.route('/ndn/CA/CHALLENGE')
def on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
    print(f'>> I: {Name.to_str(name)}, {param}')
    request = EncryptedMessage.parse(_app_param)
    request_id = name[-4][-8:]
    
    iv = request.iv
    tag = request.tag
    encrypted_payload = request.payload
    print(f'IV: {iv.hex()}')
    print(f'IV len: {len(iv)}')
    print(f'TAG: {tag.hex()}')
    print(f'request: {request_id.hex()}')
    
    ecdh = requests[request_id]
    cipher = AES.new(ecdh.derived_key, AES.MODE_GCM, nonce = iv)
    cipher.update(request_id)
    payload = cipher.decrypt_and_verify(encrypted_payload, tag)
    request = ChallengeRequest.parse(payload)
    
    print(len(request.selected_challenge))
    print(bytes(request.selected_challenge).decode('utf-8'))
    
    
    param1 = Parameter()
    param1.key = 'email';
    param1.value = 'nonsense'
    
    response = ChallengeResponse()
    response.status = 1
    response.remaining_tries = 3
    response.remaining_time = 300
    iv_random = iv[:8]
    iv_counter = int.from_bytes(iv[-4:], 'big')
    print(f'iv_counter: {iv_counter}')
    
    plaintext = response.encode()
    iv_counter = iv_counter + floor((len(plaintext) + 15) / 16)
    cipher = AES.new(ecdh.derived_key, AES.MODE_GCM, nonce = bytes(iv_random) + iv_counter.to_bytes(4, 'big'))
    cipher.update(request_id)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    message = EncryptedMessage()
    message.iv = bytes(iv_random) + iv_counter.to_bytes(4, 'big')
    message.tag = tag
    message.payload = ciphertext
    app.put_data(name, content=message.encode(), freshness_period=10000, identity='/ndn')

if __name__ == '__main__':
    with TemporaryDirectory() as tmpdirname:
        pib_file = os.path.join(tmpdirname, 'pib.db')
        tpm_dir = os.path.join(tmpdirname, 'privKeys')
        KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
        keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))

        ca_id = keychain.touch_identity('/ndn')
        ca_cert = ca_id.default_key().default_cert().data
        ca_cert_data = parse_certificate(ca_cert)
        app.run_forever()
