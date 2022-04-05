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
from typing import Optional, Dict
import plyvel

import logging, os, sys
from os import urandom
import asyncio
from datetime import datetime

from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName
from ndn.app_support.security_v2 import parse_certificate
from ndn.security import KeychainSqlite3, TpmFile
from ndn.utils import gen_nonce

from proto.ndncert_proto import *
from util.ndncert_crypto import *

from auth import *

from ca_storage import *

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

class Ca(object):
    def __init__(self, config: Dict):
        #todo: customize the storage type
        self.requests = {}
        
        self.approved_requests = IssuedCertStates()
        self.rejected_requests = RejectedCertStates()
        self.pending_requests = PendingCertStates()
        self.rejected_bindings = IdentityBindingList()

        self.cache = {}
        self.config = config
        self.ca_prefix = self.config['prefix_config']['prefix_name']
                
        pib_file = os.path.join(os.getcwd(), 'pib.db')
        tpm_dir = os.path.join(os.getcwd(), 'privKeys')
        KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
        self.keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
        ca_id = self.keychain.touch_identity(self.ca_prefix)
        ca_cert = ca_id.default_key().default_cert().data
        self.ca_cert_data = parse_certificate(ca_cert)
        self.db_init()

        self.app = NDNApp(keychain = self.keychain)

    # def save_db(self):
    #     """
    #     Save the state into the database.
    #     """
    #     logging.debug('Save state to DB')
    #     if self.db:
    #         wb = self.db.write_batch()
    #         wb.put(b'approved_requests', self.approved_requests.encode())
    #         wb.put(b'rejected_requests', self.rejected_requests.encode())
    #         wb.put(b'pending_requests', self.pending_requests.encode())
    #         wb.put(b'rejected_bindings', self.rejected_bindings.encode())
    #         wb.write()
    #         self.db.close()

    def db_init(self):
        logging.info("Server starts its initialization")
        # create or get existing state
        # Step One: Meta Info
        # 1. get system prefix from storage (from Level DB)
        import os
        self.db_dir = os.path.expanduser('~/.ndncert-ca-python/')
        if not os.path.exists(self.db_dir):
            os.makedirs(self.db_dir)
        self.db = plyvel.DB(self.db_dir, create_if_missing=True)
        ret = self.db.get(b'ca_prefix')
        if ret:
            logging.info(f'Found ca prefix from db: {ret.decode()}')
            self.ca_prefix = ret.decode()
        else:
            self.db.put(b'ca_prefix', self.ca_prefix.encode())

        # Step Two: App Layer Support (from Level DB)
        ret = self.db.get(b'approved_requests')
        if ret:
            logging.info('Found approved_requests from db')
            self.approved_requests = IssuedCertStates.parse(ret)
        ret = self.db.get(b'rejected_requests')
        if ret:
            logging.info('Found rejected_requests from db')
            self.rejected_requests = RejectedCertStates.parse(ret)
        ret = self.db.get(b'pending_requests')
        if ret:
            logging.info('Found pending_requests from db')
            self.pending_requests = PendingCertStates.parse(ret)
      
        ret = self.db.get(b'rejected_bindings')
        if ret:
            logging.info('Found rejected_bindings from db')
            self.rejected_bindings = IdentityBindingList.parse(ret)
        logging.info("Server finishes the step 2 initialization")
        self.db.close()

    def on_new_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
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
        for auth_method in self.config['auth_config']:
            response.challenges.append(str(auth_method).encode())
        
        print(f'{self.ca_prefix}')
        self.app.put_data(name, content=response.encode(), freshness_period=10000, identity=self.ca_prefix)
        
        cert_state = CertState()
        ecdh.encrypt(bytes(pub), response.salt, response.request_id)
        cert_state.aes_key = ecdh.derived_key
        cert_state.status = STATUS_BEFORE_CHALLENGE
        cert_state.id = response.request_id
        cert_state.csr = request.cert_request
        self.requests[response.request_id] = cert_state
        print(f'Request ID: {response.request_id.hex()}')

        self.pending_requests.states.append(cert_state)
        self.db = plyvel.DB(self.db_dir)
        self.db.put(b'pending_requests', self.pending_requests.encode())
        self.db.close()
        
    def on_challenge_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        logging.info(f'>> I: {Name.to_str(name)}, {param}')
        message_in = EncryptedMessage.parse(_app_param)
        request_id = name[-4][-8:]
        
        try:
            self.requests[request_id]
        except KeyError:
            print(f'Not CertState for Request ID: {response.request_id.hex()}')
            return
        cert_state = self.requests[request_id]
        
        payload = get_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), message_in)
        request = ChallengeRequest.parse(payload)
        challenge_type = bytes(request.selected_challenge).decode('utf-8')
        
        # if challenge not available
        if not challenge_type in self.config['auth_config']:
            print(f'challenge not available')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            self.app.put_data(name, content=err.encode(), freshness_period=10000, identity=self.ca_prefix)
            return
        
        challenge_str = challenge_type.capitalize() + 'Authenticator'
        # cast the corresponding challenge actor
        actor = getattr(sys.modules[__name__], challenge_str)
        # definitely not the right way to do
        actor.__init__(actor, self.ca_cert_data, self.keychain, self.requests, self.config)
        response, err = actor.actions[cert_state.status](actor, request, cert_state)

        cert_state.auth_mean = request.selected_challenge
        cert_state.iden_key = request.parameter_key
        cert_state.iden_value = request.parameter_value
        
        if response is not None:            
            plaintext = response.encode()
            message_out, iv_counter = gen_encrypted_message(bytes(cert_state.aes_key), cert_state.iv_counter, 
                                                            bytes(cert_state.id), plaintext)
            cert_state.iv_counter = iv_counter
            self.app.put_data(name, content=message_out.encode(), freshness_period=10000, identity=self.ca_prefix)
            
            if cert_state.issued_cert is not None:
                issued_name = parse_certificate(cert_state.issued_cert)
                self.cache[Name.to_bytes(issued_name.name)] = cert_state.issued_cert

            # success, put into the approved list
            self.approved_requests.states.append(cert_state)
            self.db = plyvel.DB(self.db_dir)
            self.db.put(b'approved_requests', self.approved_requests.encode())
            self.db.close()
        else:
            assert err is not None          
            self.app.put_data(name, content=err.encode(), freshness_period=10000, identity=self.ca_prefix)
            # rejected, put into the rejected list
            self.rejected_requests.states.append(cert_state)
            self.db = plyvel.DB(self.db_dir)
            self.db.put(b'rejected_requests', self.rejected_requests.encode())

            # collect the identity binding
            csr_name = parse_certificate(cert_state.csr).name
            identity_name = csr_name[:-4]

            binding = IdentityBinding()
            binding.id = gen_nonce()
            binding.auth_mean = cert_state.auth_mean
            binding.iden_key = cert_state.iden_key
            binding.iden_value= cert_state.iden_value
            binding.name = identity_name
            binding.timestamp = int(datetime.utcnow().timestamp())

            db_result = self.db.get(b'rejected_bindings')
            if db_result:
               self.rejected_bindings = IdentityBindingList.parse(db_result)

            not_found = True
            for rejected in self.rejected_bindings.bindings:
                if binding.auth_mean == rejected.auth_mean and \
                   binding.iden_key == rejected.iden_key and \
                   binding.iden_value == rejected.iden_value and \
                   binding.name == rejected.name:
                    not_found = False
            if not_found:
                self.rejected_bindings.bindings.append(binding)
                print('appeneded')
            self.db.put(b'rejected_bindings', self.rejected_bindings.encode())
            self.db.close()
        
    def _on_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        # dispatch to corresponding handlers
        if Name.is_prefix(self.ca_prefix + '/CA/NEW', name):
            self.on_new_interest(name, param, _app_param)
            return
        if Name.is_prefix(self.ca_prefix + '/CA/CHALLENGE', name):
            self.on_challenge_interest(name, param, _app_param)
            return
        
        # check whether can respond from cert cache
        try:
            self.cache[Name.to_bytes(name)]
        except KeyError:
            return
        self.app.put_raw_packet(self.cache[Name.to_bytes(name)])
        
    def go(self):
        self.app.route(self.ca_prefix)(self._on_interest)
        self.app.run_forever()