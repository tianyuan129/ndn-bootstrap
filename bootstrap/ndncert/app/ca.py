from typing import Optional, Dict
import plyvel

import logging, sys
from os import urandom
import asyncio
from datetime import datetime

from ndn.app import NDNApp
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName
from ndn.app_support.security_v2 import parse_certificate
from ndn.security import KeychainSqlite3
from ndn.utils import gen_nonce

from ..proto.ndncert_proto import *
from ..utils.ndncert_crypto import *
from ..proto.ca_storage import *
from ..proto.types import GetSigner

from ..auth import *

class Ca(object):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3,
                 get_signer: GetSigner):
        #todo: customize the storage type
        self.requests = {}
        
        self.approved_requests = IssuedCertStates()
        self.rejected_requests = RejectedCertStates()
        self.pending_requests = PendingCertStates()
        self.rejected_bindings = IdentityBindingList()

        self.cache = {}
        self.config = config
        self.ca_prefix = self.config['prefix_config']['prefix_name']
        # self.tib = tib
        self.keychain = keychain
        
        # keychain or tib based signer
        self.get_signer = get_signer

        try:
            ca_id = self.keychain[self.ca_prefix]
            ca_cert = ca_id.default_key().default_cert().data
            self.ca_cert_data = parse_certificate(ca_cert)
        except:
            ca_id = self.keychain.touch_identity(self.ca_prefix)
            ca_cert = ca_id.default_key().default_cert().data
            self.ca_cert_data = parse_certificate(ca_cert)

        # save to db base
        path = os.path.expanduser(config['db_config']['base'])
        self.db_init(path)
        self.app = app
        app.keychain = self.keychain

    def db_init(self, basedir):
        logging.info("Server starts its initialization")
        # create or get existing state
        # Step One: Meta Info
        # 1. get system prefix from storage (from Level DB)
        import os
        self.db_dir = os.path.join(basedir, 'ndncert-ca')
        if not os.path.exists(self.db_dir):
            os.makedirs(self.db_dir)
        self.db = plyvel.DB(self.db_dir, create_if_missing=True)

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

    async def on_new_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}, {param}')
        request = NewRequest.parse(_app_param)
        ecdh = ECDH()
        pub = request.ecdh_pub
        csr_data = parse_certificate(request.cert_request)
        logging.info(f'CSR name: {Name.to_str(csr_data.name)}')
        
        response = NewResponse()
        response.ecdh_pub = ecdh.pub_key_encoded
        response.salt = urandom(32)
        response.request_id = urandom(8)
        for auth_method in self.config['auth_config']:
            if str(auth_method) != 'operator_email':
                response.challenges.append(str(auth_method).encode())
                
        # raw_pkt = self.tib.sign_data(name, response.encode(), freshness_period=10000)
        self.app.put_data(name, response.encode(), freshness_period = 10000,
                          signer = self.get_signer(name))

        cert_state = CertState()
        ecdh.encrypt(bytes(pub), response.salt, response.request_id)
        cert_state.aes_key = ecdh.derived_key
        cert_state.status = STATUS_BEFORE_CHALLENGE
        cert_state.id = response.request_id
        cert_state.csr = request.cert_request
        self.requests[response.request_id] = cert_state
        logging.info(f'Request ID: {response.request_id.hex()}')

        self.pending_requests.states.append(cert_state)
        self.db = plyvel.DB(self.db_dir)
        self.db.put(b'pending_requests', self.pending_requests.encode())
        self.db.close()
        logging.debug(f'Putting this CSR into Pending Requests list')
        
    async def on_challenge_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        logging.debug(f'>> I: {Name.to_str(name)}, {param}')
        message_in = EncryptedMessage.parse(_app_param)
        request_id = name[len(Name.from_str(self.ca_prefix)) + 2][-8:]

        try:
            self.requests[request_id]
        except KeyError:
            logging.error(f'Not CertState for Request ID: {request_id.hex()}')
            return
        cert_state = self.requests[request_id]

        # checking iv counters
        payload = get_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), message_in)
        request = ChallengeRequest.parse(payload)
        
        challenge_type = ''
        if cert_state.auth_mean:
            challenge_type = bytes(cert_state.auth_mean).decode()
        else:
            challenge_type = bytes(request.selected_challenge).decode('utf-8')
            cert_state.auth_mean = challenge_type.encode()
        
        # if challenge not available
        if not challenge_type in self.config['auth_config']:
            logging.error(f'Challenge not available')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            self.app.put_data(name, errs.encode(), freshness_period = 10000,
                              signer = self.get_signer(name))
            return
        
        challenge_str = challenge_type.capitalize() + 'Authenticator'
        # cast the corresponding challenge actor
        actor = getattr(sys.modules[__name__], challenge_str)
        # definitely not the right way to do
        actor.__init__(actor, self.app, self.requests, self.config, self.db_dir, self.get_signer)
        
        response, err = await actor.actions[cert_state.status](actor, request, cert_state)

        cert_state.auth_mean = request.selected_challenge
        cert_state.iden_key = request.parameter_key
        cert_state.iden_value = request.parameter_value
        
        if response is not None:            
            plaintext = response.encode()
            # todo: iv handlings should tolerate concurrent requests
            try: 
                iv_random = self.iv_random
            except AttributeError:
                self.iv_random = None
            try: 
                iv_random = self.iv_counter
            except AttributeError:
                self.iv_counter = None

            message_out, self.iv_random, self.iv_counter =\
                gen_encrypted_message(bytes(cert_state.aes_key), bytes(cert_state.id), 
                plaintext, self.iv_random, self.iv_counter)

            cert_state.iv_counter = self.iv_counter
            self.app.put_data(name, message_out.encode(), freshness_period = 10000,
                              signer = self.get_signer(name))
            if cert_state.issued_cert is not None:
                issued_cert = parse_certificate(cert_state.issued_cert)
                self.cache[Name.to_bytes(issued_cert.name)] = cert_state.issued_cert
                
                # create an window for cert retrieval
                logging.debug(f'Register a short-lived interest filter to allow retrieve '
                              f'{Name.to_str(issued_cert.name)}...')
                asyncio.ensure_future(self.serve_cert(issued_cert.name))

            # success, put into the approved list
            self.approved_requests.states.append(cert_state)
            self.db = plyvel.DB(self.db_dir)
            self.db.put(b'approved_requests', self.approved_requests.encode())
            self.db.close()
        if err is not None:
            assert err is not None
            self.app.put_data(name, err.encode(), freshness_period = 10000,
                              signer = self.get_signer(name))
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
            self.db.put(b'rejected_bindings', self.rejected_bindings.encode())
            self.db.close()
        
    def _on_interest(self, name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr]):
        # dispatch to corresponding handlers
        if Name.is_prefix(self.ca_prefix + '/CA/NEW', name):
            asyncio.create_task(self.on_new_interest(name, param, _app_param))
            return
        if Name.is_prefix(self.ca_prefix + '/CA/CHALLENGE', name):
            asyncio.create_task(self.on_challenge_interest(name, param, _app_param))
            return
        
        # check whether can respond from cert cache
        try:
            self.cache[Name.to_bytes(name)]
        except KeyError:
            return
        self.app.put_raw_packet(self.cache[Name.to_bytes(name)])

    async def serve_cert(self, name: FormalName):
        self.app.set_interest_filter(name, lambda int_name, param, _app_param:
            self.app.put_raw_packet(self.cache[Name.to_bytes(int_name)])
        )
        await asyncio.sleep(5)
        self.app.unset_interest_filter(name)
        logging.info(f'Unregister the interest filter for {Name.to_str(name)}...')
        logging.debug(f'Clear the cache...')
        self.cache.pop(Name.to_bytes(name))

    def register(self):
        logging.debug(f'Registers for {Name.to_str(self.ca_prefix + "/CA")}')
        
        # self.app.route(self.ca_prefix + '/CA')(None)
        # self.app.set_interest_filter(self.ca_prefix + '/CA', self._on_interest)
        
        @self.app.route(self.ca_prefix + '/CA')
        def _on_interest(name: FormalName, param: InterestParam, _app_param: Optional[BinaryStr] | None):
            logging.debug(f'inside...')
            # dispatch to corresponding handlers
            if Name.is_prefix(self.ca_prefix + '/CA/NEW', name):
                asyncio.create_task(self.on_new_interest(name, param, _app_param))
                return
            if Name.is_prefix(self.ca_prefix + '/CA/CHALLENGE', name):
                asyncio.create_task(self.on_challenge_interest(name, param, _app_param))
                return
            
            # check whether can respond from cert cache
            try:
                self.cache[Name.to_bytes(name)]
            except KeyError:
                return
            self.app.put_raw_packet(self.cache[Name.to_bytes(name)])