from typing import Optional, Dict, Coroutine

import logging, sys, time
from os import urandom
import asyncio
from datetime import datetime

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, Component, parse_tl_num
from ndn.app_support.security_v2 import parse_certificate, KEY_COMPONENT, derive_cert
from ndn.app_support.keychain_register import attach_keychain_register
from ndn.app_support.light_versec import Checker
from ndn.security import KeychainSqlite3

from ..protocol import *
from ...crypto_tools import *
from ..name_auth import *
from ..name_assign import *
from ..auth_state import *
from ..mode_encoder import *
from ...keychain_register import attach_keychain_register_appv1
_POSITION_NONCE_IN_BOOT_NOTIFICATION = -3
_POSITION_NONCE_IN_PROOF_NOTIFICATION = -2

class NameAuthAssign(object):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3,
                 checker: Checker, validator: Validator):
        #todo: customize the storage type
        self.entities_cache = {}
        self.entities_storage = {}
        self.config = config
        self.aa_prefix = self.config['prefix_config']['prefix_name']
        self.keychain = keychain
        self.checker = checker
        self.data_validator = validator

        try:
            aa_id = self.keychain[self.aa_prefix]
            aa_cert = aa_id.default_key().default_cert().data
            self.aa_cert_data = parse_certificate(aa_cert)
        except:
            aa_id = self.keychain.touch_identity(self.aa_prefix)
            aa_cert = aa_id.default_key().default_cert().data
            self.aa_cert_data = parse_certificate(aa_cert)

        self.app = app
        app.keychain = self.keychain
        attach_keychain_register_appv1(self.keychain, self.app)

        # initialize membership checker, authenticator, and name assigner
        self.membership_checkers = {}
        self.authenticators = {}
        self.name_assigners = {}

        auth_configs = config['auth_config']
        for auth_type in auth_configs:
            config_section = auth_configs[auth_type]

            # locate the corresponding membership checker
            checker_type_str = auth_type.capitalize() + 'MembershipChecker'
            membership_checker_type = getattr(sys.modules[__name__], checker_type_str)
            membership_checker = object.__new__(membership_checker_type, config_section['membership_checker'])
            membership_checker.__init__(config_section['membership_checker'])
            self.membership_checkers[auth_type.capitalize()] = membership_checker
            
            authenticator_type_str = auth_type.capitalize() + 'Authenticator'
            authenticator_type = getattr(sys.modules[__name__], authenticator_type_str)
            authenticator = object.__new__(authenticator_type, config_section['authenticator'])
            authenticator.__init__(config_section['authenticator'])
            self.authenticators[auth_type.capitalize()] = authenticator

            name_assigner_type_str = auth_type.capitalize() + 'NameAssigner'
            name_assigner_type = getattr(sys.modules[__name__], name_assigner_type_str)
            name_assigner = object.__new__(name_assigner_type, config_section['name_assigner'])
            name_assigner.__init__(config_section['name_assigner'])
            self.name_assigners[auth_type.capitalize()] = name_assigner

    def _get_signer(self, name):
        suggested_keylocator = self.checker.suggest(name, self.keychain)
        if suggested_keylocator is None:
            logging.error(f'No proper keylocator for {Name.to_str(name)}')
            return None
        else:
            return self.keychain.tpm.get_signer(suggested_keylocator[:-2], suggested_keylocator)

    async def on_boot_notification(self, name, _app_param):
        nonce = Component.to_number(name[_POSITION_NONCE_IN_BOOT_NOTIFICATION])
        logging.debug(f'Received Nonce: {nonce}')
        connect_info = ConnectvityInfo.parse(_app_param)
        
        local_prefix_str = Name.to_str(Name.from_bytes(connect_info.local_prefix))
        local_forwarder_str = ''
        if connect_info.local_forwarder is not None:
            local_forwarder_str = Name.to_str(Name.from_bytes(connect_info.local_forwarder))

        self.entities_cache[nonce] = {'connect_info': [local_prefix_str, local_forwarder_str]}
        logging.debug(f'ConnectInfo: LocalPrefix {local_prefix_str}, LocalForwarder {local_forwarder_str}')
        # /<local-prefix>/NAA/BOOT/<nonce>/MSG
        boot_params_name = Name.from_str(local_prefix_str + '/NAA/BOOT') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        interest_param = InterestParam()
        interest_param.forwarding_hint = [connect_info.local_forwarder]
        time.sleep(0.01)
        data_name, _, content = await self.app.express_interest(
            boot_params_name,  must_be_fresh=True, can_be_prefix=False, lifetime=6000)
        
        # find specific encoder
        tlv_type, _ = parse_tl_num(content)
        encoder_type_str = find_encoder(tlv_type)
        encoder_type = getattr(sys.modules[__name__], encoder_type_str)
        encoder = object.__new__(encoder_type, nonce)
        encoder.__init__(nonce)
        self.entities_cache[nonce] |= {'encoder': encoder, 'encoder_type': encoder_type_str}
        
        # parsing boot params and preparing response
        encoder.parse_boot_params(content)
        
        auth_type_str = encoder_type_str[:encoder_type_str.find('ModeEncoder')]
        membership_checker = self.membership_checkers[auth_type_str]
        encoder.auth_state = await membership_checker.check(encoder.auth_state)
        if not encoder.auth_state.is_member:
            logging.error(f'Authentication id permission denied')
            errs = ErrorMessage()
            errs.code = ERROR_INVALID_PARAMTERS[0]
            errs.info = ERROR_INVALID_PARAMTERS[1].encode()
            return
    
        authenticator = self.authenticators[auth_type_str]
        encoder.auth_state, err = await authenticator.after_receive_boot_params(encoder.auth_state)
        self.app.put_data(name, content=encoder.prepare_boot_response(), freshness_period = 10000, signer = self._get_signer(name))
        self.entities_storage[nonce] = encoder.auth_state
        return

    async def on_idproof_notification(self, name, _app_param):
        nonce = Component.to_number(name[_POSITION_NONCE_IN_PROOF_NOTIFICATION])
        logging.debug(f'Received Nonce: {nonce}')
        connect_info = self.entities_cache[nonce]['connect_info']
        encoder = self.entities_cache[nonce]['encoder']
        encoder_type_str = self.entities_cache[nonce]['encoder_type']
        local_prefix_str = connect_info[0]
        local_forwarder_str = connect_info[1]

        logging.debug(f'ConnectInfo: LocalPrefix {local_prefix_str}, LocalForwarder {local_forwarder_str}')
        # /<local-prefix>/NAA/BOOT/<nonce>/MSG
        idproof_params_name = Name.from_str(local_prefix_str + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        interest_param = InterestParam()
        time.sleep(0.01)
                
        if len(local_forwarder_str) > 0:
            interest_param.forwarding_hint = [Name.from_str(local_forwarder_str)]
        data_name, _, content = await self.app.express_interest(
            idproof_params_name,  must_be_fresh=True, can_be_prefix=False, lifetime=6000)
        
        encoder.parse_idproof_params(content)
        # another string processing
        auth_type_str = encoder_type_str[:encoder_type_str.find('ModeEncoder')]
        authenticator = self.authenticators[auth_type_str]
        encoder.auth_state, err = await authenticator.after_receive_idproof_params(encoder.auth_state)
        
        if encoder.auth_state.is_authenticated and err is None:
            # assign name
            name_assigner = self.name_assigners[auth_type_str]
            assigned_name = name_assigner.assign(encoder.auth_state)
            key_id = Component.from_bytes(encoder.auth_state.nonce.to_bytes(8, 'big'))
            proof_of_possess_idname = [Component.from_str('32=authenticate')] + assigned_name
            proof_of_possess_keyname = proof_of_possess_idname + [KEY_COMPONENT, key_id]
            proof_of_possess_name_mocked = proof_of_possess_keyname + Name.from_str('/NA/v=0')
            proof_of_possess_name, proof_of_possess = \
                derive_cert(proof_of_possess_keyname, 'NA',
                            encoder.auth_state.pub_key,
                            self._get_signer(proof_of_possess_name_mocked),
                            datetime.utcnow(), 10000)
            logging.debug(f'Generating PoP {Name.to_str(proof_of_possess_name)}')
            self.app.put_data(name, content=encoder.prepare_idproof_response(proof_of_possess = proof_of_possess),
                            freshness_period = 10000, signer = self._get_signer(name))
            self.entities_storage[nonce] = encoder.auth_state

    async def register(self):
        @self.app.route(self.aa_prefix + '/NAA')
        def _on_notification(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            # dispatch to corresponding handlers
            if Name.is_prefix(self.aa_prefix + '/NAA/BOOT', name):
                asyncio.create_task(self.on_boot_notification(name, _app_param))
                return
            if Name.is_prefix(self.aa_prefix + '/NAA/PROOF', name):
                asyncio.create_task(self.on_idproof_notification(name, _app_param))
                return