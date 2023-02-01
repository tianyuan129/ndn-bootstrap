from typing import Optional, Dict

import logging, sys, time
import asyncio
from datetime import datetime

from ndn.app import NDNApp, Validator
from ndn.encoding import Name, InterestParam, BinaryStr, FormalName, Component, parse_tl_num
from ndn.app_support.security_v2 import parse_certificate, KEY_COMPONENT, derive_cert
from ndn.app_support.light_versec import Checker
from ndn.security import KeychainSqlite3

from ..protocol import *
from ...crypto_tools import *
from ..name_auth import *
from ..name_assigner import *
from ..auth_state import *
from ..mode_encoder import *
from ...types import NameAssignFunc

_POSITION_NONCE_IN_BOOT_NOTIFICATION = -3
_POSITION_NONCE_IN_PROOF_NOTIFICATION = -2

class NameAuthAssign(object):
    def __init__(self, app: NDNApp, config: Dict, keychain: KeychainSqlite3,
                 checker: Checker, validator: Validator):
        #todo: customize the storage type
        self.entities_cache = {}
        self.entities_storage = {}
        self.config = config
        self.anchor_name = self.config['identity_config']['anchor_name']
        self.aa_name = self.config['identity_config']['auth_name']
        self.keychain = keychain
        self.checker = checker
        self.data_validator = validator

        try:
            aa_id = self.keychain[self.aa_name]
            aa_cert = aa_id.default_key().default_cert().data
            self.aa_cert_data = parse_certificate(aa_cert)
        except:
            aa_id = self.keychain.touch_identity(self.aa_name)
            aa_cert = aa_id.default_key().default_cert().data
            self.aa_cert_data = parse_certificate(aa_cert)

        self.app = app
        app.keychain = self.keychain

        # initialize membership checker, authenticator, and name assigner
        self.membership_checkers = {}
        self.authenticators = {}
        self.name_assigners = {}

        auth_configs = config['auth_config']
        for auth_type in auth_configs:
            config_section = auth_configs[auth_type]

            # locate the corresponding membership checker
            capitalized = auth_type.capitalize()
            checker_type_str = capitalized + 'MembershipChecker'
            membership_checker_type = getattr(sys.modules[__name__], checker_type_str)
            membership_checker = object.__new__(membership_checker_type, config_section['membership_checker'])
            membership_checker.__init__(config_section['membership_checker'])
            self.membership_checkers[capitalized] = membership_checker
            
            authenticator_type_str = capitalized + 'Authenticator'
            authenticator_type = getattr(sys.modules[__name__], authenticator_type_str)
            authenticator = object.__new__(authenticator_type, config_section['authenticator'])
            authenticator.__init__(config_section['authenticator'])
            self.authenticators[capitalized] = authenticator

            name_assigner_type_str = capitalized + 'NameAssigner'
            name_assigner_type = getattr(sys.modules[__name__], name_assigner_type_str)
            name_assigner = object.__new__(name_assigner_type)
            name_assigner.__init__()
            self.name_assigners[capitalized] = name_assigner

    def _get_signer(self, name):
        suggested_keylocator = self.checker.suggest(name, self.keychain)
        if suggested_keylocator is None:
            logging.error(f'No proper keylocator for {Name.to_str(name)}')
            return None
        else:
            return self.keychain.tpm.get_signer(suggested_keylocator[:-2], suggested_keylocator)

    def _return_err_msg(self, name, err):
        self.app.put_data(name, content=err.encode(), freshness_period = 10000, signer = self._get_signer(name))

    async def on_boot_notification(self, name, _app_param):
        nonce = Component.to_number(name[_POSITION_NONCE_IN_BOOT_NOTIFICATION])
        logging.debug(f'Received Nonce: {nonce}')
        try:
            connect_info = ConnectvityInfo.parse(_app_param)
        except:
            errs = ErrorMessage()
            errs.code = ERROR_BAD_PARAMETER_FORMAT[0]
            errs.info = ERROR_BAD_PARAMETER_FORMAT[1].encode()
            self._return_err_msg(name, errs)
            return            
        
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
        time.sleep(0.001)
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
        try:
            encoder.parse_boot_params(content)
        except:
            errs = ErrorMessage()
            errs.code = ERROR_BAD_RESPONSE_FORMAT[0]
            errs.info = ERROR_BAD_RESPONSE_FORMAT[1].encode()
            self._return_err_msg(name, errs)
            return            
        
        auth_type_str = encoder_type_str[:encoder_type_str.find('ModeEncoder')]
        membership_checker = self.membership_checkers[auth_type_str]
        encoder.auth_state = await membership_checker.check(encoder.auth_state)
        self.entities_storage[nonce] = encoder.auth_state
        if not encoder.auth_state.is_member:
            errs = ErrorMessage()
            errs.code = ERROR_IDENTITY_NOT_ALLOWED[0]
            errs.info = ERROR_IDENTITY_NOT_ALLOWED[1].encode()
            self._return_err_msg(name, errs)
            self.entities_storage[nonce] = encoder.auth_state
            return
    
        authenticator = self.authenticators[auth_type_str]
        encoder.auth_state = await authenticator.after_receive_boot_params(encoder.auth_state)
        self.entities_storage[nonce] = encoder.auth_state
        self.app.put_data(name, content=encoder.prepare_boot_response(), freshness_period = 10000, signer = self._get_signer(name))
        return

    async def on_idproof_notification(self, name, _app_param):
        nonce = Component.to_number(name[_POSITION_NONCE_IN_PROOF_NOTIFICATION])
        logging.debug(f'Received Nonce: {nonce}')
        connect_info = self.entities_cache[nonce]['connect_info']
        encoder = self.entities_cache[nonce]['encoder']
        
        # if rejected before, keep the decision
        if not encoder.auth_state.is_member:
            errs = ErrorMessage()
            errs.code = ERROR_IDENTITY_NOT_ALLOWED[0]
            errs.info = ERROR_IDENTITY_NOT_ALLOWED[1].encode()
            self._return_err_msg(name, errs)
            self.entities_storage[nonce] = encoder.auth_state
            return
        encoder_type_str = self.entities_cache[nonce]['encoder_type']
        local_prefix_str = connect_info[0]
        local_forwarder_str = connect_info[1]

        logging.debug(f'ConnectInfo: LocalPrefix {local_prefix_str}, LocalForwarder {local_forwarder_str}')
        # /<local-prefix>/NAA/BOOT/<nonce>/MSG
        idproof_params_name = Name.from_str(local_prefix_str + '/NAA/PROOF') \
            + [Component.from_number(nonce, Component.TYPE_GENERIC), Component.from_str('MSG')]
        interest_param = InterestParam()
        time.sleep(0.001)
                
        if len(local_forwarder_str) > 0:
            interest_param.forwarding_hint = [Name.from_str(local_forwarder_str)]
        data_name, _, content = await self.app.express_interest(
            idproof_params_name,  must_be_fresh=True, can_be_prefix=False, lifetime=6000)

        try:
            encoder.parse_idproof_params(content)
        except:
            errs = ErrorMessage()
            errs.code = ERROR_BAD_RESPONSE_FORMAT[0]
            errs.info = ERROR_BAD_RESPONSE_FORMAT[1].encode()
            self._return_err_msg(name, errs)
            return         

        # another string processing
        auth_type_str = encoder_type_str[:encoder_type_str.find('ModeEncoder')]
        authenticator = self.authenticators[auth_type_str]
        encoder.auth_state = await authenticator.after_receive_idproof_params(encoder.auth_state)
        self.entities_storage[nonce] = encoder.auth_state
        if not encoder.auth_state.is_authenticated:
            errs = ErrorMessage()
            errs.code = ERROR_BAD_IDENTITY_PROOF[0]
            errs.info = ERROR_BAD_IDENTITY_PROOF[1].encode()
            self._return_err_msg(name, errs)
            self.entities_storage[nonce] = encoder.auth_state
            return

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
                        datetime.utcnow(), int(self.config['validity_period']['proof_of_possession']))
        logging.info(f'Generating PoP {Name.to_str(proof_of_possess_name)}')
        self.app.put_data(name, content=encoder.prepare_idproof_response(proof_of_possess = proof_of_possess),
                        freshness_period = 10000, signer = self._get_signer(name))
        self.entities_storage[nonce] = encoder.auth_state

    def load_name_assignment(self, auth_type: str, assign_func: NameAssignFunc):
        capitalized = auth_type.capitalize()
        if capitalized not in self.membership_checkers or \
           capitalized not in self.authenticators or \
           capitalized not in self.name_assigners:
            raise Exception('Cannot load name assignment because'
                            'no corresponding membership checker,'
                            'authenticator or name preprocessor')
        else:
            self.name_assigners[capitalized].load_callback(assign_func)

    def route(self):
        @self.app.route(self.anchor_name + '/NAA')
        def _on_notification(name: FormalName, _params: InterestParam, _app_param: Optional[BinaryStr] | None):
            # dispatch to corresponding handlers
            if Name.is_prefix(self.anchor_name + '/NAA/BOOT', name):
                asyncio.create_task(self.on_boot_notification(name, _app_param))
                return
            if Name.is_prefix(self.anchor_name + '/NAA/PROOF', name):
                asyncio.create_task(self.on_idproof_notification(name, _app_param))
                return