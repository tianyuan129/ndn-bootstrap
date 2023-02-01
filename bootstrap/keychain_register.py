# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
import logging
from ndn.app import NDNApp
from ndn.encoding import Name, FormalName, InterestParam
from ndn.app_support.security_v2 import KEY_COMPONENT
from ndn.security import Keychain

class KcHandler:
    def __init__(self, app: NDNApp, ident):
        self.ident = ident
        self.app = app

    def on_int(self, int_name: FormalName, _param: InterestParam, _app_param):
        id_name = self.ident.name
        if not Name.is_prefix(id_name, int_name):
            return
        # can_be_prefix = True if using KEY name, False if using CERT name
        if len(int_name) != len(id_name) + (2 if _param.can_be_prefix else 4):
            logging.warning(f'Invalid key fetching Interest: {Name.to_str(int_name)}')
            return
        try:
            key_name = int_name[:len(id_name)+2]
            key = self.ident[key_name]
            cert = None
            if _param.can_be_prefix:
                # fetch KEY
                for _, cur_cert in key.items():
                    cert = cur_cert
                    break
            else:
                cert = key[int_name]
            if cert is not None:
                logging.info(f'KeychainRegister replied with: {Name.to_str(cert.name)}')
                self.app.put_raw_packet(cert.data)
            else:
                logging.warning(f'No certificate for key: {Name.to_str(int_name)}')
        except KeyError:
            logging.warning(f'Fetching not existing key/cert: {Name.to_str(int_name)}')


def attach_keychain_register_appv1(keychain: Keychain, app: NDNApp):
    for name, ident in keychain.items():
        reg_name = name + [KEY_COMPONENT]
        handler = KcHandler(app, ident)
        app.route(reg_name)(handler.on_int)