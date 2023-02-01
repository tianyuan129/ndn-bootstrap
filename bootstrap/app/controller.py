from datetime import datetime
from ndn.app import NDNApp
from ndn.security import KeychainSqlite3
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.app_support.light_versec import Checker, lvs_validator

from ..ndnauth.app.name_aa import NameAuthAssign
from ..ndncert.app.cert_issuer import CertIssuer
from ..config import get_yaml
from ..types import NameAssignFunc

class Controller(object):
    def __init__(self, app: NDNApp, config_path: str, keychain: KeychainSqlite3, lvs_checker: Checker):
        self.app = app
        self.config = get_yaml(config_path)
        self.anchor_prefix = self.config['identity_config']['anchor_name']
        self.auth_prefix = self.config['identity_config']['auth_name']
        self.issuer_prefix = self.config['identity_config']['issuer_name']
        self._check_and_prepare_keychain(keychain, lvs_checker)

        # construct name server and cert issuer
        self.aa = NameAuthAssign(self.app, self.config, self.keychain, self.lvs_checker,
                                 lvs_validator(self.lvs_checker, self.app, self.cert_data))
        # fill in the verifier
        self.config['verifier_config'] = {'possession': ''}
        self.issuer = CertIssuer(self.app, self.config, self.keychain, self.lvs_checker,
                                 lvs_validator(self.lvs_checker, self.app, self.cert_data))

    def _check_and_prepare_keychain(self, keychain: KeychainSqlite3, lvs_checker: Checker):
        self.keychain = keychain
        self.lvs_checker = lvs_checker
        # check and prepare trust anchor
        try:
            self.cert_data = self.keychain[self.anchor_prefix].default_key().default_cert().data
            self.cert_name = parse_certificate(self.cert_data).name
        except:
            self.keychain.touch_identity(self.anchor_prefix)
            self.cert_data = self.keychain[self.anchor_prefix].default_key().default_cert().data
            self.cert_name = parse_certificate(self.cert_data).name
        # check and prepare auth-signer
        try:
            auth_signer_key = self.keychain[self.auth_prefix].default_key()
        except:
            auth_signer_key = self.keychain.touch_identity(self.auth_prefix).default_key()
        auth_signer_default_cert = parse_certificate(auth_signer_key.default_cert().data)
        if not self.lvs_checker.check(auth_signer_default_cert.name, 
                                      auth_signer_default_cert.signature_info.key_locator.name):
            auth_signer_pubkey = auth_signer_default_cert.content
            auth_signer_cert_name, auth_signer_cert_data = \
                derive_cert(auth_signer_key.name, 'root', auth_signer_pubkey,
                            self.keychain.tpm.get_signer(self.cert_name[:-2], self.cert_name), datetime.utcnow(), 10000)
            self.keychain.import_cert(auth_signer_key.name, auth_signer_cert_name, auth_signer_cert_data)
            auth_signer_key.set_default_cert(auth_signer_cert_name)
        # check and prepare cert-signer
        try:
            cert_signer_key = self.keychain[self.issuer_prefix].default_key()
        except:
            cert_signer_key = self.keychain.touch_identity(self.issuer_prefix).default_key()
            cert_signer_default_cert = parse_certificate(cert_signer_key.default_cert().data)
            if not self.lvs_checker.check(cert_signer_default_cert.name, 
                                          cert_signer_default_cert.signature_info.key_locator.name):
                cert_signer_pubkey = cert_signer_default_cert.content
                cert_signer_cert_name, cert_signer_cert_data = \
                    derive_cert(cert_signer_key.name, 'root', cert_signer_pubkey,
                                self.keychain.tpm.get_signer(self.cert_name[:-2], self.cert_name), datetime.utcnow(), 10000)
                self.keychain.import_cert(cert_signer_key.name, cert_signer_cert_name, cert_signer_cert_data)
                cert_signer_key.set_default_cert(cert_signer_cert_name)

    def route(self):
        self.aa.route()
        self.issuer.route()
        
    def load_name_assignment(self, auth_type: str, assign_func: NameAssignFunc):
        self.aa.load_name_assignment(auth_type, assign_func)
            
        