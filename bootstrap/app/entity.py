import logging

from ndn.encoding import Name, InterestParam, NonStrictName
from ndn.app import NDNApp, Validator
from ndn.security import KeychainSqlite3
from ndn.app_support.security_v2 import parse_certificate
from ndn.app_support.light_versec import Checker

from ..ndnauth.app.name_requester import NameRequster
from ..ndncert.app.cert_requester import CertRequester
from ..types import Prover

class Entity(object):
    def __init__(self, app: NDNApp, keychain: KeychainSqlite3, checker: Checker, validator: Validator):
        self.app = app
        self.keychain = keychain
        self.tpm = keychain.tpm
        self.checker = checker
        self.validator = validator
        self.name_requester = NameRequster(self.app, self.validator)
        self.cert_requester = CertRequester(self.app, self.checker, self.validator)
    
    async def certify(self, pop_wire, signer):
        pop_data = parse_certificate(pop_wire)
        assigned_keyname = pop_data.name[:-2]
        assigned_name = assigned_keyname[1:-2]
        logging.info(f'Receiving PoP {Name.to_str(pop_data.name)}')
        def pop_prover(nonce: bytes):
            wire = bytearray(70)
            assert signer.write_signature_value(wire, [memoryview(nonce)]) == len(wire)
            return bytes(wire)

        # prepare keychain
        try:
            csr_data = self.keychain[assigned_name].default_key().default_cert().data
        except:
            logging.info(f'Creating new Identity under assigned name {Name.to_str(assigned_name)}')
            self.keychain.touch_identity(assigned_name)
            csr_data = self.keychain[assigned_name].default_key().default_cert().data
        csr_name = parse_certificate(csr_data).name
        issued_cert_name, forwarding_hint = \
            await self.cert_requester.request_signing_with_possession(
                '/ndn/site1', csr_data, self.tpm.get_signer(csr_name[:-2], csr_name),
                pop_wire, pop_prover
            )
        interest_param = InterestParam()
        interest_param.forwarding_hint = [forwarding_hint]
        _, _, _, issued_cert = await self.app.express_interest(issued_cert_name, validator=self.validator,
                                                        interest_param=interest_param,
                                                        need_raw_packet=True)
        logging.info(f'Loading issued certificate {Name.to_str(issued_cert_name)} to Keychain')
        self.keychain.import_cert(issued_cert_name[:-2], issued_cert_name, issued_cert)
        logging.info(f'Deleting authentication key {Name.to_str(assigned_keyname)} from TPM')
        self.tpm.delete_key(assigned_keyname)

    async def get_user_certified(self, controller_prefix: NonStrictName, local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                 email: str, prover: Prover):
        logging.info(f'Start authentication...')
        pop_wire, signer = await self.name_requester.authenticate_user(
            controller_prefix, local_prefix, local_forwarder, email, prover
        )
        await self.certify(pop_wire, signer)
        
    async def get_server_certified(self, controller_prefix: NonStrictName, local_prefix: NonStrictName, local_forwarder: NonStrictName | None,
                                   x509_chain: bytes, x509_prv_key: bytes):
        logging.info(f'Start authentication...')
        pop_wire, signer = await self.name_requester.authenticate_server(
            controller_prefix, local_prefix, local_forwarder, x509_chain, x509_prv_key
        )
        await self.certify(pop_wire, signer)