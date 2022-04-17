from typing import Tuple
from Cryptodome.PublicKey import ECC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


from ndn.app_support.security_v2 import CertificateV2Value, SafeBag, parse_certificate
from ndn.encoding import FormalName
from ndn.security import KeychainSqlite3

def export_ecdsa_safebag(keychain: KeychainSqlite3, cert_name: FormalName, passwd: bytes) -> SafeBag:
    id_name = cert_name[:-4]
    key_name = cert_name[:-2]
    
    signer = keychain.get_signer({'cert': cert_name})
    ecc_key = ECC.import_key(signer.key_der)
    encrypted_prv= ecc_key.export_key(format = 'DER', passphrase = passwd, use_pkcs8 = True, 
        protection = 'PBKDF2WithHMAC-SHA1AndAES128-CBC')
    cert = keychain[id_name][key_name][cert_name]
    
    safebag = SafeBag()
    safebag.certificate_v2 = cert.data
    safebag.encrypted_key_bag = encrypted_prv
    return safebag
    
def parse_ecdsa_safebag(wire: bytes, passwd: bytes) -> Tuple[CertificateV2Value, ECC.EccKey]: 
    safebag = SafeBag.parse(wire)
    cert = safebag.certificate_v2
    cert_data = parse_certificate(cert)
    prv_key = ECC.import_key(safebag.encrypted_key_bag, passphrase = passwd)
    return cert_data, prv_key