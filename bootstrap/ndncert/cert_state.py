from ndn.encoding import TlvModel, BytesField, UintField, ModelField
from .protocol_v3 import *

TLV_PLACEHOLDER = 1
INTERNAL_TLV_AES = 2
INTERNAL_TLV_IV_COUNTER = 3
INTERNAL_TLV_IV_RANDOM = 4
INTERNAL_TLV_PARAMETERS = 5

class CertState(TlvModel):
    # status
    id = BytesField(TLV_REQUEST_ID_TYPE)
    status = UintField(TLV_STATUS_TYPE)

    # cryptos
    aes_key = BytesField(INTERNAL_TLV_AES)
    iv_counter = UintField(INTERNAL_TLV_IV_COUNTER)
    iv_random = BytesField(INTERNAL_TLV_IV_RANDOM)

    # authentication 
    auth_mean = BytesField(TLV_CHALLENGE_TYPE)
    auth_status = BytesField(TLV_CHALLENGE_STATUS_TYPE)
    auth_key = BytesField(TLV_PARAMETER_KEY_TYPE)
    auth_value = BytesField(TLV_PARAMETER_VALUE_TYPE)
    
    # certificates
    csr = BytesField(TLV_CERT_REQUEST_TYPE)
    issued_cert = BytesField(TLV_ISSUED_CERT_NAME_TYPE)
    
    # other
    parameters = RepeatedField(ModelField(INTERNAL_TLV_PARAMETERS, Parameter))
