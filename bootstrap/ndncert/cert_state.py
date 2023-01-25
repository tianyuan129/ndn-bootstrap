from ndn.encoding import TlvModel, BytesField, UintField, ModelField
from .protocol_v3 import *

TLV_PLACEHOLDER = 1
INTERNAL_TLV_AES = 2
INTERNAL_TLV_IV_COUNTER = 3
INTERNAL_TLV_IV_RANDOM = 4
INTERNAL_TLV_PARAMETERS = 5

class CertState(TlvModel):
    # protocol-defined
    id = BytesField(TLV_REQUEST_ID_TYPE)
    status = UintField(TLV_STATUS_TYPE)
    challenge_status = BytesField(TLV_CHALLENGE_STATUS_TYPE)
    selected_challenge = BytesField(TLV_CHALLENGE_TYPE)
    remaining_tries = UintField(TLV_REMAINING_TRIES_TYPE)
    remaining_time = UintField(TLV_REMAINING_TIME_TYPE)
    csr = BytesField(TLV_CERT_REQUEST_TYPE)
    issued_cert_name = BytesField(TLV_ISSUED_CERT_NAME_TYPE)
    forwarding_hint = BytesField(TypeNumber.FORWARDING_HINT)

    # internal-needed
    aes_key = BytesField(INTERNAL_TLV_AES)
    iv_counter = UintField(INTERNAL_TLV_IV_COUNTER)
    iv_random = BytesField(INTERNAL_TLV_IV_RANDOM)

    # parameters
    parameters = RepeatedField(ModelField(INTERNAL_TLV_PARAMETERS, Parameter))
    def put_parameter(self, key: str, value: bytes):
        param = Parameter()
        param.key = key.encode()
        param.value = value
        self.parameters.append(param)
    
    def get_parameter(self, key: str) -> bytes | None:
        for param in self.parameters:
            if param.key == key.encode():
                return bytes(param.value)
        return None

    def encode_parameter(self, key: str) -> bytes | None:
        for param in self.parameters:
            if param.key == key.encode():
                return param.encode()
        return None