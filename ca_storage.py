from proto.ndncert_proto import *

TLV_PLACEHOLDER = 1

class CertState(TlvModel):
    id = BytesField(TLV_PLACEHOLDER)
    status = UintField(TLV_PLACEHOLDER)

    aes_key = BytesField(TLV_PLACEHOLDER)
    iv_counter = UintField(TLV_PLACEHOLDER)

    csr = BytesField(TLV_CHALLENGE_STATUS_TYPE)

    auth_mean = BytesField(TLV_PLACEHOLDER)
    iden_key = BytesField(TLV_PLACEHOLDER)
    iden_value = BytesField(TLV_PLACEHOLDER)

    auth_key = BytesField(TLV_PLACEHOLDER)
    auth_value = BytesField(TLV_PLACEHOLDER)
    
    issued_cert = BytesField(TLV_PLACEHOLDER)
