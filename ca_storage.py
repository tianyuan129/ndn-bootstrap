from proto.ndncert_proto import *

TLV_PLACEHOLDER = 1

class CertState(TlvModel):
    id = BytesField(1)
    status = UintField(2)

    aes_key = BytesField(3)
    iv_counter = UintField(4)

    csr = BytesField(5)

    auth_mean = BytesField(6)
    iden_key = BytesField(7)
    iden_value = BytesField(8)

    auth_key = BytesField(9)
    auth_value = BytesField(10)
    
    issued_cert = BytesField(11)


class IssuedCertStates(TlvModel):
    states = RepeatedField(ModelField(1, CertState))
    
class PendingCertStates(TlvModel):
    states = RepeatedField(ModelField(1, CertState))

class RejectedCertStates(TlvModel):
    states = RepeatedField(ModelField(1, CertState))
    
class ManualApproval(TlvModel):
    state = CertState()
    expires = UintField(1)

class ManualApprovalList(TlvModel):
    approvals = RepeatedField(ModelField(1, ManualApproval))