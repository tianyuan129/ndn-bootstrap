from .ndncert_proto import *
from ndn.encoding import NameField, ModelField

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

class IdentityBinding(TlvModel):
    id = UintField(9)
    auth_mean = BytesField(6)
    iden_key = BytesField(7)
    iden_value = BytesField(8)
    name = NameField()
    timestamp = UintField(9)

class IdentityBindingList(TlvModel):
    bindings = RepeatedField(ModelField(1, IdentityBinding))

class IssuedCertStates(TlvModel):
    states = RepeatedField(ModelField(1, CertState))
    
class PendingCertStates(TlvModel):
    states = RepeatedField(ModelField(1, CertState))

class RejectedCertStates(TlvModel):
    states = RepeatedField(ModelField(1, CertState))