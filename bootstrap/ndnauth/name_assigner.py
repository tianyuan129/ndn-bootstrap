from abc import ABC, abstractmethod
from cryptography import x509

from .protocol import *
from .auth_state import *
from ..types import NameAssignFunc

from ndn.encoding import FormalName

class NameAssigner(ABC):
    _assign_func = None
    def load_callback(self, assign_func: NameAssignFunc):
        self._assign_func = assign_func
        pass

    @abstractmethod
    def preprocess(self, auth_state: AuthState) -> str:
        pass

    def assign(self, auth_state: AuthState) -> FormalName:
        if self._assign_func is None:
            raise Exception("NameAssigner hasn't loaded callback")
        else:
            preprocessed = self.preprocess(auth_state)
            return self._assign_func(preprocessed)

class ServerNameAssigner(NameAssigner): 
    def preprocess(self, auth_state: AuthState) -> str:
        loaded_chain = x509.load_pem_x509_certificates(bytes(auth_state.x509_chain))
        leaf = loaded_chain[0]
        common_names = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return common_names[0].value

class UserNameAssigner(NameAssigner):
    def preprocess(self, auth_state: AuthState) -> str:
        return bytes(auth_state.email).decode('utf-8')