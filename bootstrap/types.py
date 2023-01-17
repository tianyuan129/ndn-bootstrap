from typing import Any, Callable, Tuple, List
from ndn.encoding import NonStrictName, Signer

GetSigner = Callable[[NonStrictName], Signer]

Selector = Callable[[List[bytes]], Tuple[bytes, bytes, bytes]]

Prover = Callable[[Any], bytes]

class InvalidName(Exception):
    """
    Raised when an name request is invalid
    """
    pass

class ProtoError(Exception):
    """
    Raised when there is a protocol-specific error
    """
    pass
