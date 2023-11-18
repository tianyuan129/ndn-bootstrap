from typing import Any, Callable, Tuple, List, Coroutine
from ndn.encoding import NonStrictName, Signer, FormalName

GetSigner = Callable[[NonStrictName], Signer]

Selector = Callable[[List[bytes]], Tuple[str, str, bytes]]

Prover = Callable[[Any], Coroutine[Any, None, bytes]]

NameAssignFunc = Callable[[str], FormalName]

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
