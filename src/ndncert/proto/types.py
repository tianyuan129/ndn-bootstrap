from typing import Callable, Tuple, List

Selector = Callable[[List[bytes]], Tuple[bytes, bytes, bytes]]

Verifier = Callable[[bytes, bytes, bytes], Tuple[bytes, bytes]]


class InvalidName(Exception):
    """
    Raised when an name request is invalid
    """
    pass

class ProtoError(Exception):
    """
    Raised when the remote end doesn't support this protocol, 
    or the result is not success
    """
    pass