from typing import Callable, Tuple, List

Selector = Callable[[List[bytes]], Tuple[bytes, bytes, bytes]]

Verifier = Callable[[bytes, bytes, bytes], Tuple[bytes, bytes]]


class InvalidName(Exception):
    """
    Raised when an name request is invalid
    """
    pass
