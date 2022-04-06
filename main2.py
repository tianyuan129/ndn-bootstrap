from contextlib import AsyncExitStack
from typing import Optional, Dict, Callable, Any, Coroutine, List

import sys, os
import asyncio
from tempfile import TemporaryDirectory
from ndn.encoding import Name
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app_support.security_v2 import sign_req
from ca.client import *

app = NDNApp()

async def select_first(list: List[bytes]) -> Tuple[bytes, bytes, bytes]:
    print(bytes(list[0]).decode())
    return bytes(list[0]), "email".encode(), "tianyuan@cs.ucla.edu".encode()
    
    
async def email_verifier(challenge_status: bytes, param_key: bytes, param_value: bytes) -> Tuple[bytes, bytes]:
    assert param_key is None
    assert param_value is None
    assert bytes(challenge_status).decode() == "need-code"
    return "code".encode(), "2345".encode()
    
async def main() -> int:

    client = Client(app, None, None)
    with TemporaryDirectory() as tmpdirname:
        pib_file = os.path.join(tmpdirname, 'pib.db')
        tpm_dir = os.path.join(tmpdirname, 'privKeys')
        KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
        keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
        assert len(keychain) == 0

        ty_id = keychain.touch_identity('/ndn/tianyuan')
        ty_key = ty_id.default_key()
        ty_key_name = ty_key.name
        ty_cert_data = parse_certificate(ty_key.default_cert().data)
        ty_cert_name = ty_cert_data.name
        ty_signer = keychain.get_signer({'cert': ty_cert_name})
        
        if ty_signer is None:
            print(f'signer is none')
        _, csr = sign_req(ty_key_name, ty_cert_data.content, ty_signer)
        issued_cert_name, hint = await client.request_signing(Name.from_str('/ndn'), bytes(csr), ty_signer, select_first, email_verifier)
        print(f'{Name.to_str(issued_cert_name)}, {Name.to_str(hint)}')

    return 0

if __name__ == "__main__":
    app.run_forever(after_start=main())