from contextlib import AsyncExitStack
from statistics import mode
from typing import Optional, Dict, Callable, Any, Coroutine, List

import sys, os
import asyncio
from tempfile import TemporaryDirectory
from ndn.encoding import Name
from ndn.security import KeychainSqlite3, TpmFile
from ndn.app_support.security_v2 import sign_req
from ca.client import *

from app_support.tib import Tib, TibBundle
from ndn.app_support.light_versec import compile_lvs, LvsModel

app = NDNApp()

async def select_first(list: List[bytes]) -> Tuple[bytes, bytes, bytes]:
    print(list[0])
    return list[0], "email".encode(), "tianyuan@cs.ucla.edu".encode()
    
    
async def email_verifier(challenge_status: bytes, param_key: bytes, param_value: bytes) -> Tuple[bytes, bytes]:
    assert param_key is None
    assert param_value is None
    assert bytes(challenge_status).decode() == "need-code"
    return "code".encode(), "2345".encode()
    
def main() -> int:

    basedir = os.path.expanduser('~/.ndn-tib-test/')
    tpm_path = os.path.join(basedir, 'privKeys')
    pib_path = os.path.join(basedir, 'pib.db')
    keychain = KeychainSqlite3(pib_path, TpmFile(tpm_path))
    anchor_id = keychain['/ndn']
    anchor_key = anchor_id.default_key()
    
    lvs = r'''
    #KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
    #NewResponse: /site/CA/_func/_ & { _func: "NEW"} <= #anchor
    #ChaResponse: /site/CA/_func/_/_param & { _func: "CHALLENGE" } <= #anchor
    #TmpCert: /site/_/#KEY <= #anchor 
    #anchor: /site/#KEY & { site: "ndn" }
    '''
    bundle = TibBundle()
    bundle.anchor = anchor_key.default_cert().data
    bundle.schema = compile_lvs(lvs)
    
    # package = bundle.encode()
    # print(package)
       
    tib = Tib(app, bundle, '~/.ndn-tib-test/')
    async def bootstrap():
        await tib.bootstrap(Name.from_str('/ndn/tianyuan'), select_first, email_verifier)
        app.shutdown()

    app.run_forever(bootstrap())
    
    
if __name__ == "__main__":
    main()
