import logging, os, asyncio
from ndn.encoding import Name, Component, parse_data, NonStrictName
from ndn.app import NDNApp, InterestTimeout, InterestNack

from ..ndncert.proto.types import Selector, Verifier
from ..tib import Tib, TibBundle
from ..app_support.simple_rdr import RdrConsumer

class ZoneEntity(object):
    def __init__(self, app: NDNApp, path: str, signed_bundle: bytes):
        tib_base = os.path.join(path, 'zone-entity')
        Tib.initialize(signed_bundle, tib_base)
        # TIB will create keychain on application's behalf and load to app
        self.tib = Tib(app, path=tib_base)
        
        # prepare for rdr
        name, _, _, _ = parse_data(signed_bundle)
        # /<zone>/BUNDLE/version
        self.bundle_version = Component.to_number(name[-1])
        self.rdrcon = RdrConsumer(app, name[:-1])
    async def bootstrap_to(self, id_name: NonStrictName,
                           selector: Selector, verifier: Verifier, 
                           need_auth = False, need_issuer = False):
        await self.tib.bootstrap(Name.normalize(id_name), selector, verifier,
                                 need_auth = need_auth,
                                 need_issuer = need_issuer)

    async def rdr_discover_bundle(self, scheduled_after):
        await asyncio.sleep(scheduled_after)
        try:
            latest_verison = await self.rdrcon.get_latest_version()
        except (InterestTimeout, InterestNack) as e:
            logging.debug(f'Interest failed because of {e}')
            latest_verison = self.bundle_version
        if latest_verison > self.bundle_version:
            try:
                name, _, content = await self.rdrcon.get_versioned_data(latest_verison)
            except (InterestTimeout, InterestNack) as e:
                logging.debug(f'Interest failed because of {e.reason}')            
            logging.info(f'Installing bundle {Name.to_str(name)}...')
            fetched_bundle = TibBundle.parse(content)
            self.tib.install_trusted_bundle(fetched_bundle)
            self.bundle_version = latest_verison
