import asyncio as aio
from datetime import datetime, timedelta
import logging
from ndn.app import NDNApp
from ndn.encoding import Name, FormalName, Component
from ndn.utils import timestamp

from ..tib import Tib

# this producer will not register route
class RdrProducer(object):
    def __init__(self, app: NDNApp, object_name: FormalName, tib: Tib, **kwargs):
        self.app = app
        self.objn = object_name
        self.tib = tib
        self.pkt_cache = {}
        self.latest_version = 0
        self.rdr_freshness = 4000
        
        if 'ttl' in kwargs:
            aio.create_task(self._clear_cache(kwargs['ttl']))
        if 'register_route' in kwargs:
            register_route = kwargs['register_route']
            if register_route:
                self.app.route(self.objn)(None)
        if 'rdr_freshness' in kwargs:
            self.rdr_freshness = kwargs['rdr_freshness']
        self.app.set_interest_filter(object_name + [Component.from_str('32=metadata')],
                                     self._on_rdr_discover)
        
    async def _clear_cache(self, ttl):
        self.pkt_cache = [_pkt for _pkt in self.pkt_cache\
            if _pkt[1] + timedelta(seconds=ttl) > datetime.utcnow()]
        await aio.sleep(ttl + 0.01)

    def _on_rawpkt_interest(self, int_name, _int_param, _app_param):
        if Name.to_str(int_name) in self.pkt_cache:
            self.app.put_raw_packet(self.pkt_cache[Name.to_str(int_name)][0])
            logging.debug(f'Returning Data {Name.to_str(int_name)}')

    def _on_rdr_discover(self, int_name, _int_param, _app_param):
        if not Name.is_prefix(self.objn, int_name):
            logging.debug("Not for this object, do nothing")
            return
        
        if self.latest_version == 0:
            logging.debug("No produced data available")
            return
        metadata_name = int_name
        metadata_name += [Component.from_version(timestamp())]
        metadata_name += [Component.from_segment(0)]

        latest_pkt_name = self.objn + [Component.from_version(self.latest_version)]
        rawpkt = self.tib.sign_data(metadata_name, Name.to_bytes(latest_pkt_name),
                                    freshness_period = self.rdr_freshness)
        self.app.put_raw_packet(rawpkt)

    def produce(self, content: bytes, **kwargs):
        self.latest_version = timestamp()
        pkt_name = self.objn + [Component.from_version(self.latest_version)]
        # insert into cache
        created_at = datetime.utcnow()
        rawpkt = self.tib.sign_data(pkt_name, content, **kwargs)
        if len(rawpkt) >= 8800:
            logging.fatal(f'Packet is too large, need to be segmented!')
            return
        self.pkt_cache[Name.to_str(pkt_name)] = [rawpkt, created_at]
        self.app.set_interest_filter(pkt_name, self._on_rawpkt_interest)
        

class RdrConsumer(object):
    class VersionError(Exception):
        '''raised when RDR retrieved data version is decreasing'''
        pass
    def __init__(self, app: NDNApp, object_name: FormalName):
        self.app = app
        self.objn = object_name
        self.latest_version = 0
    async def consume(self, **kwargs):
        # fetch the metadata        
        int_name = self.objn + [Component.from_str('32=metadata')]
        data_name, _, content = await self.app.express_interest(
            int_name, must_be_fresh=True, can_be_prefix=True, lifetime=6000)
        
        Name.from_bytes(latest_dataname)[-1]
        Component.to_number()
        
        logging.info(f'Receiving Metadata {Name.to_str(data_name)}')
        latest_dataname = Name.from_bytes(content)
        observed_version = Component.to_number(latest_dataname[-1])
        if observed_version < self.latest_version:
            raise RdrConsumer.VersionError(f'Observed version {observed_version} <'
                                           f'last observed version {self.latest_version}')
        logging.info(f'Receiving Data name {Name.to_str(latest_dataname)}')
        return await self.app.express_interest(latest_dataname, must_be_fresh=True,
                                            can_be_prefix=False, lifetime=6000, **kwargs)
            
    async def get_latest_version(self):
        # fetch the metadata        
        int_name = self.objn + [Component.from_str('32=metadata')]
        data_name, _, content = await self.app.express_interest(
            int_name, must_be_fresh=True, can_be_prefix=True, lifetime=6000)
        
        logging.info(f'Receiving Metadata {Name.to_str(data_name)}')
        latest_dataname = Name.from_bytes(content)
        observed_version = Component.to_number(latest_dataname[-1])
        if observed_version >= self.latest_version:        
            return observed_version
        else:
            return self.latest_version
        
    async def get_versioned_data(self, version: int, **kwargs):        
        # fetch the metadata        
        int_name = self.objn + [Component.from_version(version)]
        return await self.app.express_interest(int_name,
            must_be_fresh=True, lifetime = 6000, **kwargs)