import asyncio
import time
import os

from util.config import get_yaml

import logging
from ca import Ca
from ndn.encoding import Name
from PIL import Image
import json
from aiohttp import web
import socketio
import aiohttp_jinja2
import jinja2
from datetime import datetime

from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate

def gui_main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}', datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG, style='{')

    base_path = os.getcwd() + '/gui'
    # Serve static content from /static
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(os.path.join(base_path, 'templates')))
    app.router.add_static(prefix='/static', path=os.path.join(base_path, 'static'))
    routes = web.RouteTableDef()
    # Create SocketIO async server for controller
    sio = socketio.AsyncServer(async_mode='aiohttp')
    sio.attach(app)
    
    ndn_app = NDNApp()
    ca = Ca(ndn_app, get_yaml(None)).go()
        # app.run_forever()
        
    # controller = CaGui(sio.emit)
    # controller.system_init()

    def render_template(template_name, request, **kwargs):
        return aiohttp_jinja2.render_template(template_name, request, context=kwargs)

    def redirect(route_name, request, **kwargs):
        raise web.HTTPFound(request.app.router[route_name].url_for().with_query(kwargs))

    def process_list(lst):
        for it in lst:
            for k, v in it.items():
                if isinstance(v, bytes):
                    it[k] = v.decode()

    @routes.get('/')
    @aiohttp_jinja2.template('index.html')
    async def index(request):
        return

    @routes.get('/system-overview')
    @aiohttp_jinja2.template('system-overview.html')
    async def system_overview(request):
        metainfo = []
        metainfo.append({"information":"System Prefix", "value": ca.ca_prefix})
        # metainfo.append({"information":"System Anchor", "value": controller.system_anchor})
        metainfo.append({"information": "Approved Certificates", "value": str(len(ca.approved_requests.states))})
        metainfo.append({"information": "Rejected Certificates", "value": str(len(ca.rejected_requests.states))})
        return {'metainfo': metainfo}

    # Approved Certificate Requests List
    @routes.get('/approved-requests')
    @aiohttp_jinja2.template('approved-requests.html')
    async def approved_requests(request):
        ret = []
        for state in ca.approved_requests.states:
            cert_data = parse_certificate(state.issued_cert)
            ret.append({'requestID': bytes(state.id).decode(),
                        'authMean': bytes(state.auth_mean).decode(),
                        'idenKey': bytes(state.iden_key).decode(),
                        'idenValue': bytes(state.iden_value).decode(),
                        'issuedCertName': Name.to_str(cert_data.name)})
        return {'approved-requests': ret}

    # Rejected Certificate Requests List
    @routes.get('/rejected-requests')
    @aiohttp_jinja2.template('rejected-requests.html')
    async def rejected_requests(request):
        ret = []
        for state in ca.rejected_requests.states:
            csr_data = parse_certificate(state.csr)
            ret.append({'requestID': bytes(state.id).decode(),
                        'authMean': bytes(state.auth_mean).decode(),
                        'idenKey': bytes(state.iden_key).decode(),
                        'idenValue': bytes(state.iden_value).decode(),
                        'csrName': Name.to_str(csr_data.name)})
        return {'rejected-requests': ret}

    app.add_routes(routes)
    try:
        web.run_app(app, port=6060)
    finally:
        # ca.save_db()
        pass
    try:
        ca.go()
        app.run_forever() 
    except FileNotFoundError:
        print('Error: could not connect to NFD.')
    return 0


if __name__ == '__main__':
    gui_main()