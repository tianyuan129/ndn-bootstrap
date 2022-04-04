import asyncio
import time
import os

from util.config import get_yaml
import plyvel
import logging
from ca_storage import *
from ndn.encoding import Name
from PIL import Image
import json
from aiohttp import web
import socketio
import aiohttp_jinja2
import jinja2
from datetime import datetime
import base64

from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate

ca_prefix = 'N/A'
approved_requests = IssuedCertStates()
rejected_requests = RejectedCertStates()

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
        global ca_prefix, approved_requests, rejected_requests

        db = plyvel.DB(os.path.expanduser('~/.ndncert-ca-python/'))
        db_result = db.get(b'ca_prefix')
        if db_result:
           ca_prefix = db_result.decode()

        db_result = db.get(b'approved_requests')
        if db_result:
            approved_requests = IssuedCertStates.parse(db_result)

        db_result = db.get(b'rejected_requests')
        if db_result:
            rejected_requests = RejectedCertStates.parse(db_result)
        db.close()

        metainfo = []
        metainfo.append({"information":"System Prefix", "value": ca_prefix})
        # metainfo.append({"information":"System Anchor", "value": controller.system_anchor})
        metainfo.append({"information": "Approved Certificates", "value": str(len(approved_requests.states))})
        metainfo.append({"information": "Rejected Certificates", "value": str(len(rejected_requests.states))})
        return {'metainfo': metainfo}

    # Approved Certificate Requests List
    @routes.get('/approved-requests')
    @aiohttp_jinja2.template('approved-requests.html')
    async def approved_requests(request):
        global approved_requests

        db = plyvel.DB(os.path.expanduser('~/.ndncert-ca-python/'))
        db_result = db.get(b'approved_requests')
        db.close()
        if db_result:
            approved_requests = IssuedCertStates.parse(db_result)

        ret = []
        for state in approved_requests.states:
            cert_data = parse_certificate(state.issued_cert)
            ret.append({'requestId':  base64.b64encode(state.id).decode(),
                        'authMean': bytes(state.auth_mean).decode(),
                        'idenKey': bytes(state.iden_key).decode(),
                        'idenValue': bytes(state.iden_value).decode(),
                        'issuedCertName': Name.to_str(cert_data.name)})
        if len(ret) < 1:
            ret.append({'requestId': 'N/A',
                        'authMean': 'N/A',
                        'idenKey': 'N/A',
                        'idenValue': 'N/A',
                        'issuedCertName': 'N/A'})
        return {'approved_requests': ret}

    # Rejected Certificate Requests List
    @routes.get('/rejected-requests')
    @aiohttp_jinja2.template('rejected-requests.html')
    async def rejected_requests(request):
        global rejected_requests

        db = plyvel.DB(os.path.expanduser('~/.ndncert-ca-python/'))
        db_result = db.get(b'rejected_requests')
        db.close()
        if db_result:
            rejected_requests = RejectedCertStates.parse(db_result)

        ret = []
        for state in rejected_requests.states:
            csr_data = parse_certificate(state.csr)
            ret.append({'requestId': base64.b64encode(state.id).decode(),
                        'authMean': bytes(state.auth_mean).decode(),
                        'idenKey': bytes(state.iden_key).decode(),
                        'idenValue': bytes(state.iden_value).decode(),
                        'csrName': Name.to_str(csr_data.name)})
        if len(ret) < 1:
            ret.append({'requestId': 'N/A',
                        'authMean': 'N/A',
                        'idenKey': 'N/A',
                        'idenValue': 'N/A',
                        'csrName': 'N/A'})
        return {'rejected_requests': ret}

    app.add_routes(routes)
    try:
        web.run_app(app, port=6060)
    finally:
        # ca.save_db()
        pass

if __name__ == '__main__':
    gui_main()