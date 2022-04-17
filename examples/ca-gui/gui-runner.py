import os

import plyvel
import logging
from bootstrap.ndncert.proto.ca_storage import *
from ndn.encoding import Name
from aiohttp import web
import socketio
import aiohttp_jinja2
import jinja2
from datetime import datetime, timedelta
import base64

from ndn.app import NDNApp
from ndn.app_support.security_v2 import parse_certificate

ca_prefix = 'N/A'
approved_requests = IssuedCertStates()
rejected_requests = RejectedCertStates()

rejected_bindings = IdentityBindingList()
approved_bindings = IdentityBindingList()

def gui_main():

    logging.basicConfig(format='[{asctime}]{levelname}:{message}', datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG, style='{')

    base_path = os.getcwd() + '/gui'
    # Serve static content from /static
    app = web.Application()
    
    dirname = os.path.dirname(__file__)
    base_path = os.path.join(dirname, 'gui')
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
        return {'rejected_requests': ret}

    # Rejected Identity Binding List
    @routes.get('/rejected-bindings')
    @aiohttp_jinja2.template('rejected-bindings.html')
    async def rejected_requests(request):
        global rejected_bindings

        db = plyvel.DB(os.path.expanduser('~/.ndncert-ca-python/'))
        db_result = db.get(b'rejected_bindings')
        db.close()
        if db_result:
            rejected_bindings = IdentityBindingList.parse(db_result)

        ret = []
        for binding in rejected_bindings.bindings:
            date_time = datetime.fromtimestamp(binding.timestamp)
            ret.append({'bindingId': str(binding.id),
                        'authMean': bytes(binding.auth_mean).decode(),
                        'idenKey': bytes(binding.iden_key).decode(),
                        'idenValue': bytes(binding.iden_value).decode(),
                        'name': Name.to_str(binding.name),
                        'effTimestamp': date_time.strftime("%Y/%m/%d, %H:%M:%S")})
        print(ret)
        return {'rejected_bindings': ret}

    # Approved Identity Binding List
    @routes.get('/approved-bindings')
    @aiohttp_jinja2.template('approved-bindings.html')
    async def rejected_requests(request):
        global approved_bindings

        db = plyvel.DB(os.path.expanduser('~/.ndncert-ca-python/'))
        db_result = db.get(b'approved_bindings')
        db.close()
        if db_result:
            approved_bindings = IdentityBindingList.parse(db_result)

        # clean up all expired bindings
        approved_bindings.bindings = [binding for binding in approved_bindings.bindings
                                      if binding.timestamp and 
                                         binding.timestamp > int(datetime.utcnow().timestamp())]
        print(len(approved_bindings.bindings))

        ret = []
        for binding in approved_bindings.bindings:
            date_time = datetime.fromtimestamp(binding.timestamp)
            ret.append({'bindingId': str(binding.id),
                        'authMean': bytes(binding.auth_mean).decode(),
                        'idenKey': bytes(binding.iden_key).decode(),
                        'idenValue': bytes(binding.iden_value).decode(),
                        'name': Name.to_str(binding.name),
                        'expiresAt': date_time.strftime("%Y/%m/%d, %H:%M:%S")})
        return {'approved_bindings': ret}

    @routes.post('/approve/rejected-bindings')
    async def approve_rejected(request):
        global rejected_bindings, approved_bindings
        data = await request.json()
        
        # get the rejected list
        db = plyvel.DB(os.path.expanduser('~/.ndncert-ca-python/'))
        db_result = db.get(b'rejected_bindings')
        user_approved = IdentityBinding()
        # db.close()
        if db_result:
            rejected_bindings = IdentityBindingList.parse(db_result)
            for binding in rejected_bindings.bindings:
                if binding.id == int(data['bindingId']):
                    user_approved = binding
            
            rejected_bindings.bindings = [binding for bindings in rejected_bindings.bindings
                                           if binding.id != int(data['bindingId'])]
            db.put(b'rejected_bindings', rejected_bindings.encode())

        # if found one
        if user_approved.timestamp is not None:
            start_time = datetime.utcnow()
            end_time = start_time + timedelta(hours=1)
            user_approved.timestamp = int(end_time.timestamp())

        # write to approved list
        db_result = db.get(b'approved_bindings')
        approved_bindings = IdentityBindingList()
        not_found = True
        if db_result:
            approved_bindings = IdentityBindingList.parse(db_result)            
            for approved in approved_bindings.bindings:
                if approved.auth_mean == user_approved.auth_mean or \
                   approved.iden_key == user_approved.iden_key or \
                   approved.iden_value == user_approved.iden_value or \
                   approved.name == user_approved.name:
                   not_found = False
        
        if not_found:
            approved_bindings.bindings.append(user_approved)
        print(len(approved_bindings.bindings))
        db.put(b'approved_bindings', approved_bindings.encode())
        db.close()
        return web.json_response({"st_code": 200})

    app.add_routes(routes)
    try:
        web.run_app(app, port=6060)
    finally:
        # ca.save_db()
        pass

if __name__ == '__main__':
    gui_main()