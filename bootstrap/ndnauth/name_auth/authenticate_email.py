from typing import Tuple, Dict

import logging, os
from random import randint

from ..protocol import *
from ..auth_state import AuthState
from ...crypto_tools import *

import smtplib
import socket
from configparser import ConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .authenticate import Authenticator


class EmailAuthenticator(Authenticator):
    def __init__(self, config: Dict):
        self.config = config
        self.email_sender = lambda email, secret : getattr(__class__, self.config['email_sender'])(self, email, secret)

    def sender_default(self, email: str, secret: str):
        socket.setdefaulttimeout(10)
        # open config
        confParser = ConfigParser()
        
        if self.config['email_template'] == 'template_default.conf':
            dirname = os.path.dirname(__file__)
            self.config['email_template'] = os.path.join(dirname, 'template_default.conf')       
        confParser.read(self.config['email_template'])

        # read smtp settings
        encrypt_mode = confParser.get('ndnauth_smtp_settings', "ENCRYPT_MODE")
        server = confParser.get('ndnauth_smtp_settings', 'SMTP_SERVER')
        port = confParser.get('ndnauth_smtp_settings', 'SMTP_PORT')
        username = confParser.get('ndnauth_smtp_settings', 'SMTP_USER')
        password = confParser.get('ndnauth_smtp_settings', 'SMTP_PASSWORD')

        # read email settings
        msg_from = confParser.get('ndnauth_email_settings', 'MAIL_FROM')
        subject = confParser.get('ndnauth_email_settings', 'SUBJECT')
        text = confParser.get('ndnauth_email_settings', 'TEXT_TEMPLATE').format(secret, self.config['name_in_email'])
        html = confParser.get('ndnauth_email_settings', 'HTML_TEMPLATE').format(secret, self.config['name_in_email'])

        # form email message
        msg = MIMEMultipart('alternative')
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        msg['From'] = msg_from
        msg['To'] = email
        msg['Subject'] = subject

        # send email
        if encrypt_mode == 'ssl':
            smtp_server = smtplib.SMTP_SSL(server, port)
        else: # none or tls
            smtp_server = smtplib.SMTP(server, port)

        if encrypt_mode != 'none':
            smtp_server.ehlo()
            if encrypt_mode == 'tls':
                smtp_server.starttls()

        if username != '' and password != '':
            smtp_server.login(username, password)

        smtp_server.sendmail(msg_from, email, msg.as_string())
        smtp_server.close()

    async def actions_before_authenticate(self, auth_state: AuthState) -> Tuple[AuthState, ErrorMessage]:
        ret = auth_state
        email = bytes(ret.auth_id).decode("utf-8")
        PINCODE_SIZE = 6
        secret = ''
        for i in range(PINCODE_SIZE):
            secret += str(randint(0,9))
        logging.info(f'Secret for Request ID {ret.id.hex()} is {secret}')
        
        # self.email_sender(email, secret)
        ret.auth_key = AUTHENTICATION_EMAIL_PARAMETER_KEY_CODE.encode()
        # ret.auth_cache = secret.encode()
        ret.auth_cache = '1234'.encode()
        ret.status = STATUS_AUTHENTICATION
        return ret, None

    async def actions_continue_authenticate(self, auth_state: AuthState) -> Tuple[AuthState, ErrorMessage]:
        ret = auth_state
        if ret.auth_value == ret.auth_cache:
            logging.info(f'Identity verification succeed, should issue proof-of-possession')
            ret.status = STATUS_PENDING
            return ret, None
        else:
            errs = ErrorMessage()
            errs.code = ERROR_BAD_RAN_OUT_OF_TRIES[0]
            errs.info = ERROR_BAD_RAN_OUT_OF_TRIES[1].encode()
            logging.error('Identity verification failed, returning errors {ERROR_BAD_RAN_OUT_OF_TRIES[1]}')
            return None, errs
