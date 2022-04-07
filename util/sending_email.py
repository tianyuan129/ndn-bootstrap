import smtplib
import socket
from configparser import ConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def SendingEmail(email: str, param1: str, param2: str, param3: str, config: str):
    socket.setdefaulttimeout(10)
    # open config
    confParser = ConfigParser()
    confParser.read(config)

    # read smtp settings
    encrypt_mode = confParser.get('ndncert_smtp_settings', "ENCRYPT_MODE")
    server = confParser.get('ndncert_smtp_settings', 'SMTP_SERVER')
    port = confParser.get('ndncert_smtp_settings', 'SMTP_PORT')
    username = confParser.get('ndncert_smtp_settings', 'SMTP_USER')
    password = confParser.get('ndncert_smtp_settings', 'SMTP_PASSWORD')

    # read email settings
    msg_from = confParser.get('ndncert_email_settings', 'MAIL_FROM')
    subject = confParser.get('ndncert_email_settings', 'SUBJECT')
    text = confParser.get('ndncert_email_settings', 'TEXT_TEMPLATE').format(param1, param2, param3)
    html = confParser.get('ndncert_email_settings', 'HTML_TEMPLATE').format(param1, param2, param3)

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