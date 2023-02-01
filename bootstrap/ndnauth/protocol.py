from ndn.encoding import TlvModel, BytesField, UintField, ModelField
from ..crypto_tools import EncryptedMessage

# ApplicationParameters = APPLICATION-PARAMETERS-TYPE TLV-LENGTH
#                         ecdh-pub
#                         cert-request
# ecdh-pub = ECDH-PUB-TYPE
#            TLV-LENGTH ; == 65
#            65OCTET
# cert-request = CERT-REQUEST-TYPE TLV-LENGTH *OCTET
TLV_ECDH_PUB_TYPE = 145
TLV_PUBKEY_TYPE = 147
TLV_PARAMETER_KEY_TYPE = 133
TLV_PARAMETER_VALUE_TYPE = 135

class Parameter(TlvModel):
    key = BytesField(TLV_PARAMETER_KEY_TYPE)
    value = BytesField(TLV_PARAMETER_VALUE_TYPE)

class NewRequest(TlvModel):
    ecdh_pub = BytesField(TLV_ECDH_PUB_TYPE)
    pubkey = BytesField(TLV_PUBKEY_TYPE)
    auth_type = BytesField(TLV_PARAMETER_KEY_TYPE)
    auth_id = BytesField(TLV_PARAMETER_VALUE_TYPE)

# Content = CONTENT-TYPE TLV-LENGTH
#           ecdh-pub
#           salt
#           request-id
#           1*AUTHENTICATION
# ecdh-pub = ECDH-PUB-TYPE
#            TLV-LENGTH ; == 65
#            65OCTET
# salt = SALT-TYPE
#        TLV-LENGTH ; == 32
#        32OCTET
# request-id = REQUEST-ID-TYPE
#              TLV-LENGTH ; == 8
#              8OCTET
# AUTHENTICATION = AUTHENTICATION-TYPE
#             TLV-LENGTH
#             *OCTET
TLV_SALT_TYPE = 149
TLV_REQUEST_ID_TYPE = 151
TLV_AUTHENTICATION_TYPE = 153
TLV_STATUS_TYPE = 155

class NewResponse(TlvModel):
    ecdh_pub = BytesField(TLV_ECDH_PUB_TYPE)
    salt = BytesField(TLV_SALT_TYPE)
    request_id = BytesField(TLV_REQUEST_ID_TYPE)
    
    # optional
    parameter_key = BytesField(TLV_PARAMETER_KEY_TYPE)
    parameter_value = BytesField(TLV_PARAMETER_VALUE_TYPE)

# ApplicationParameters = APPLICATION-PARAMETERS-TYPE TLV-LENGTH encrypted-message

# ; the plaintext before encryption
# plaintext = selected-AUTHENTICATION
#             1*(parameter-key parameter-value)
# selected-AUTHENTICATION = SELECTED-AUTHENTICATION-TYPE TLV-LENGTH *OCTET
# parameter-key = PARAMETER-KEY-TYPE TLV-LENGTH *OCTET
# parameter-value = PARAMETER-VALUE-TYPE TLV-LENGTH *OCTET
class AuthenticateRequest(TlvModel):
    parameter_key = BytesField(TLV_PARAMETER_KEY_TYPE)
    parameter_value = BytesField(TLV_PARAMETER_VALUE_TYPE)

# Content = CONTENT-TYPE TLV-LENGTH encrypted-message

# ; the plaintext before encryption
# plaintext = plaintext-success / plaintext-failure / plaintext-AUTHENTICATION
# plaintext-success = status ; ==3
#                     [AUTHENTICATION-status]
#                     issued-cert-name
#                     [ForwardingHint]
# plaintext-failure = status ; ==4
#                     [AUTHENTICATION-status]
# plaintext-AUTHENTICATION = status ; ==1
#                       AUTHENTICATION-status
#                       remaining-tries
#                       remaining-time
#                       *(parameter-key parameter-value)
# status = STATUS-TYPE TLV-LENGTH NonNegativeInteger
# AUTHENTICATION-status = AUTHENTICATION-STATUS-TYPE TLV-LENGTH *OCTET
# remaining-tries = REMAINING-TRIES-TYPE TLV-LENGTH NonNegativeInteger
# remaining-time = REMAINING-TIME-TYPE TLV-LENGTH NonNegativeInteger
# issued-cert-name = ISSUED-CERT-NAME-TYPE TLV-LENGTH Name
TLV_ISSUED_POP = 169

class AuthenticateResponse(TlvModel):
    status = UintField(TLV_STATUS_TYPE)
    proof_of_possess = BytesField(TLV_ISSUED_POP)
    
    # optional
    parameter_key = BytesField(TLV_PARAMETER_KEY_TYPE)
    parameter_value = BytesField(TLV_PARAMETER_VALUE_TYPE)



TLV_LOCAL_PREFIX_TYPE = 129
TLV_LOCAL_FORWARDER_TYPE = 131
class ConnectvityInfo(TlvModel):
    local_prefix = BytesField(TLV_LOCAL_PREFIX_TYPE)
    local_forwarder = BytesField(TLV_LOCAL_FORWARDER_TYPE)
    
TLV_ECDB_PUB_TYPE = 133
TLV_EMAIL_ADDRESS_TYPE = 135
TLV_CERT_REQUEST_TYPE = 137
class BootParamsResponseUserInner(TlvModel):
    ecdh_pub = BytesField(TLV_ECDB_PUB_TYPE)
    email = BytesField(TLV_EMAIL_ADDRESS_TYPE)
    cert_request = BytesField(TLV_CERT_REQUEST_TYPE)

TLV_BOOT_PARAMS_RES_USER_TYPE = 201
class BootParamsResponseUser(TlvModel):
    inner = ModelField(TLV_BOOT_PARAMS_RES_USER_TYPE, BootParamsResponseUserInner)

TLV_X509_CHAIN_TYPE = 139
class BootParamsResponseServerInner(TlvModel):
    x509_chain = BytesField(TLV_X509_CHAIN_TYPE)

TLV_BOOT_PARAMS_RES_SERVER_TYPE = 203
class BootParamsResponseServer(TlvModel):
    inner = ModelField(TLV_BOOT_PARAMS_RES_SERVER_TYPE, BootParamsResponseServerInner)

TLV_SALT_TYPE = 141
class BootResponseUser(TlvModel):
    ecdh_pub = BytesField(TLV_ECDB_PUB_TYPE)
    salt = BytesField(TLV_SALT_TYPE)

TLV_RAND_TYPE = 143
class BootResponseServer(TlvModel):
    rand = BytesField(TLV_RAND_TYPE)

TLV_ENCRYPTED_CODE_TYPE = 145
class IdProofParamsUser(TlvModel):
    encrypted_code = ModelField(TLV_ENCRYPTED_CODE_TYPE, EncryptedMessage)

TLV_SIGNED_RAND_TYPE = 147
class IdProofParamsServer(TlvModel):
    signed_rand = BytesField(TLV_SIGNED_RAND_TYPE)

TLV_PROOF_OF_POSSESSION_TYPE = 159
class IdProofResponse(TlvModel):
    proof_of_possess = BytesField(TLV_PROOF_OF_POSSESSION_TYPE)


TLV_ERROR_CODE = 171
TLV_ERROR_INFO = 173
class ErrorMessage(TlvModel):
    code = UintField(TLV_ERROR_CODE)
    info = BytesField(TLV_ERROR_INFO)
ERROR_BAD_INTEREST_FORMAT = [1, 'Bad Interest Format: the Interest format is incorrect, e.g., no ApplicationParameters.']
ERROR_BAD_PARAMETER_FORMAT = [2, 'Bad Interest Parameter Format: the ApplicationParameters field is not correctly formed.']
ERROR_BAD_SIGNATURE_VALUE_OR_INFO = [3, 'Bad Signature or signature info: the Interest carries an invalid signature.']
ERROR_BAD_RESPONSE_FORMAT = [4, 'Bad Response Format: Bootstrapping Parameters Response or Identity Proof Parameter Response is not correctly formed.']
ERROR_IDENTITY_NOT_ALLOWED = [5, 'Identity not allowed: the provided email address or X.509 common name is not allowed by controller.']
ERROR_BAD_IDENTITY_PROOF = [6, 'Bad Identity Proof: provided identity proof parameter cannot be verified, e.g., wrong email verification code.']