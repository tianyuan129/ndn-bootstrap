from urllib import request
from ndn.encoding import TlvModel, BytesField, UintField, ModelField, RepeatedField, NameField, TypeNumber

# ApplicationParameters = APPLICATION-PARAMETERS-TYPE TLV-LENGTH
#                         ecdh-pub
#                         cert-request
# ecdh-pub = ECDH-PUB-TYPE
#            TLV-LENGTH ; == 65
#            65OCTET
# cert-request = CERT-REQUEST-TYPE TLV-LENGTH *OCTET
TLV_ECDH_PUB_TYPE = 145
TLV_CERT_REQUEST_TYPE = 147

class NewRequest(TlvModel):
    ecdh_pub = BytesField(TLV_ECDH_PUB_TYPE)
    cert_request = BytesField(TLV_CERT_REQUEST_TYPE)

# Content = CONTENT-TYPE TLV-LENGTH
#           ecdh-pub
#           salt
#           request-id
#           1*challenge
# ecdh-pub = ECDH-PUB-TYPE
#            TLV-LENGTH ; == 65
#            65OCTET
# salt = SALT-TYPE
#        TLV-LENGTH ; == 32
#        32OCTET
# request-id = REQUEST-ID-TYPE
#              TLV-LENGTH ; == 8
#              8OCTET
# challenge = CHALLENGE-TYPE
#             TLV-LENGTH
#             *OCTET
TLV_SALT_TYPE = 149
TLV_REQUEST_ID_TYPE = 151
TLV_CHALLENGE_TYPE = 153

class NewResponse(TlvModel):
    ecdh_pub = BytesField(TLV_ECDH_PUB_TYPE)
    salt = BytesField(TLV_SALT_TYPE)
    request_id = BytesField(TLV_REQUEST_ID_TYPE)
    challenges = RepeatedField(BytesField(TLV_CHALLENGE_TYPE, is_string=True))
    
# encrypted-message = initialization-vector
#                     authentication-tag
#                     encrypted-payload
# initialization-vector = INITIALIZATION-VECTOR-TYPE
#                         TLV-LENGTH ; == 12
#                         12OCTET
# authentication-tag = AUTHENTICATION-TAG-TYPE
#                      TLV-LENGTH ; == 16
#                      16OCTET
# encrypted-payload = ENCRYPTED-PAYLOAD-TYPE TLV-LENGTH *OCTET
TLV_INITIALIZATION_VECTOR_TYPE = 157
TLV_AUTHENTICATION_TAG_TYPE = 175
TLV_ENCRYPTED_PAYLOAD_TYPE = 159

class EncryptedMessage(TlvModel):
    iv = BytesField(TLV_INITIALIZATION_VECTOR_TYPE)
    tag = BytesField(TLV_AUTHENTICATION_TAG_TYPE)
    payload = BytesField(TLV_ENCRYPTED_PAYLOAD_TYPE)

# ApplicationParameters = APPLICATION-PARAMETERS-TYPE TLV-LENGTH encrypted-message

# ; the plaintext before encryption
# plaintext = selected-challenge
#             1*(parameter-key parameter-value)
# selected-challenge = SELECTED-CHALLENGE-TYPE TLV-LENGTH *OCTET
# parameter-key = PARAMETER-KEY-TYPE TLV-LENGTH *OCTET
# parameter-value = PARAMETER-VALUE-TYPE TLV-LENGTH *OCTET
TLV_SELECTED_CHALLENGE_TYPE = 161
TLV_PARAMETER_KEY_TYPE = 133
TLV_PARAMETER_VALUE_TYPE = 135

class Parameter(TlvModel):
    key = BytesField(TLV_PARAMETER_KEY_TYPE)
    value = BytesField(TLV_PARAMETER_VALUE_TYPE)
    
class ChallengeRequest(TlvModel):
    selected_challenge = BytesField(TLV_SELECTED_CHALLENGE_TYPE)
    parameter_key = BytesField(TLV_PARAMETER_KEY_TYPE)
    parameter_value = BytesField(TLV_PARAMETER_VALUE_TYPE)

# Content = CONTENT-TYPE TLV-LENGTH encrypted-message

# ; the plaintext before encryption
# plaintext = plaintext-success / plaintext-failure / plaintext-challenge
# plaintext-success = status ; ==3
#                     [challenge-status]
#                     issued-cert-name
#                     [ForwardingHint]
# plaintext-failure = status ; ==4
#                     [challenge-status]
# plaintext-challenge = status ; ==1
#                       challenge-status
#                       remaining-tries
#                       remaining-time
#                       *(parameter-key parameter-value)
# status = STATUS-TYPE TLV-LENGTH NonNegativeInteger
# challenge-status = CHALLENGE-STATUS-TYPE TLV-LENGTH *OCTET
# remaining-tries = REMAINING-TRIES-TYPE TLV-LENGTH NonNegativeInteger
# remaining-time = REMAINING-TIME-TYPE TLV-LENGTH NonNegativeInteger
# issued-cert-name = ISSUED-CERT-NAME-TYPE TLV-LENGTH Name
TLV_STATUS_TYPE = 155
TLV_CHALLENGE_STATUS_TYPE = 163
TLV_REMAINING_TRIES_TYPE = 165
TLV_REMAINING_TIME_TYPE = 167
TLV_ISSUED_CERT_NAME_TYPE = 169

class ChallengeResponse(TlvModel):
    status = UintField(TLV_STATUS_TYPE)
    challenge_status = BytesField(TLV_CHALLENGE_STATUS_TYPE)
    remaining_tries = UintField(TLV_REMAINING_TRIES_TYPE)
    remaining_time = UintField(TLV_REMAINING_TIME_TYPE)
    # parameters = RepeatedField(Parameter)
    issued_cert_name = BytesField(TLV_ISSUED_CERT_NAME_TYPE)
    forwarding_hint = BytesField(TypeNumber.FORWARDING_HINT)



# 0: STATUS_BEFORE_CHALLENGE, the requester has not selected a challenge.
# 1: STATUS_CHALLENGE, the challenge is in progress.
# 2: STATUS_PENDING, the challenge is finished, but not yet approved by the CA.
# 3: STATUS_SUCCESS, the challenge is finished, and the CA has approved the result.
# 4: STATUS_FAILURE, the challenge has failed.
STATUS_BEFORE_CHALLENGE = 0
STATUS_CHALLENGE = 1
STATUS_PENDING = 2
STATUS_SUCCESS = 3
STATUS_FAILURE = 4


CHALLENGE_STATUS_NEED_CODE = "need-code";
CHALLENGE_STATUS_WRONG_CODE = "wrong-code";
CHALLENGE_STATUS_PARAMETER_KEY_EMAIL = "email";
CHALLENGE_STATUS_PARAMETER_KEY_CODE = "code";