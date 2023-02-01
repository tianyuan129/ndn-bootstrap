from ndn.encoding import TlvModel, BytesField, UintField, RepeatedField, TypeNumber

TLV_ECDH_PUB_TYPE = 145
TLV_CERT_REQUEST_TYPE = 147

TLV_SALT_TYPE = 149
TLV_REQUEST_ID_TYPE = 151
TLV_CHALLENGE_TYPE = 153

TLV_SELECTED_CHALLENGE_TYPE = 161
TLV_PARAMETER_KEY_TYPE = 133
TLV_PARAMETER_VALUE_TYPE = 135

TLV_STATUS_TYPE = 155
TLV_CHALLENGE_STATUS_TYPE = 163
TLV_REMAINING_TRIES_TYPE = 165
TLV_REMAINING_TIME_TYPE = 167
TLV_ISSUED_CERT_NAME_TYPE = 169

TLV_ERROR_CODE = 171
TLV_ERROR_INFO = 173

STATUS_BEFORE_CHALLENGE = 0
STATUS_CHALLENGE = 1
STATUS_PENDING = 2
STATUS_SUCCESS = 3
STATUS_FAILURE = 4

# possession challenge
CHALLENGE_STATUS_NEED_PROOF = "need-proof";
CHALLENGE_POSS_PARAMETER_KEY_ISSUEDCERT = "issued-cert";
CHALLENGE_POSS_PARAMETER_KEY_NONCE = "nonce";
CHALLENGE_POSS_PARAMETER_KEY_PROOF = "proof";

ERROR_BAD_INTEREST_FORMAT = [1, 'BAD_INTEREST_FORMAT']
ERROR_BAD_PARAMETER_FORMAT = [2, 'BAD_PARAMETER_FORMAT']
ERROR_BAD_SIGNATURE_VALUE_OR_INFO = [3, 'BAD_SIGNATURE_VALUE_OR_INFO']
ERROR_INVALID_PARAMTERS = [4, 'INVALID_PARAMTERS']
ERROR_NAME_NOT_ALLOWED = [5, 'NAME_NOT_ALLOWED']
ERROR_BAD_VALIDITY_PERIOD = [6, 'BAD_VALIDITY_PERIOD']
ERROR_BAD_RAN_OUT_OF_TRIES = [7, 'BAD_RAN_OUT_OF_TRIES']
ERROR_BAD_RAN_OUT_OF_TIMES = [8, 'BAD_RAN_OUT_OF_TRIES']
ERROR_NOT_AVAILABLE_NAMES = [9, 'NOT_AVAILABLE_NAMES']

class Parameter(TlvModel):
    key = BytesField(TLV_PARAMETER_KEY_TYPE, is_string=True)
    value = BytesField(TLV_PARAMETER_VALUE_TYPE)
    
class NewRequest(TlvModel):
    ecdh_pub = BytesField(TLV_ECDH_PUB_TYPE)
    cert_request = BytesField(TLV_CERT_REQUEST_TYPE)

class NewResponse(TlvModel):
    ecdh_pub = BytesField(TLV_ECDH_PUB_TYPE)
    salt = BytesField(TLV_SALT_TYPE)
    request_id = BytesField(TLV_REQUEST_ID_TYPE)
    challenges = RepeatedField(BytesField(TLV_CHALLENGE_TYPE, is_string=True))

# doesn't contain parameters
class ChallengeRequest(TlvModel):
    selected_challenge = BytesField(TLV_SELECTED_CHALLENGE_TYPE, is_string=True)

# doesn't contain parameters
class ChallengeResponse(TlvModel):
    status = UintField(TLV_STATUS_TYPE)
    challenge_status = BytesField(TLV_CHALLENGE_STATUS_TYPE, is_string=True)
    remaining_tries = UintField(TLV_REMAINING_TRIES_TYPE)
    remaining_time = UintField(TLV_REMAINING_TIME_TYPE)
    # note: we cannot use this since parameter itself isn't a tlv
    # parameters = RepeatedField(Parameter)
    issued_cert_name = BytesField(TLV_ISSUED_CERT_NAME_TYPE)
    # forwarding_hint = BytesField(TypeNumber.FORWARDING_HINT)
    forwarding_hint = BytesField(TypeNumber.FORWARDING_HINT)

class ErrorMessage(TlvModel):
    code = UintField(TLV_ERROR_CODE)
    info = BytesField(TLV_ERROR_INFO, is_string=True)
