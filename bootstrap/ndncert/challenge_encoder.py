from typing import List
from ndn.encoding import parse_tl_num

from .protocol_v3 import *
from .cert_state import *
from ..crypto_tools import *

def get_parameter_keys(selected_challenge: str, status: int, packet_format: str) -> List[str]:
    _keys = {
        'possession': {
            STATUS_BEFORE_CHALLENGE: {
                'request': ['issued-cert']
            },
            STATUS_CHALLENGE: {
                'request': ['proof'],
                'response': ['nonce']
            },
            STATUS_SUCCESS: {
                'response': []
            },
            STATUS_FAILURE: {
                'response': []
            },
        }
    }
    return _keys[selected_challenge][status][packet_format]

class ChallengeEncoder(object):
    def __init__(self, id):
        self.cert_state = CertState()
        self.cert_state.id = id

    @staticmethod
    def _probe_parameter_list(buf, offset) -> int:
        while offset < len(buf):
            tlv_type, tlv_type_size = parse_tl_num(buf[offset:])
            tlv_length, tlv_length_size = parse_tl_num(buf[offset + tlv_type_size:])
            if tlv_type == TLV_PARAMETER_KEY_TYPE:
                return offset
            else:
                offset += tlv_type_size + tlv_length_size + tlv_length
        return offset
        
    @staticmethod
    def _parse_parameter_list(buf, offset) -> List[Parameter]:
        parameters = []
        while offset < len(buf):
            tlv_type, tlv_type_size = parse_tl_num(buf[offset:])
            offset += tlv_type_size
            tlv_length, tlv_length_size = parse_tl_num(buf[offset:])
            offset += tlv_length_size
            tlv_value = buf[offset : offset + tlv_length]
            if tlv_type == TLV_PARAMETER_KEY_TYPE:
                parameter = Parameter()
                parameter.key = tlv_value
                parameters.append(parameter)
            elif tlv_type == TLV_PARAMETER_VALUE_TYPE:
                if parameters[-1].value == None:
                    parameters[-1].value = tlv_value
            offset += tlv_length
        return parameters
    def prepare_challenge_request(self, parameter_keys: List[str]) -> bytearray:
        request = ChallengeRequest()
        request.selected_challenge = self.cert_state.selected_challenge
        # encode parameters
        parameter_buf = []
        for parameter_key in parameter_keys:
            parameter_buf += self.cert_state.encode_parameter(parameter_key)
        # concatentaion
        return request.encode() + bytearray(parameter_buf)

    def parse_challenge_request(self, plaintext: bytes):
        offset = self._probe_parameter_list(plaintext, offset = 0)
        request = ChallengeRequest.parse(plaintext[:offset])
        self.cert_state.selected_challenge = request.selected_challenge
        # parsing parameters
        parameters = self._parse_parameter_list(plaintext, offset)
        for parameter in parameters:
            self.cert_state.parameters.append(parameter)

    def prepare_challenge_response(self, parameter_keys: List[str]) -> bytearray:        
        response = ChallengeResponse()
        response.status = self.cert_state.status
        response.challenge_status = self.cert_state.challenge_status
        response.remaining_time = self.cert_state.remaining_time
        response.remaining_tries = self.cert_state.remaining_tries
        if self.cert_state.issued_cert_name is not None:
            response.issued_cert_name = self.cert_state.issued_cert_name
            response.forwarding_hint = self.cert_state.forwarding_hint
        # encode parameters
        parameter_buf = []
        for parameter_key in parameter_keys:
            parameter_buf += self.cert_state.encode_parameter(parameter_key)
        # concatentaion
        return response.encode() + bytearray(parameter_buf)
    
    def parse_challenge_response(self, plaintext: bytes):
        offset = self._probe_parameter_list(plaintext, offset = 0)
        response = ChallengeResponse.parse(plaintext[:offset])
        self.cert_state.status = response.status
        self.cert_state.challenge_status = response.challenge_status
        self.cert_state.remaining_time = response.remaining_time
        self.cert_state.remaining_tries = response.remaining_tries
        if response.issued_cert_name is not None:
            self.cert_state.issued_cert_name = response.issued_cert_name
        if response.forwarding_hint is not None:
            self.cert_state.forwarding_hint = response.forwarding_hint
        
        parameters = self._parse_parameter_list(plaintext, offset)
        for parameter in parameters:
            self.cert_state.parameters.append(parameter)