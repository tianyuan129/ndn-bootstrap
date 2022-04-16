from calendar import c
from traceback import print_tb
from typing import List

from ndn.encoding import Name, FormalName, Component

lvs_template = r'''
#KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
#NewResponse: /site/"auth"/CA/_func/_ & { _func: "NEW"} <= #Anchor
#ChaResponse: /site/"auth"/CA/_func/_/_param & { _func: "CHALLENGE" } <= #Anchor
#NewResponse2: /site/"cert"/CA/_func/_ & { _func: "NEW"} <= #Issuer
#ChaResponse2: /site/"cert"/CA/_func/_/_param & { _func: "CHALLENGE" } <= #Issuer
#TmpCert: /site/"auth"/_/#KEY <= #Anchor 
#FormalCert: /site/_/#KEY <= #Issuer
#Issuer: /site/"cert"/#KEY <= #Anchor
#Anchor: /site/#KEY
'''

TEMPLATE_KEY = '''
#KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
'''
TEMPLATE_DELEGATEDKEY = '''
#DELEGATEDKEY: "KEY"/_/"Anchor"/_version & { _version: $eq_type("v=0") }
'''
TEMPLATE_ANCHOR_RULE = '''
#Anchor: {zone_pattern}/#KEY
'''
TEMPLATE_TMPCERT_RULE = '''
#TmpCert: {zone_pattern}{variable_pattern}/#{key} <= #{signer}
'''
TEMPLATE_GENERIC_CERT_RULE = '''
#{signee}: {zone_pattern}{variable_pattern}/#{key} <= #{signer}
'''
TEMPLATE_NDNCERT1_DATA_RULE = '''
#NewResponse: {zone_pattern}/"CA"/"NEW"/_ <= #Anchor
#ChaResponse: {zone_pattern}/"CA"/"CHALLENGE"/_/_param <= #Anchor
'''
TEMPLATE_NDNCERT2_DATA_RULE = '''
#NewResponse2: {zone_pattern}{variable_pattern}/"CA"/"NEW"/_ <= #{issuer}
#ChaResponse2: {zone_pattern}{variable_pattern}/"CA"/"CHALLENGE"/_/_param <= #{issuer}
'''

TEMPLATE_NDNCERT_DATA_RULE = '''
#NewResponse{index}: {zone_pattern}{variable_pattern}/"CA"/"NEW"/_ <= #{issuer}
#ChaResponse{index}: {zone_pattern}{variable_pattern}/"CA"/"CHALLENGE"/_/_param <= #{issuer}
'''

TEMPLATE_GENERIC_DATA_RULE = '''#{rule}: {zone_pattern}{variable_pattern}'''
TEMPLATE_GENERIC_SIGNER = ' <= #{signer}\n'
TEMPLATE_GENERIC_CONSTRAINT = '{comp}: {condition}'
TEMPLATE_GENERIC_CONSTRAINTS = ' & {{{constraints}}}'
TEMPLATE_GENERIC_DATA_RULE2= '''
#{rule}: {zone_pattern}{variable_pattern} & {{{constraints}}} <= #{signer}
'''

class VarLenName(object):
    def __init__(self):
        pass

# each component is a temporary component
def gen_temp_pattern(len):
    i = 0
    _temp_pattern = ''
    while i < len:
        _temp_pattern += '/_' + str(i)
        i += 1
    return _temp_pattern

# The pattern meaning will continue hold across the rules!
def gen_schematized_pattern(params: List[str]):
    _schematized_pattern = ''
    for param in params:
        _schematized_pattern += '/' + str(param)
    return _schematized_pattern

# fill name components into temp patterns as its value
def _harden(var_name, params):
    _hardend = var_name
    for count, param in enumerate(params):
        comp = '"' + param + '"'
        _hardend = _hardend.replace('_' + str(count), comp)
    return _hardend

def name_to_hardened_pattern(name: FormalName):
    var_name = gen_temp_pattern(len(name))
    mapping = []
    for comp in name:
        mapping.append(Component.to_str(comp))
    return _harden(var_name, mapping)

# template instantiation
def define_key():
    return TEMPLATE_KEY

def define_delagatedkey():
    return TEMPLATE_DELEGATEDKEY

def define_tmpcert(zone_name: FormalName, variable_pattern: str, key = 'KEY', signer = 'Anchor'):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_TMPCERT_RULE.format(zone_pattern = _zone_pattern,
                                        variable_pattern = variable_pattern,
                                        key = key,
                                        signer = signer)
# when defining a cert rule, one must know who is the signer and signee
def define_generic_cert(zone_name: FormalName, variable_pattern: str, signee: str, signer: str, key = 'KEY'):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_GENERIC_CERT_RULE.format(zone_pattern = _zone_pattern,
                                        variable_pattern = variable_pattern,
                                        key = key,
                                        signee = signee,
                                        signer = signer)

def define_anchor(zone_name: FormalName):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_ANCHOR_RULE.format(zone_pattern = _zone_pattern)

# if issuer is the anchor
def define_ndncert1_proto(zone_name: FormalName):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_NDNCERT1_DATA_RULE.format(zone_pattern = _zone_pattern)    

# if issuer is *NOT* the anchor
# this should be the generic ndncert proto definition
def define_ndncert_proto(zone_name: FormalName, **kwargs):
                        #   variable_name: FormalName, issuer: str, harden: bool = False):
    # format rule index
    if 'index' in kwargs:
        _index = kwargs['index']
    else:
        _index = 0
    
    _zone_pattern = name_to_hardened_pattern(zone_name)
    
    # format issuer varname
    _issuer_varname = ''
    _issuer_varpattern = ''
    if 'issuer_var' in kwargs:
        _issuer_varname = kwargs['issuer_var']
        _issuer_varpattern = gen_temp_pattern(len(_issuer_varname))
        if 'harden' in kwargs:
            harden = kwargs['harden']
            if harden:
                _issuer_varpattern = name_to_hardened_pattern(_issuer_varname)
    
    # format issuer id
    if 'issuer_id' in kwargs:
        _issuer_id = kwargs['issuer_id']
        _issuer_id.capitalize()
    else:
        _issuer_id = 'Anchor'
    return TEMPLATE_NDNCERT_DATA_RULE.format(index = _index, zone_pattern = _zone_pattern,
                                             variable_pattern = _issuer_varpattern,
                                             issuer = _issuer_id)
    
def _prepare_signer(signer: str):    
    return TEMPLATE_GENERIC_SIGNER.format(signer = signer)

def _prepare_constraint(comp: str, condition: str):
    return TEMPLATE_GENERIC_CONSTRAINT.format(comp = comp, condition = condition)

def _prepare_constraints(constraints: List[str]):
    _constraints = ''
    for count, constraint in enumerate(constraints):
        if count < len(constraints) - 1:
            _constraints += constraint + ', '
        else:
            _constraints += constraint
    return TEMPLATE_GENERIC_CONSTRAINTS.format(constraints = _constraints)

def define_generic_data_rule(rule: str, zone_name: FormalName, **kwargs):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    _variable_pattern = ''
    _prepared_constraints = ''
    _prepared_signer = ''
    if 'constraints' in kwargs:
        constraint_list = kwargs['constraints']
        _constraints_assem = []
        for constraint in constraint_list:
            _constraints_assem.append(_prepare_constraint(constraint[0], constraint[1]))
        _prepared_constraints = _prepare_constraints(_constraints_assem)
    if 'variable_pattern' in kwargs:
        # todo: more customzied pattern
        _variable_pattern = kwargs['variable_pattern']
    if 'signer' in kwargs:
        _prepared_signer = _prepare_signer(kwargs['signer'])
    _generic_rule = TEMPLATE_GENERIC_DATA_RULE.format(rule = rule, zone_pattern = _zone_pattern,
        variable_pattern = _variable_pattern)
    return _generic_rule + _prepared_constraints + _prepared_signer

def define_minimal_trust_zone(zone_name: FormalName, need_auth = False, need_issuer = False):
    lvs = ''
    lvs += define_key()
    lvs += define_delagatedkey()
    # only allow 1 length suffix
    lvs += define_anchor(zone_name)
    
    # define the first ndncert for authenticator
    index = 0
    if need_issuer:
        cert_issuer = 'Issuer'
        # derive the issuer from anchor
        lvs += define_generic_cert(zone_name, '/"cert"', signee = 'Issuer', signer = 'Anchor',
                                   key = 'DELEGATEDKEY')
        # define the second ndncert for cert issuer
        lvs += define_ndncert_proto(zone_name, issuer_var = Name.from_str('/cert'),
            index = index, issuer_id = 'Issuer', harden = True)
        index += 1
    else:
        cert_issuer = 'Anchor'

    if need_auth:
        authenticator = 'Auth'
        # derive the authenticator from anchor
        lvs += define_generic_cert(zone_name, '/"auth"', signee ='Auth', signer = 'Anchor',
                                   key = 'DELEGATEDKEY')
        lvs += define_ndncert_proto(zone_name, issuer_var = Name.from_str('/auth'), 
            index = index, issuer_id = 'Auth', harden = True)
        index += 1
    else:
        authenticator = 'Anchor'
    
    # define the tmp cert
    if need_auth or need_issuer:
        lvs += define_tmpcert(zone_name, '/"auth"/_', signer = authenticator)
    
    # define ndncert proto for cert issuer
    lvs += define_ndncert_proto(zone_name, index = index, issuer_id = cert_issuer, harden = True)
    index += 1
    # derive other certs from the cert issuer
    # EntityClassi: i len suffix after @zone_name 
    lvs += define_generic_cert(zone_name, '/suffix1', signee = 'EntityClass1', signer = cert_issuer)

    # define app data produced by EntityClass
    # DataClassi: rule applied to EntityClassi
    lvs += define_generic_data_rule('DataClass1', zone_name,
        # allow entity class publish data at one level deeper
        variable_pattern = '/suffix1/_',
        #don't have constraints#,
        signer = 'EntityClass1')
    
    # enable anchor the sign bundle
    constraints = [['_version', '$eq_type("v=0")']]
    lvs += define_generic_data_rule('Bundle', zone_name,
        # allow entity class publish data at one level deeper
        variable_pattern = '/"BUNDLE"/_version',
        constraints = constraints,
        signer = 'Anchor')
    
    # RDR for Bundle
    lvs += define_generic_data_rule('BundleRdr', zone_name,
        # allow entity class publish data at one level deeper
        variable_pattern = '/"BUNDLE"/"32=metadata"/_version/_',
        constraints = constraints,
        signer = 'Anchor')
    # a little formatting
    return lvs.replace('\n\n', '\n')
