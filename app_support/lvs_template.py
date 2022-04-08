from select import kevent
from string import Template
from typing import List

from ndn.encoding import Name, FormalName, Component

lvs = r'''
#KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
#NewResponse: /site/CA/_func/_ & { _func: "NEW"} <= #anchor
#ChaResponse: /site/CA/_func/_/_param & { _func: "CHALLENGE" } <= #anchor
#TmpCert: /site/_/#KEY <= #anchor 
#Anchor: /site/#KEY & { site: "ndn" }
'''


TEMPLATE_KEY = '#KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }'
TEMPLATE_ANCHOR_RULE = '#Anchor: {zone_pattern}/#KEY'
TEMPLATE_TMPCERT_RULE = '#TmpCert: {zone_pattern}{variable_pattern}/#KEY <= #Anchor'
TEMPLATE_GENERIC_RULE = '#{signee}: {zone_pattern}{variable_pattern}/#KEY <= {signer}'

TEMPLATE_NDNCERT_DATA_RULE = '''
#NewResponse: {zone_pattern}/"CA"/"NEW"/_ <= #Anchor
#ChaResponse: {zone_pattern}/"CA"/"CHALLENGE"/_/_param <= #Anchor
'''

TEMPLATE_NDNCERT2_DATA_RULE = '''
#NewResponse2: {zone_pattern}{variable_pattern}/"CA"/"NEW"/_ <= #{issuer}
#ChaResponse2: {zone_pattern}{variable_pattern}/"CA"/"CHALLENGE"/_/_param <= #{issuer}
'''

TEMPLATE_GENERIC_DATA_RULE = '''
#{rule}: {zone_pattern}{variable_pattern} 
'''
TEMPLATE_GENERIC_SIGNER = ' <= #{signer}'
TEMPLATE_GENERIC_CONSTRAINT = '{comp}: {condition}'
TEMPLATE_GENERIC_CONSTRAINTS = '& {{constraints}}'

TEMPLATE_GENERIC_DATA_RULE2= '''
#{rule}: {zone_pattern}{variable_pattern} & {{constraints}} <= #{signer}
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

def define_anchor(zone_name: FormalName):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_ANCHOR_RULE.format(zone_pattern = _zone_pattern)

# if issuer is the anchor
def define_ndncert_proto(zone_name: FormalName):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_NDNCERT_DATA_RULE.format(zone_pattern = _zone_pattern)    

# if issuer is *NOT* the anchor
def define_ndncert2_proto(zone_name: FormalName, variable_name: FormalName, issuer: str, harden: bool = False):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    _variable_pattern = gen_temp_pattern(len(variable_name))
    if harden:
        _variable_pattern = name_to_hardened_pattern(variable_name)
    return TEMPLATE_NDNCERT2_DATA_RULE.format(zone_pattern = _zone_pattern,
        variable_pattern = _variable_pattern,
        issuer = issuer)
    
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
        
# print(define_anchor(Name.from_str('/ndn/try/best')))
# print(TEMPLATE_ANCHOR_SIGNER_RULE)
def define_generic_proto(rule: str, zone_name: FormalName, **kwargs):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    
    _constraints = ''
    if 'constraints' in kwargs:
        for constraint in kwargs['constraints']:
            _constraints = _prepare_constraint(constraint[0], constraint[1])
            _constraints = _prepare_constraints(_constraints)

    _prepared_signer = ''
    if 'signer' in kwargs:
        _prepared_signer = _prepared_signer(kwargs['signer'])
    