from string import Template
from typing import List

from ndn.encoding import Name, FormalName, Component

lvs_template = r'''
#KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
#NewResponse: /site/CA/_func/_ & { _func: "NEW"} <= #anchor
#ChaResponse: /site/CA/_func/_/_param & { _func: "CHALLENGE" } <= #anchor
#TmpCert: /site/"auth"/_/#KEY <= #anchor 
#Anchor: /site/#KEY & { site: "ndn" }
'''

TEMPLATE_KEY = '''
#KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
'''
TEMPLATE_ANCHOR_RULE = '''
#Anchor: {zone_pattern}/#KEY
'''
TEMPLATE_TMPCERT_RULE = '''
#TmpCert: {zone_pattern}{variable_pattern}/#KEY <= #Anchor
'''
TEMPLATE_GENERIC_CERT_RULE = '''
#{signee}: {zone_pattern}{variable_pattern}/#KEY <= #{signer}
'''
TEMPLATE_NDNCERT_DATA_RULE = '''
#NewResponse: {zone_pattern}/"CA"/"NEW"/_ <= #Anchor
#ChaResponse: {zone_pattern}/"CA"/"CHALLENGE"/_/_param <= #Anchor
'''
TEMPLATE_NDNCERT2_DATA_RULE = '''
#NewResponse2: {zone_pattern}{variable_pattern}/"CA"/"NEW"/_ <= #{issuer}
#ChaResponse2: {zone_pattern}{variable_pattern}/"CA"/"CHALLENGE"/_/_param <= #{issuer}
'''
TEMPLATE_GENERIC_DATA_RULE = '''#{rule}: {zone_pattern}{variable_pattern} '''
TEMPLATE_GENERIC_SIGNER = ' <= #{signer}'
TEMPLATE_GENERIC_CONSTRAINT = '{comp}: {condition}'
TEMPLATE_GENERIC_CONSTRAINTS = ' & {{constraints}}'
TEMPLATE_GENERIC_DATA_RULE2= '''#{rule}: {zone_pattern}{variable_pattern} & {{constraints}} <= #{signer}'''

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

def define_tmpcert(zone_name: FormalName, variable_pattern: str):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_TMPCERT_RULE.format(zone_pattern = _zone_pattern,
                                        variable_pattern = variable_pattern)

def define_anchor(zone_name: FormalName):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_ANCHOR_RULE.format(zone_pattern = _zone_pattern)

# if issuer is the anchor
def define_ndncert_proto(zone_name: FormalName):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    return TEMPLATE_NDNCERT_DATA_RULE.format(zone_pattern = _zone_pattern)    

# if issuer is *NOT* the anchor
def define_ndncert2_proto(zone_name: FormalName, variable_name: FormalName, issuer: str, harden: bool = False):
    ret_lvs = ''
    _zone_pattern = name_to_hardened_pattern(zone_name)
    _variable_pattern = gen_temp_pattern(len(variable_name))
    if harden:
        _variable_pattern = name_to_hardened_pattern(variable_name)
        
    # this issuer should be signed by anchor
    ret_lvs += TEMPLATE_GENERIC_CERT_RULE.format(zone_pattern = _zone_pattern,
                    variable_pattern = _variable_pattern,
                    signee = issuer, signer = 'Anchor')
    
    ret_lvs += TEMPLATE_NDNCERT2_DATA_RULE.format(zone_pattern = _zone_pattern,
                    variable_pattern = _variable_pattern,
                    issuer = issuer)
    return ret_lvs
    
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
def define_generic_data_rule(rule: str, zone_name: FormalName, **kwargs):
    _zone_pattern = name_to_hardened_pattern(zone_name)
    _generic_rule = TEMPLATE_GENERIC_DATA_RULE.format(rule = rule, zone_pattern = _zone_pattern)
    if 'constraints' in kwargs:
        _constraints = ''
        for constraint in kwargs['constraints']:
            _constraints = _prepare_constraint(constraint[0], constraint[1])
            _constraints = _prepare_constraints(_constraints)
        _generic_rule += _constraints
    if 'variable_pattern' in kwargs:
        # todo: more customzied pattern
        _generic_rule += kwargs['variable_pattern']
    if 'signer' in kwargs:
        _prepared_signer = _prepare_signer(kwargs['signer'])
        _generic_rule += _prepared_signer
    return _generic_rule

def define_minimal_trust_zone(zone_name: FormalName, **kwargs):
    lvs = ''
    lvs += define_key()
    # only allow 1 length suffix
    lvs += define_anchor(zone_name)
    lvs += define_tmpcert(zone_name, '/"auth"/_')
    lvs += define_ndncert_proto(zone_name)
    
    if 'issuer_variable' in kwargs:
        issuer = 'issuer'
        if 'issuer_id' in kwargs:
            issuer = kwargs['issuer_id'].capitalize()
        lvs += define_ndncert2_proto(zone_name, kwargs['issuer_variable'], issuer, harden=True)
    # a little formatting
    return lvs.replace("\n\n", "\n")

# print(define_minimal_trust_zone(Name.from_str('/ndn/try/best')))
# print(define_minimal_trust_zone(Name.from_str('/ndn/try/best'), issuer_variable=Name.from_str('/formal/issuer'), issuer_id='formal-signer'))