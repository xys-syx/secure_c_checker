"""
CERT Rules
"""
from . import rule_no_deprecated
from . import msc33c
from . import env33c

RULES = [
    rule_no_deprecated.RuleNoDeprecated,
    msc33c.MSC33C,
    env33c.ENV33C
]
