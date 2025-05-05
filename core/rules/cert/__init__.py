"""
CERT Rules
"""
from . import rule_no_deprecated
from . import msc33c
from . import env33c
from . import fio30c
from . import msc32c

RULES = [
    rule_no_deprecated.RuleNoDeprecated,
    msc33c.MSC33C,
    env33c.ENV33C,
    fio30c.FIO30C,
    msc32c.MSC32C
]
