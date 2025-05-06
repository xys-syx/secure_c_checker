"""
CERT Rules
"""
from . import msc24c
from . import msc33c
from . import env33c
from . import fio30c
from . import msc32c
from . import mem30c
from . import str31c
from . import arr30c
from . import exp33c
from . import mem34c
RULES = [
    msc24c.MSC24C,
    msc33c.MSC33C,
    env33c.ENV33C,
    fio30c.FIO30C,
    msc32c.MSC32C,
    mem30c.MEM30C,
    str31c.STR31C,
    arr30c.ARR30C,
    #exp33c.EXP33C,
    
    #mem34c.MEM34C
]
