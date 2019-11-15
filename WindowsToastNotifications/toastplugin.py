#!/usr/bin/env python
"""
Requires Yara-python to be installed
"""
__authors__ = "Max de Bruijn , Rolf Govers"
__department__ = "Forensics and Incident Response"
__company__ = "Fox-IT B.V." 
__year__ = "2019"
__version__ = "1.0"
__status__ = "Final Volatility Plugin contest submission"


import volatility.plugins.common as common
import volatility.plugins.malware.malfind as malfind
import volatility.utils as utils
import volatility.win32 as win32
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import yara
import os

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False



class toastPlugin(common.AbstractWindowsCommand):


    def generator(self,data):
        for proc, address, hit, content in data:
            relevantContent = content.split('/toast>')[0]+'/toast>'
            yield(0,[Address(address),str(proc.ImageFileName),relevantContent])

    def unified_output(self,data):
        tree = [("Address",Address),
                ("ProcessName",str),
                ("ToastXML",str)]
        return TreeGrid(tree,self.generator(data))


    def calculate(self):
        if not has_yara:
            debug.error("Yara must be installed for this plugin")
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        for proc in tasks:
            if str(proc.ImageFileName) == "explorer.exe":
                rules = yara.compile(sources = {
                    'n':'rule toast {strings: $a=/<toast.*\/toast>/ condition: $a}'
                    })
                scanner = malfind.VadYaraScanner(task=proc, rules=rules)
                for hit,address in scanner.scan(maxlen=0x40000000):
                    yield (proc, address, hit, scanner.address_space.zread(address, 0x4000))
