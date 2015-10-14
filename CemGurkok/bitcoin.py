# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Cem Gurkok
@license:      GNU General Public License 2.0
@contact:      cemgurkok@gmail.com
@organization:
"""

import re
import volatility.obj as obj
import volatility.plugins.mac.common as common
import volatility.plugins.mac.pstasks as pstasks
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.mac.mac_yarascan as mac_yarascan

try:
    import pycoin.key as pykey
    import pycoin.encoding as pyenc
except ImportError:
    print "You need to install pycoin for this plugin to run [pip install pycoin]"    

try:
    import yara
except ImportError:
    print "You need to install yara for this plugin to run [https://github.com/plusvic/yara]"


class mac_bitcoin(common.AbstractMacCommand):
    """Get bitcoin artifacts from OS X multibit client memory"""

    def  __init__(self, config, *args, **kwargs):
        common.AbstractMacCommand.__init__(self, config, *args, **kwargs)
        
    def calculate(self):
        # find multibit process
        all_tasks = pstasks.mac_tasks(self._config).allprocs()
        try:
            name_re = re.compile("JavaApplicationS", re.I)
        except re.error:
            debug.error("Invalid name {0}".format(self._config.NAME))

        bit_tasks = [t for t in all_tasks if name_re.search(str(t.p_comm))]

        # scan for bitcoin addresses with yara, 34 chars, https://en.bitcoin.it/wiki/Address
        # Most Bitcoin addresses are 34 characters. They consist of random digits and uppercase 
        # and lowercase letters, with the exception that the uppercase letter "O", uppercase 
        # letter "I", lowercase letter "l", and the number "0" are never used to prevent visual ambiguity.
        bit_addrs = []
        addr_rule = yara.compile(sources = {'n' : 'rule r1 {strings: $a = /[1-9a-zA-z]{34}(?!OIl)/ condition: $a}'})
        for task in bit_tasks:
            scanner = mac_yarascan.MapYaraScanner(task = task, rules = addr_rule)
            for hit, address in scanner.scan():
                content = scanner.address_space.zread(address, 34)
                if pyenc.is_valid_bitcoin_address(content) and content not in bit_addrs:
                    bit_addrs.append(content)

        # scan for bitcoin keys with yara, 52 char compressed base58, starts with L or K, https://en.bitcoin.it/wiki/Private_key
        addr_key = {}
        key_rule = yara.compile(sources = {'n' : 'rule r1 {strings: $a = /(L|K)[0-9A-Za-z]{51}/ condition: $a}'})
        for task in bit_tasks:
            scanner = mac_yarascan.MapYaraScanner(task = task, rules = key_rule)
            for hit, address in scanner.scan():
                content = scanner.address_space.zread(address, 52)
                if pyenc.is_valid_wif(content):
                    secret_exp = pyenc.wif_to_secret_exponent(content)
                    key = pykey.Key(secret_exponent = secret_exp,is_compressed=True)
                    if key.address() not in addr_key.keys():
                        addr_key[key.address()] = content
                        yield(content, key.address())

        # addresses with no known keys
        for bit_addr in bit_addrs:
            if bit_addr not in addr_key.keys():
                yield ("UNKNOWN", bit_addr)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Bitcoin Key (Base58, compressed pub key)", "<52"),("Bitcoin Address","<34")])
        for key, address in data:
            self.table_row(outfd, key, address)
