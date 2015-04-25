# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2014 Dave Lassalle <dave@superponible.com>
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
# Details on TrustRecords at http://forensicartifacts.com/2012/07/ntuser-trust-records/

"""
@author:       Dave Lassalle
@license:      GNU General Public License 2.0 or later
@contact:      dave@superponible.com
@organization: N/A
"""

#pylint: disable-msg=C0111

import volatility.plugins.registry.registryapi as registryapi
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.plugins.registry.hivelist as hivelist
import struct
import datetime

def vol(k):
    return bool(k.obj_offset & 0x80000000)

class TrustRecords(hivelist.HiveList):
    """Extract MS Office TrustRecords from the Registry"""

    meta_info = {}
    meta_info['author']    = 'Dave Lassalle'
    meta_info['copyright'] = 'Copyright (c) 2014 Dave Lassalle'
    meta_info['contact']   = 'dave@superponible.com'
    meta_info['license']   = 'GNU General Public License 2.0 or later'
    meta_info['url']       = 'http://superponible.com/'
    meta_info['version']   = '1.0'

    def __init__(self, config, *args, **kwargs):
        hivelist.HiveList.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'USER Hive offset (virtual)', type = 'int')

    def hive_name(self, hive):
        try:
            return hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
        except AttributeError:
            return "[no name]"

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)

        user_hive = "ntuser.dat"
        trustrecords = {"Software\\Microsoft\\Office\\14.0\\Word\\Security\\Trusted Documents\\TrustRecords",
                        "Software\\Microsoft\\Office\\14.0\\Excel\\Security\\Trusted Documents\\TrustRecords",
                        "Software\\Microsoft\\Office\\14.0\\PowerPoint\\Security\\Trusted Documents\\TrustRecords",
                        "Software\\Microsoft\\Office\\14.0\\Access\\Security\\Trusted Documents\\TrustRecords",
                       }

        hive_offsets = {}
        if not self._config.HIVE_OFFSET:
            for h in hivelist.HiveList.calculate(self):
                hive_name = self.hive_name(h)
                if user_hive in hive_name.lower():
                    hive_offsets[h.obj_offset] = hive_name
        else:
            hive_offsets = [("User Specified", self._config.HIVE_OFFSET)]

        found = False
        for hoff, name in hive_offsets.iteritems():
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
            else:
                for r in trustrecords:
                    trustrecord_key = rawreg.open_key(root, r.split('\\'))
                    if trustrecord_key:
                        yield name, r, trustrecord_key
                        found = True

        if not found:
            debug.error("The requested key could not be found in the hive(s) searched\n")


    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        for reg, path, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key path: {0}\n".format(path))
                outfd.write("Key name: {0} {1:3s}\n".format(key.Name, self.voltext(key)))
                outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                outfd.write("\n")
                outfd.write("Values:\n")
                for s in rawreg.values(key):
                    tp, dat = rawreg.value_data(s)
                    if tp == 'REG_BINARY' or tp == 'REG_NONE':
                        time = struct.unpack("<q", dat[0:8])[0]
                        seconds, msec= divmod(time, 10000000)
                        days, seconds = divmod(seconds, 86400)
                        if days > 160000 or days < 140000:
                            days = 0
                            seconds = 0
                            msec = 0
                        open_date = datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds, msec)
                        outfd.write(str(open_date) + "\t" + s.Name + "\n")
