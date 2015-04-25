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

def vol(k):
    return bool(k.obj_offset & 0x80000000)

class UninstallInfo(hivelist.HiveList):
    """Extract installed software info from Uninstall registry key"""

    meta_info = {}
    meta_info['author']    = 'Dave Lassalle'
    meta_info['copyright'] = 'Copyright (c) 2014 Dave Lassalle'
    meta_info['contact']   = 'dave@superponible.com'
    meta_info['license']   = 'GNU General Public License 2.0 or later'
    meta_info['url']       = 'http://superponible.com/'
    meta_info['os']        = 'WIN_32_XP_SP3'
    meta_info['version']   = '1.0'

    def __init__(self, config, *args, **kwargs):
        hivelist.HiveList.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'SOFTWARE Hive offset (virtual)', type = 'int')

    def hive_name(self, hive):
        try:
            return hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
        except AttributeError:
            return "[no name]"

    def calculate(self):
        addr_space = utils.load_as(self._config)
        regapi = registryapi.RegistryApi(self._config)

        software_hive = "SOFTWARE"
        uninstall = "Microsoft\\Windows\\CurrentVersion\\Uninstall"

        hive_offsets = []
        if not self._config.HIVE_OFFSET:
            for h in hivelist.HiveList.calculate(self):
                hive_name = self.hive_name(h)
                if software_hive in hive_name:
                    hive_offsets = [(hive_name, h.obj_offset)]
        else:
            hive_offsets = [("User Specified", self._config.HIVE_OFFSET)]

        for name, hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
            else:
                uninstall_key = rawreg.open_key(root, uninstall.split('\\'))
                if uninstall_key:
                    yield name, uninstall_key
                else:
                    outfd.write("The requested key could not be found in the hive(s) searched\n")


    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):
        print_values = {5:'InstallSource', 6:'InstallLocation', 3:'Publisher',
                        1:'DisplayName', 2:'DisplayVersion', 4:'InstallDate'}
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        for reg, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key name: {0} {1:3s}\n".format(key.Name, self.voltext(key)))
                outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                outfd.write("\n")
                outfd.write("Subkeys:\n")
                for s in rawreg.subkeys(key):
                    key_info = {}
                    if s.Name == None:
                        outfd.write("  Unknown subkey: " + s.Name.reason + "\n")
                    else:
                        key_info['Name'] = s.Name
                        key_info['LastUpdated'] = s.LastWriteTime
                        for v in rawreg.values(s):
                            if v.Name not in print_values.values():
                                continue
                            tp, dat = rawreg.value_data(v)
                            if tp == 'REG_BINARY' or tp == 'REG_NONE':
                                dat = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(dat)])
                            if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                                dat = dat.encode("ascii", 'backslashreplace')
                            if tp == 'REG_MULTI_SZ':
                                for i in range(len(dat)):
                                    dat[i] = dat[i].encode("ascii", 'backslashreplace')
                            key_info[str(v.Name)] = dat
                    outfd.write("Subkey: {0}\n".format(key_info.get('Name','')))
                    outfd.write("  LastUpdated     : {0}\n".format(key_info.get('LastUpdated','')))
                    for k, v in sorted(print_values.items()):
                        val = key_info.get(v, '')
                        if val != '':
                            outfd.write("  {0:16}: {1}\n".format(v, val))
                    outfd.write("\n")
