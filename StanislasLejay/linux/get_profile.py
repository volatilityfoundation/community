# Volatility linux_get_profile plugin
# Copyright (c) 2016 Stanislas 'P1kachu' Lejay (p1kachu@lse.epita.fr)
#
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing
# Agreement
#
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this plugin.  If not, see <http://www.gnu.org/licenses/>.

"""
@author       : Stanislas Lejay
@license      : GPL 2 or later
@contact      : p1kachu@lse.epita.fr
"""

import re
import volatility.scan as scan
import volatility.utils as utils
import volatility.commands as commands

READ_SIZE = 0x100


class LinuxVersionScanner(scan.BaseScanner):
    checks = []

    def __init__(self, signatures=None):
        scan.BaseScanner.__init__(self)
        self.checks = [("VersionCheck", {'signatures': signatures})]


class VersionCheck(scan.ScannerCheck):
    """ Looks for linux kernel string """

    def __init__(self, address_space, signatures=None):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offst):
        dump_chunk = self.address_space.read(offst, READ_SIZE)

        # If linux not in the chunk, skip it completely
        if "Linux" not in dump_chunk:
            self.skip(None, None)
        else:
            # Else, return the correct string, maybe with junk after
            # but we don't care
            found = re.search('Linux version [\w\.-]* .*', dump_chunk)

            if found is not None:
                return True

        return False

    def skip(self, data, off):
        return READ_SIZE


class LinuxGetProfile(commands.Command):
    """
       Scan to try to determine the Linux profile
    """

    distribution_profiles = {
        'centos': 'CentOS',
        'cent os': 'CentOS',
        'debian': 'Debian',
        'fedora': 'Fedora',
        'opensuse': 'OpenSUSE',
        'open suse': 'OpenSUSE',
        'redhat': 'Red Hat',
        'red hat': 'Red Hat',
        'ubuntu': 'Ubuntu',
        '': 'Distribution Not found'
    }

    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')

        scanner = LinuxVersionScanner()

        for offst in scanner.scan(address_space):

            # Read the full size, like before
            magic_string = address_space.zread(offst, READ_SIZE)

            if self._config.get_value('verbose') != 0:
                s = '[ ] DEBUG: String found {0} at offset {1}'
                print(s.format(magic_string.replace('\n', ''), hex(offst)))

            # And directly return the string (there shouldn't
            # be more than one string matching the regex
            return magic_string

    def render_text(self, outfd, data):
        if data is None:
            outfd.write("Couldn't determine OS")
            return

        # Find and remove everything before the kernel version
        beg_string = "Linux version"
        pos = data.find(beg_string) + len(beg_string) + 1
        data = data[pos:]

        k_version = re.search("[\w\.-]*", data).group()
        cmpile_by = re.search("\([\w@\.-]*\)", data).group()
        cmpiler = re.search("\([\w\s\.-]*\(.*\).*\)", data).group()

        outfd.write("Informations found:\n")
        outfd.write("    Kernel version: {0}\n".format(k_version))
        outfd.write("    Compiled by   : {0}\n".format(cmpile_by))
        outfd.write("    Compiler      : {0}\n".format(cmpiler))

        for distrib in self.distribution_profiles:
            if distrib in cmpiler.lower():
                outfd.write('Profile: {0} ({1})\n'.format(self.distribution_profiles[distrib], k_version))
                break
        outfd.flush()
