# Volatility profilescan plugin
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


import operator
import volatility.scan as scan
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.imageinfo as imageinfo
import volatility.plugins.linux as linux
import volatility.plugins.mac as mac


class SignatureScanner(scan.BaseScanner):
    checks = []

    def __init__(self, signatures=None):
        scan.BaseScanner.__init__(self)
        self.checks = [("SignatureCheck", {'signatures': signatures})]


class SignatureCheck(scan.ScannerCheck):
    """ Looks for binary signatures """
    signature_hashes = []
    PAGE_SIZE = 4096

    def __init__(self, address_space, signatures=None):
        scan.ScannerCheck.__init__(self, address_space)
        if not signatures:
            signatures = []
        self.signature_hashes = signatures

    def check(self, offst):
        """
        Check for each executable format if the byte sequence
        at offst matches its signature
        :param offst: offst to check - multiple of PAGE_SIZE
        :return: boolean
        """

        # Might be a way to do that in superclass
        if offst % self.PAGE_SIZE:
            return False

        for signature in self.signature_hashes:

            # Read sequence of bytes of length equal to the signature's length
            dump_chunk = self.address_space.read(offst, len(signature['magic']))

            # Convert hex strings to int to perform comparison
            magic = int(signature['magic'].encode('hex'), 16)
            mask = int(signature['mask'].encode('hex'), 16)
            chunk = int(dump_chunk.encode('hex'), 16)
            if (chunk | mask) == magic:
                return True

        return False


class ProfileScan(commands.Command):
    """
    Scan for executables to try to determine the underlying OS
    """

    dos_mode_string = 'This program cannot be run in DOS mode'
    signatures = [{
        'formt': "elf",
        'os_id': 'lin',
        'magic': '\x7F\x45\x4C\x46\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00',
        'offst': 0,
        'mask': '\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'
    }, {
        'formt': 'dos_mode',
        'os_id': 'win',
        'magic': dos_mode_string,
        'offst': 0,
        'mask': len(dos_mode_string) * "\x00",
    }, {
        'formt': 'exe',
        'os_id': 'win',
        'magic': '\x4d\x5a\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00',
        'offst': 0,
        'mask': '\x00\x00\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00',
    }, {
        'formt': 'mach-o_32',
        'os_id': 'mac',
        'magic': '\xfe\xed\xfa\xce',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mach-o_64',
        'os_id': 'mac',
        'magic': '\xfe\xed\xfa\xcf',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mach-o_32-rev',
        'os_id': 'mac',
        'magic': '\xce\xfa\xed\xfe',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mach-o_64-rev',
        'os_id': 'mac',
        'magic': '\xcf\xfa\xed\xfe',
        'offst': 0,
        'mask': '\x00\x00\x00\x00'

    }, {
        'formt': 'mac_dmg',
        'os_id': 'mac',
        'magic': '\x78\x01\x73\x0d\x62\x62\x60',
        'offst': 0,
        'mask': '\x00\x00\x00\x00\x00\x00\x00'

    }]

    occurences = {
        'win': 0,
        'mac': 0,
        'lin': 0,
    }

    def calculate(self):

        # Number of executables to find before trying to stop
        MIN_LIMIT = 15

        # Min percentage threshold for an format to reach before
        # being interesting
        THRESHOLD = 90

        address_space = utils.load_as(self._config, astype='physical')

        scanner = SignatureScanner(self.signatures)

        for offst in scanner.scan(address_space):
            # Read the two first bytes at the offst that triggered
            # Might be a simpler way to do that (return format instead of
            # offst ?)
            magic = address_space.zread(offst, 0x2)

            # Compare to each signature's first two bytes,
            # and increment the right id
            for sig in self.signatures:
                if sig['magic'][:2] == magic:
                    self.occurences[sig['os_id']] += 1
                    if self._config.get_value('verbose') != 0:
                        to_print = "[ ] DEBUG: {0} found at offst {1}"
                        print(to_print.format(sig['formt'], hex(offst)))

                    # If minimum limit was reached, check if it is > THRESHOLD
                    maximum = max(self.occurences[x] for x in self.occurences)
                    if maximum > MIN_LIMIT:
                        for occ in self.occurences:
                            nb_occ = self.occurences[occ]
                            percentage = nb_occ / sum(self.occurences[x] for x in self.occurences) * 100
                            if nb_occ > MIN_LIMIT and percentage > THRESHOLD:
                                hightest_id = \
                                    sorted(self.occurences.items(), key=operator.itemgetter(1), reverse=True)[0][0]
                                return hightest_id, percentage

    def render_text(self, outfd, data):
        if data is None:
            outfd.write("OS not found.")
            outfd.write("Executables found: EXE {0} - MACH-O {1} - ELF {2}\n".format(
                self.occurences['win'], self.occurences['mac'], self.occurences['lin']))
            return

        highest, percentage = data
        if highest == 'lin':
            outfd.write("Found OS: LINUX - Launching LinuxGetProfile\n")
            profile = linux.get_profile.LinuxGetProfile(self._config)
            profile.render_text(outfd, profile.calculate())

        elif highest == 'win':
            outfd.write("Found OS: WINDOWS - Launching ImageInfo\n")
            image = imageinfo.ImageInfo(self._config)
            image.render_text(outfd, image.calculate())

        else:
            outfd.write("Found OS: OSX - Launching mac_get_profile\n")
            profile = mac.get_profile.mac_get_profile(self._config)
            profile.render_text(outfd, profile.calculate())
