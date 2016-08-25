# Copyright (C) 2013 Dave Lassalle (@superponible) <dave@superponible.com>
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
@author:       Dave Lassalle (@superponible)
@license:      GNU General Public License 2.0 or later
@contact:      dave@superponible.com
"""

# Information for this script taken from http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format

import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.filescan as filescan
from volatility.renderers import TreeGrid
import volatility.scan as scan
import volatility.utils as utils

PF_file_XP = {
    'PF_HEADER': [ 0x9C, {
        'Version': [ 0x0, ['unsigned int']],
        'Magic': [ 0x4, ['String', dict(length = 4)]],
        'Version2': [0x8, ['unsigned int']],
        'Length': [ 0xc, ['unsigned int']],
        'Name': [0x10, ['NullString', dict(length = 60)]],
        'Hash': [ 0x4c, ['unsigned int']],
        'NtosBoot': [ 0x50, ['unsigned int']],
        'SecAOff': [ 0x54, ['unsigned int']],
        'SecAEntries': [ 0x58, ['unsigned int']],
        'SecBOff': [ 0x5c, ['unsigned int']],
        'SecBEntries': [ 0x60, ['unsigned int']],
        'SecCOff': [ 0x64, ['unsigned int']],
        'SecCLength': [ 0x68, ['unsigned int']],
        'SecDOff': [ 0x6c, ['unsigned int']],
        'SecDEntries': [ 0x70, ['unsigned int']],
        'LastExecTime': [0x78, ['WinTimeStamp', dict(is_utc = True)]],
        'TimesExecuted': [0x90, ['unsigned int']],       
    }]
}

PF_file_Win7 = {
    'PF_HEADER': [ 0x9C, {
        'Version': [ 0x0, ['unsigned int']],
        'Magic': [ 0x4, ['String', dict(length = 4)]],
        'Version2': [0x8, ['unsigned int']],
        'Length': [ 0xc, ['unsigned int']],
        'Name': [0x10, ['NullString', dict(length = 60)]],
        'Hash': [ 0x4c, ['unsigned int']],
        'NtosBoot': [ 0x50, ['unsigned int']],
        'SecAOff': [ 0x54, ['unsigned int']],
        'SecAEntries': [ 0x58, ['unsigned int']],
        'SecBOff': [ 0x5c, ['unsigned int']],
        'SecBEntries': [ 0x60, ['unsigned int']],
        'SecCOff': [ 0x64, ['unsigned int']],
        'SecCLength': [ 0x68, ['unsigned int']],
        'SecDOff': [ 0x6c, ['unsigned int']],
        'SecDEntries': [ 0x70, ['unsigned int']],
        'LastExecTime': [0x80, ['WinTimeStamp', dict(is_utc = True)]],
        'TimesExecuted': [0x98, ['unsigned int']],
    }]
}

class HashGenerator(object):
    def __init__(self, filename):
        # @filename: full kernel path to a file in upper case
        self.filename = filename.encode('utf-16-le')

    def ssca_xp_hash_function(self):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#51-scca-xp-hash-function
        hash_value = 0
        for character in self.filename:
            hash_value = ((hash_value * 37) + ord(character)) % 0x100000000

        hash_value = (hash_value * 314159269) % 0x100000000

        if hash_value > 0x80000000:
            hash_value = 0x100000000 - hash_value

        return (abs(hash_value) % 1000000007) % 0x100000000

    def ssca_vista_hash_function(self):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#52-scca-vista-hash-function
        hash_value = 314159
        for character in self.filename:
            hash_value = ((hash_value * 37) + ord(character)) % 0x100000000

        return hash_value

    def ssca_2008_hash_function(self):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#53-scca-2008-hash-function 
        hash_value = 314159
        filename_index = 0
        filename_length = len(self.filename)

        while filename_index + 8 < filename_length:
            character_value = ord(self.filename[filename_index + 1]) * 37
            character_value += ord(self.filename[filename_index + 2])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 3])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 4])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 5])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 6])
            character_value *= 37
            character_value += ord(self.filename[filename_index]) * 442596621
            character_value += ord(self.filename[filename_index + 7])

            hash_value = ((character_value - (hash_value * 803794207)) %
                          0x100000000)

            filename_index += 8

        while filename_index < filename_length:
            hash_value = (((37 * hash_value) + ord(self.filename[filename_index])) %
                          0x100000000)

            filename_index += 1

        return hash_value

class PFTYPES_XP(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5}
    def modification(self, profile):
        profile.vtypes.update(PF_file_XP)
    
class PFTYPES_W7(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6}
    def modification(self, profile):
        profile.vtypes.update(PF_file_Win7)

class PrefetchScanner(scan.BaseScanner):
    def __init__(self, config, needles = None):
        self.config = config
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self)

    def carve(self, address_space, offset):
        pf_buff = address_space.read(offset-4, 256)
        bufferas = addrspace.BufferAddressSpace(self.config, data = pf_buff)
        self.pf_header = obj.Object('PF_HEADER', vm = bufferas, offset = 0)

        return self.pf_header

    def dedup(self, pf_headers):
        """ Yields a unique list of prefetch entries from all PF_HEADERs """
        unique_entries = []
        for pf_header in pf_headers:
            new = {pf_header:
                    ('{0}'.format(pf_header.Name),
                     '{0}'.format(pf_header.Hash),
                     '{0}'.format(pf_header.LastExecTime),
                     '{0}'.format(pf_header.TimesExecuted),
                     '{0}'.format(pf_header.Length))
                    }

            if not new in unique_entries:
                unique_entries.append(new)

        unique_headers =[]
        for unique_entry in unique_entries:
            for header, uniqued_data in unique_entry.iteritems():
                yield header

    def is_valid(self):
        """ Checks of a prefetch header structure is valid """

        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#411-format-version
        # 17 = XP/2003
        # 23 = Vista/2008/7/2012
        # 26 = 8.1
        # 30 = 10
        if self.pf_header.Version != 23 and self.pf_header.Version != 17:
            return
        if self.pf_header.Version2 != 15 and self.pf_header.Version2 != 17:
            return
        if self.pf_header.NtosBoot != 0 and self.pf_header.NtosBoot != 1:
            return
        if self.pf_header.Length < 1 or self.pf_header.Length > 99999999:
            return
        if not ('%X' % self.pf_header.Hash).isalnum():
            return
        if self.pf_header.LastExecTime == 0:
            return
        if self.pf_header.TimesExecuted > 99999999:
            return

        return True

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class DirectoryEnumerator(filescan.FileScan):
    """ Enumerates all unique directories from FileScan """

    def __init__(self, config):
        filescan.FileScan.__init__(self, config)

    def scan(self):
        # Enumerate all available file paths        
        directories = []
        scanner = filescan.FileScan(self._config)        
        for fobj in scanner.calculate():
            fpath = "{0}".format(fobj.file_name_with_device() or '')
            if fpath:
                path = fpath.upper().rsplit('\\', 1)[0]
                if not path in directories:
                    directories.append(path)

        return directories

class PrefetchParser(common.AbstractWindowsCommand):
    """ Scans for and parses potential Prefetch files """

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                (profile.metadata.get('major') == 5 or
                 profile.metadata.get('major') == 6))

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('FULL_PATHS', default = False,
                          help = 'Print the full path the Prefetch file translates to, if possible.',
                          action = "store_true")

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(address_space.profile):
            debug.error("This command does not support the selected profile.")

        scanner = PrefetchScanner(config = self._config, needles = ['SCCA'])
        pf_headers = []

        debug.debug("Scanning for Prefetch files, this can take a while.............")
        for offset in scanner.scan(address_space):
            pf_header = scanner.carve(address_space, offset)
            if scanner.is_valid():
                pf_headers.append(pf_header)

        # This list may have duplicate pf_header entries since
        #   we're not doing unique validation, just scanning.
        # Uniquing makes sense for reducing repetetive entries
        for unique_pf_entry in scanner.dedup(pf_headers):
            yield unique_pf_entry

    def unified_output(self, data):
        """This standardizes the output formatting"""

        row = [
                ("Prefetch File", str),
                ("Execution Time", str),
                ("Times", str),
                ("Size", str),
            ]

        if self._config.FULL_PATHS:
            row.append(("File Path", str))

        return TreeGrid(row, self.generator(data))

    def generator(self, data):
        """This yields data according to the unified output format"""

        if self._config.FULL_PATHS:
            directory_scanner = DirectoryEnumerator(self._config)
            directories = directory_scanner.scan()

        for pf_header in data:
            pf_file = '{0}-{1:X}.pf'.format(pf_header.Name, pf_header.Hash)
            if self._config.FULL_PATHS:
                full_path = ""
                for path in directories:
                    tmp_path = "{0}\\{1}".format(path, pf_header.Name)
                    if pf_header.Version == 17:
                        pf_hash = HashGenerator(tmp_path).ssca_xp_hash_function()
                    elif pf_header.Version == 23:
                        pf_hash = HashGenerator(tmp_path).ssca_vista_hash_function()

                    if "{0}".format(pf_hash) == "{0}".format(pf_header.Hash):
                        full_path = tmp_path
                        break

                yield (0, [str(pf_file),
                            str(pf_header.LastExecTime),
                            str(pf_header.TimesExecuted),
                            str(pf_header.Length),
                            str(full_path),
                        ])               
            else:
                yield (0, [str(pf_file),
                            str(pf_header.LastExecTime),
                            str(pf_header.TimesExecuted),
                            str(pf_header.Length),
                        ])   

    def render_text(self, outfd, data):
        """Renders the Prefetch entries as text"""

        headers = [
                    ("Prefetch File", "42"),
                    ("Execution Time", "28"),
                    ("Times", "5"),
                    ("Size", "8"),
                ]
   
        if self._config.FULL_PATHS:
            headers.append(("File Path", ""))
            directory_scanner = DirectoryEnumerator(self._config)
            directories = directory_scanner.scan()

        self.table_header(outfd, headers)

        for pf_header in data:
            pf_file = '{0}-{1:X}.pf'.format(pf_header.Name, pf_header.Hash)
            if self._config.FULL_PATHS:
                # Iterate prefetch files previously found & compare their
                #   file path hash to the ones generated
                full_path = ''
                for path in directories:
                    tmp_path = "{0}\\{1}".format(path, pf_header.Name)
                    if pf_header.Version == 17:
                        pf_hash = HashGenerator(tmp_path).ssca_xp_hash_function()
                    elif pf_header.Version == 23:
                        pf_hash = HashGenerator(tmp_path).ssca_vista_hash_function()

                    if "{0}".format(pf_hash) == "{0}".format(pf_header.Hash):
                        full_path = tmp_path
                        break

                self.table_row(outfd,
                                pf_file,
                                pf_header.LastExecTime,
                                pf_header.TimesExecuted,
                                pf_header.Length,
                                full_path)
            else:
                self.table_row(outfd,
                                pf_file,
                                pf_header.LastExecTime,
                                pf_header.TimesExecuted,
                                pf_header.Length)
