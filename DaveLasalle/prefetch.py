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

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import struct
import binascii

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
    checks = [ ] 

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset


class PrefetchParser(common.AbstractWindowsCommand):
    """ Scans for and parses potential Prefetch files """
    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                (profile.metadata.get('major') == 5 or
                 profile.metadata.get('major') == 6))

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        #config.add_option('CHECK', short_option = 'C', default = False,
                          #help = 'Only print entries w/o null timestamps',
                          #action = "store_true")
    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(address_space.profile):
            debug.error("This command does not support the selected profile.")

        scanner = PrefetchScanner(needles = ['SCCA'])
        pf_files = []
        print "Scanning for Prefetch files, this can take a while............."
        for offset in scanner.scan(address_space):
            pf_buff = address_space.read(offset-4, 256)
            bufferas = addrspace.BufferAddressSpace(self._config, data = pf_buff)
            pf_header = obj.Object('PF_HEADER', vm = bufferas, offset = 0)
            if pf_header.Version != 23 and pf_header.Version != 17:
                continue
            if pf_header.Version2 != 15 and pf_header.Version2 != 17:
                continue
            if pf_header.NtosBoot != 0 and pf_header.NtosBoot != 1:
                continue
            if pf_header.Length < 1 or pf_header.Length > 99999999:
                continue
            if not ('%X' % pf_header.Hash).isalnum():
                continue
            if pf_header.LastExecTime == 0:
                continue
            if pf_header.TimesExecuted > 99999999:
                continue

            pf_files.append((offset, pf_header))

        return pf_files

    #def render_body(self, outfd, data):
        # Some notes: every base MFT entry should have one $SI and at lease one $FN
        # Usually $SI occurs before $FN
        # We'll make an effort to get the filename from $FN for $SI
        # If there is only one $SI with no $FN we dump whatever information it has
        #for offset, mft_entry, attributes in data:
            #si = None
            #full = ""
            #for a, i in attributes:
                #if a.startswith("STANDARD_INFORMATION"):
                    #if full != "":
                        ## if we are here, we've hit one $FN attribute for this entry already and have the full name
                        ## so we can dump this $SI
                        #outfd.write("0|{0}\n".format(i.body(full, mft_entry.RecordNumber, int(mft_entry.EntryUsedSize), offset)))
                    #elif si != None:
                        ## if we are here then we have more than one $SI attribute for this entry
                        ## since we don't want to lose its info, we'll just dump it for now
                        ## we won't have full path, but we'll have a filename most likely
                        #outfd.write("0|{0}\n".format(i.body("", mft_entry.RecordNumber, int(mft_entry.EntryUsedSize), offset)))
                    #elif si == None:
                        ## this is the usual case and we'll save the $SI to process after we get the full path from the $FN
                        #si = i
                #elif a.startswith("FILE_NAME"):
                    #if hasattr(i, "ParentDirectory"):
                        #full = mft_entry.get_full_path(i)
                        #outfd.write("0|{0}\n".format(i.body(full, mft_entry.RecordNumber, int(mft_entry.EntryUsedSize), offset)))
                        #if si != None:
                            #outfd.write("0|{0}\n".format(si.body(full, mft_entry.RecordNumber, int(mft_entry.EntryUsedSize), offset)))
                            #si = None
            #if si != None:
                ## here we have a lone $SI in an MFT entry with no valid $FN.  This is most likely a non-base entry
                #outfd.write("0|{0}\n".format(si.body("", mft_entry.RecordNumber, int(mft_entry.EntryUsedSize), offset)))

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Prefetch file", "42"), ("Execution Time", "28"), ("Times", "5"), ("Size", "8")])
        for offset, pf_header in data:
            self.table_row(outfd, pf_header.Name + "-" + '%X' % pf_header.Hash + ".PF", pf_header.LastExecTime, pf_header.TimesExecuted, pf_header.Length)
