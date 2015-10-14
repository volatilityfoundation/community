# 
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Csaba Barta
@license:      GNU General Public License 2.0
@contact:      csaba.barta@gmail.com
"""

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.timefmt as timefmt
import struct
import binascii
import re
import csv
import sys
import datetime


LOGFILE_STRUCTS = {
    'RCRD_HEADER': [ None, {
        'Magic' : [0x00, ['String', dict(encoding='ascii', length=4)]],
        'UpdateSequenceOffset': [0x04, ['unsigned short']],
        'UpdateSequenceCount'  : [0x06, ['unsigned short']],
        'LastLogfileSequenceNumber': [0x08, ['unsigned long long']],
        'Flags': [0x10, ['unsigned long']],
        'PageCount': [0x14, ['unsigned short']],
        'PagePosition': [0x16, ['unsigned short']],
        'NextRecordOffset': [0x18, ['unsigned short']],
        'Align1': [0x1a, ['array', 6, ['unsigned char']]],
        'LastEndLogfileSequenceNumber': [0x20, ['unsigned long long']]
    }],

    'LSN_RECORD_HEADER': [ None, {
        'CurrentLSN': [0x00, ['unsigned long long']],
        'PreviousLSN': [0x08, ['unsigned long long']],
        'ClientUndoLSN': [0x10, ['unsigned long long']],
        'ClientDataLength': [0x18, ['unsigned long']],
        'ClientID': [0x1c, ['unsigned long']],
        'RecordType': [0x20, ['unsigned long']],
        'TransactionID': [0x24, ['unsigned long']],
        'Flags': [0x28, ['unsigned short']],
        'Align1': [0x2a, ['array', 6, ['unsigned char']]],
        'RedoOP': [0x30, ['unsigned short']],
        'UndoOP': [0x32, ['unsigned short']],
        'RedoOffset': [0x34, ['unsigned short']],
        'RedoLength': [0x36, ['unsigned short']],
        'UndoOffset': [0x38, ['unsigned short']],
        'UndoLength': [0x3a, ['unsigned short']],
        'TargetAttribute': [0x3c, ['unsigned short']],
        'LCNsToFollow': [0x3e, ['unsigned short']],
        'RecordOffset': [0x40, ['unsigned short']],
        'AttributeOffset': [0x42, ['unsigned short']],
        'MFTClusterIndex': [0x44, ['unsigned short']],
        'Align2': [0x46, ['array', 2, ['unsigned char']]],
        'TargetVCN': [0x48, ['unsigned long']],
        'Align3': [0x4c, ['array', 4, ['unsigned char']]],
        'TargetLCN': [0x50, ['unsigned long']],
        'Align4': [0x54, ['array', 4, ['unsigned char']]]
    }],
    
    'FILENAME_ALLOCATION': [None, {
        'CreationTime': [0x00, ['WinTimeStamp', dict(is_utc = True)]],
        'ModifiedTime': [0x08, ['WinTimeStamp', dict(is_utc = True)]],
        'MFTAlteredTime': [0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'FileAccessedTime': [0x18, ['WinTimeStamp', dict(is_utc = True)]],
        'AllocatedFileSize': [0x20, ['unsigned long long']],
        'RealFileSize': [0x28, ['unsigned long long']]
    }]
}

class RCRD_HEADER(obj.CType):
    @property
    def isValid(self):
        if self.Magic.v() == "RCRD" and \
           self.NextRecordOffset % 8 == 0 and \
           self.UpdateSequenceOffset % 8 == 0 and \
           self.Align1[0] == 0x00:
            return True
        else:
            return False

class LSN_RECORD_HEADER(obj.CType):

    ImportantOPs = [0x02, # InitializeFileRecordSegment
                    0x03, # DeallocateFileRecordSegment
                    0x0e, # AddIndexEntryAllocation
                    0x0f, # DeleteIndexEntryAllocation
                    0x14] # UpdateFileNameAllocation

    @property
    def isValid(self):
        if self.RecordType == 1 and \
           self.RecordOffset == 0 and \
           self.Flags == 0 and \
           self.RedoOffset == 0x28 and \
           self.RedoOffset % 8 == 0 and \
           self.UndoOffset % 8 == 0 and \
           self.UndoOffset == self.RedoOffset + self.RedoLength and \
           (self.RedoOP in self.ImportantOPs or self.RedoOP == 0) and \
           (self.UndoOP in self.ImportantOPs or self.UndoOP == 0) and \
           self.Align1[0] == 0x00 and \
           self.Align1[1] == 0x00 and \
           self.Align1[2] == 0x00 and \
           self.Align1[3] == 0x00:
            return True
        else:
            return False

    def __str__(self, record_bufferas, record_data):
        if self.RedoOP == 0x02 or self.UndoOP == 0x02: # MFT file record
            mft_entry = obj.Object('MFT_FILE_RECORD', vm = record_bufferas,
                               offset = 0)
            if mft_entry.is_valid():
                attributes = mft_entry.parse_attributes(record_data, entrysize=1024)
                # find the win32 filename for this record
                # if not found get the dos name
                # if not found there should be a posix name
                filename = ""
                posix = ""
                win32 = ""
                dos = ""
                for a, i in attributes:
                    if a.startswith("FILE_NAME"):
                        if i.Namespace == 1 or i.Namespace == 3:
                            win32 = i.get_name()
                        if i.Namespace == 2 or i.Namespace == 3:
                            dos = i.get_name()
                        if i.Namespace == 0:
                            posix = i.get_name()
                if win32 != "":
                    filename = win32
                elif dos != "":
                    filename = dos
                elif posix != "":
                    filename = posix
                else:
                    filename = "[NO FILENAME FOUND]"
                
                out = ""
                for a, i in attributes:
                    if a.startswith("STANDARD_INFORMATION"):
                        if out != "":
                            out = out + "\n"
                        out = out + "{0:30} {1:30} {2:30} {3:30} {4}".format(
                            str(i.CreationTime),
                            str(i.ModifiedTime),
                            str(i.MFTAlteredTime),
                            str(i.FileAccessedTime),
                            filename + " (SI)")
                    elif a.startswith("FILE_NAME"):
                        if out != "":
                            out = out + "\n"
                        out = out + "{0:30} {1:30} {2:30} {3:30} {4}".format(
                            str(i.CreationTime),
                            str(i.ModifiedTime),
                            str(i.MFTAlteredTime),
                            str(i.FileAccessedTime),
                            filename + " (FN)")
                return out
            else:
                return ""
        elif self.RedoOP == 0x0e or self.UndoOP == 0x0e: # INDX entry
            indx_entry_header = obj.Object('INDX_ENTRY_HEADER', vm=record_bufferas, offset=0)
            if indx_entry_header.isValid:
                indx_entry = obj.Object('FILE_NAME', vm=record_bufferas, offset=16)
                if indx_entry.is_valid():
                    null_date = datetime.datetime(1970,1,1,0,0,0).replace(tzinfo = timefmt.UTC())
                    future_date = datetime.datetime(2025,1,1,0,0,0).replace(tzinfo = timefmt.UTC())
                    if indx_entry.FileAccessedTime.as_datetime() <= future_date and indx_entry.FileAccessedTime.as_datetime() >= null_date and \
                       indx_entry.ModifiedTime.as_datetime() <= future_date and indx_entry.ModifiedTime.as_datetime() >= null_date and \
                       indx_entry.MFTAlteredTime.as_datetime() <= future_date and indx_entry.MFTAlteredTime.as_datetime() >= null_date and \
                       indx_entry.CreationTime.as_datetime() <= future_date and indx_entry.CreationTime.as_datetime() >= null_date:
                        return "{0:30} {1:30} {2:30} {3:30} {4}".format(
                            str(indx_entry.CreationTime),
                            str(indx_entry.ModifiedTime),
                            str(indx_entry.MFTAlteredTime),
                            str(indx_entry.FileAccessedTime),
                            indx_entry.get_name() + " (INDX)")
                    else:
                        return ""
                else:
                    return ""
            else:
                return ""
        elif self.RedoOP == 0x14 or self.UndoOP == 0x14: # FILENAME_Allocation
            fna = obj.Object('FILE_NAME', vm=record_bufferas, offset=0)
            filename = "[NO FILENAME FOUND] (FNA, VCN: %d, Offset into the file: %d)" % (self.TargetLCN, self.AttributeOffset)
            return "{0:30} {1:30} {2:30} {3:30} {4}".format(
                    str(fna.CreationTime),
                    str(fna.ModifiedTime),
                    str(fna.MFTAlteredTime),
                    str(fna.FileAccessedTime),
                    filename)
        else:
            return ""
    
    def body(self, record_bufferas, record_data):
        if self.RedoOP == 0x02 or self.UndoOP == 0x02: # MFT file record
            mft_entry = obj.Object('MFT_FILE_RECORD', vm = record_bufferas,
                               offset = 0)
            if mft_entry.is_valid():
                attributes = mft_entry.parse_attributes(record_data, entrysize=1024)
                # find the win32 filename for this record
                # if not found get the dos name
                # if not found there should be a posix name
                filesize = 0
                filename = ""
                posix = ""
                win32 = ""
                dos = ""
                for a, i in attributes:
                    if a.startswith("FILE_NAME"):
                        filesize = i.RealFileSize
                        if i.Namespace == 1 or i.Namespace == 3:
                            win32 = i.get_name()
                        if i.Namespace == 2 or i.Namespace == 3:
                            dos = i.get_name()
                        if i.Namespace == 0:
                            posix = i.get_name()
                if win32 != "":
                    filename = win32
                elif dos != "":
                    filename = dos
                elif posix != "":
                    filename = posix
                else:
                    filename = "[NO FILENAME FOUND]"
                
                out = ""
                for a, i in attributes:
                    if a.startswith("STANDARD_INFORMATION"):
                        if out != "":
                            out = out + "\n"
                        out = out + "0|{0}|{6}|0|0|0|{1}|{2}|{3}|{4}|{5}".format(
                            filename + " (SI)",
                            str(filesize),
                            i.FileAccessedTime.v(),
                            i.ModifiedTime.v(),
                            i.MFTAlteredTime.v(),
                            i.CreationTime.v(),
                            str(mft_entry.RecordNumber))
                    elif a.startswith("FILE_NAME"):
                        if out != "":
                            out = out + "\n"
                        out = out + "0|{0}|{6}|0|0|0|{1}|{2}|{3}|{4}|{5}".format(
                            filename + " (FN)",
                            i.RealFileSize,
                            i.FileAccessedTime.v(),
                            i.ModifiedTime.v(),
                            i.MFTAlteredTime.v(),
                            i.CreationTime.v(),
                            str(mft_entry.RecordNumber))
                return out
            else:
                return ""
        elif self.RedoOP == 0x0e or self.UndoOP == 0x0e: # INDX entry
            indx_entry_header = obj.Object('INDX_ENTRY_HEADER', vm=record_bufferas, offset=0)
            if indx_entry_header.isValid:
                indx_entry = obj.Object('FILE_NAME', vm=record_bufferas, offset=16)
                if indx_entry.is_valid():
                    null_date = datetime.datetime(1970,1,1,0,0,0).replace(tzinfo = timefmt.UTC())
                    future_date = datetime.datetime(2025,1,1,0,0,0).replace(tzinfo = timefmt.UTC())
                    if indx_entry.FileAccessedTime.as_datetime() <= future_date and indx_entry.FileAccessedTime.as_datetime() >= null_date and \
                       indx_entry.ModifiedTime.as_datetime() <= future_date and indx_entry.ModifiedTime.as_datetime() >= null_date and \
                       indx_entry.MFTAlteredTime.as_datetime() <= future_date and indx_entry.MFTAlteredTime.as_datetime() >= null_date and \
                       indx_entry.CreationTime.as_datetime() <= future_date and indx_entry.CreationTime.as_datetime() >= null_date:
                        return "0|{0}|{6}|0|0|0|{1}|{2}|{3}|{4}|{5}".format(
                            indx_entry.get_name() + " (INDX)",
                            indx_entry.RealFileSize,
                            indx_entry.FileAccessedTime.v(),
                            indx_entry.ModifiedTime.v(),
                            indx_entry.MFTAlteredTime.v(),
                            indx_entry.CreationTime.v(),
                            indx_entry_header.MFT.RecordNumber)
                    else:
                        return ""
                else:
                    return ""
            else:
                return ""
        elif self.RedoOP == 0x14 or self.UndoOP == 0x14: # FILENAME Allocation
            fna = obj.Object('FILE_NAME', vm=record_bufferas, offset=0)
            filename = "[NO FILENAME FOUND] (FNA, VCN: %d, Offset into the file: %d)" % (self.TargetLCN, self.AttributeOffset)
            return "0|{0}|0|0|0|0|{1}|{2}|{3}|{4}|{5}".format(
                    filename,
                    fna.RealFileSize,
                    fna.FileAccessedTime.v(),
                    fna.ModifiedTime.v(),
                    fna.MFTAlteredTime.v(),
                    fna.CreationTime.v())
        else:
            return ""

class FILENAME_ALLOCATION(obj.CType):
    def __str__(self):
        return "FILENAME_ALLOCATION"

class LOGFILE_STRUCT(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.object_classes.update({
            'RCRD_HEADER' : RCRD_HEADER,
            'LSN_RECORD_HEADER' : LSN_RECORD_HEADER,
            'FILENAME_ALLOCATION' : FILENAME_ALLOCATION
        })
        profile.vtypes.update(LOGFILE_STRUCTS)

class RCRDScanner(scan.BaseScanner):
    checks = [ ]
    overlap = 0x40

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("RCRDRegExCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class RCRDRegExCheck(scan.ScannerCheck):
    """ Checks for multiple strings per page """
    
    regexs = []

    def __init__(self, address_space, needles = None):
        scan.ScannerCheck.__init__(self, address_space)
        if not needles:
            needles = []
        self.needles = needles
        self.maxlen = 0x28
        for needle in needles:
            r = re.compile(needle)
            self.regexs.append(re.compile(needle))
        if not self.maxlen:
            raise RuntimeError("No needles of any length were found for the " + self.__class__.__name__)

    def check(self, offset):
        buff = self.address_space.zread(offset, 4096)
        for regex in self.regexs:
            if regex.match(buff) != None:
                return True
        return False

    def skip(self, data, offset):
        for regex in self.regexs:
            rcrd = regex.search(data)
            if rcrd == None:
                return len(data) - offset
            else:
                return rcrd.start()


class LOGFILE(common.AbstractWindowsCommand):
    """ Scans for and parses potential $Logfile entries """
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("DEBUGOUT", default = False,
                        help = "Output debugging messages",
                        action = "store_true")

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')
        scanner = RCRDScanner(needles = ['RCRD\('])
        
        # Carve RCRD Headers
        for offset in scanner.scan(address_space):
            lsn_records = []
            lsn_page_header_buff = address_space.zread(offset, 0x28)
            lsn_page_bufferas = addrspace.BufferAddressSpace(self._config, data = lsn_page_header_buff)
            rcrd_header = obj.Object('RCRD_HEADER', vm = lsn_page_bufferas,
                               offset = 0)
            if rcrd_header.isValid:
                lsn_page_buff = address_space.zread(offset, 4096)
                o = 0x28 # skip the RCRD header
                while o < (4096 - 0x58):
                    # Read in the data containing that might contain possible LSN record
                    lsn_header_buff = lsn_page_buff[o:o+0x58]
                    lsn_header_bufferas = addrspace.BufferAddressSpace(self._config, data = lsn_header_buff)
                    # Create the LSN record header object
                    lsn_record_header = obj.Object('LSN_RECORD_HEADER', vm=lsn_header_bufferas,
                                                   offset=0)
                    # Check if it's valid
                    if lsn_record_header != None and \
                       lsn_record_header.isValid:
                        # read in the LSN record data
                        lsn_record_buff = lsn_page_buff[o+0x58:o+0x58+lsn_record_header.RedoLength + lsn_record_header.UndoLength]
                        lsn_record_bufferas = addrspace.BufferAddressSpace(self._config, data = lsn_record_buff)
                        
                        # yield the results
                        yield offset, o, lsn_record_header, lsn_record_buff, lsn_record_bufferas
                        
                        # Increase the offset within the page buffer
                        o = o + 0x58 + lsn_record_header.RedoLength + lsn_record_header.UndoLength
                    else:
                        o += 8


    def render_text(self, outfd, data):
        for page_offset, lsn_entry_offset, lsn_record_header, lsn_data_buff, lsn_data_bufferas in data:
            e = lsn_record_header.__str__(lsn_data_bufferas, lsn_data_buff)
            if e != "":
                print e
    
    def render_body(self, outfd, data):
        for page_offset, lsn_entry_offset, lsn_record_header, lsn_data_buff, lsn_data_bufferas in data:
            e = lsn_record_header.body(lsn_data_bufferas, lsn_data_buff)
            if e != "":
                print e