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

# Information for this script taken from the following blog-post by Sebastian Nerz
# http://www.propheciesintothepast.name/2014/03/10/usnjrnlj/

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.obj as obj
import struct
import binascii
import re
import volatility.constants
import csv
import sys

REASONSCODES = {
    0x00000001: 'Data in one or more named data streams for the file was overwritten.',
    0x00000002: 'The file or directory was added to.',
    0x00000004: 'The file or directory was truncated.',
    0x00000010: 'Data in one or more named data streams for the file was overwritten.',
    0x00000020: 'One or more named data streams for the file were added to.',
    0x00000040: 'One or more named data streams for the file was truncated.',
    0x00000100: 'The file or directory was created for the first time.',
    0x00000200: 'The file or directory was deleted.',
    0x00000400: "The user made a change to the file's or directory's extended attributes. These NTFS attributes are not accessible to Windows-based applications.",
    0x00000800: 'A change was made in the access rights to the file or directory.',
    0x00001000: 'The file or directory was renamed, and the file name in this structure is the previous name.',
    0x00002000: 'The file or directory was renamed, and the file name in this structure is the new name.',
    0x00004000: 'A user changed the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute. That is, the user changed the file or directory from one that can be content indexed to one that cannot, or vice versa.',
    0x00008000: 'A user has either changed one or more file or directory attributes or one or more time stamps.',
    0x00010000: 'An NTFS hard link was added to or removed from the file or directory',
    0x00020000: 'The compression state of the file or directory was changed from or to compressed.',
    0x00040000: 'The file or directory was encrypted or decrypted.',
    0x00080000: 'The object identifier of the file or directory was changed.',
    0x00100000: 'The reparse point contained in the file or directory was changed, or a reparse point was added to or deleted from the file or directory.',
    0x00200000: 'A named stream has been added to or removed from the file, or a named stream has been renamed.',
    0x80000000: 'The file or directory was closed.',
}

SOURCES = {
    0x00000002 : 'USN_SOURCE_AUXILIARY_DATA',
    0x00000001 : 'USN_SOURCE_DATA_MANAGEMENT',
    0x00000004 : 'USN_SOURCE_REPLICATION_MANAGEMENT'
  }

ATTRIBUTES = {
    1:'FILE_ATTRIBUTE_READONLY',
    2:'FILE_ATTRIBUTE_HIDDEN',
    4:'FILE_ATTRIBUTE_SYSTEM',
    16:'FILE_ATTRIBUTE_DIRECTORY',
    32:'FILE_ATTRIBUTE_ARCHIVE',
    64:'FILE_ATTRIBUTE_DEVICE',
    128:'FILE_ATTRIBUTE_NORMAL',
    256:'FILE_ATTRIBUTE_TEMPORARY',
    512:'FILE_ATTRIBUTE_SPARSE_FILE',
    1024:'FILE_ATTRIBUTE_REPARSE_POINT',
    2048:'FILE_ATTRIBUTE_COMPRESSED',
    4096:'FILE_ATTRIBUTE_OFFLINE',
    8192:'FILE_ATTRIBUTE_NOT_CONTENT_INDEXED',
    16384:'FILE_ATTRIBUTE_ENCRYPTED',
    65536:'FILE_ATTRIBUTE_VIRTUAL'
}

USN_RECORDS = {
    'FILE_REFERENCE': [ None, {
        'RecordNumberLow' : [0x00, ['unsigned long']],
        'RecordNumberHigh': [0x04, ['unsigned short']],
        'SequenceNumber'  : [0x06, ['unsigned short']]
    }],

    'USN_RECORD_V2': [ None, {
        'RecordLength': [0x00, ['unsigned int']],
        'MajorVersion': [0x04, ['unsigned short']],
        'MinorVersion': [0x06, ['unsigned short']],
        'FileReferenceNumber': [0x08, ['FILE_REFERENCE']],
        'ParentFileReferenceNumber': [0x10, ['FILE_REFERENCE']],
        'USN': [0x18, ['unsigned long long']],
        'TimeStamp': [0x20, ['WinTimeStamp', dict(is_utc = True)]],
        'ReasonCode': [0x28, ['unsigned int']],
        'SourceInfo': [0x2B, ['unsigned int']],
        'SecurityId': [0x30, ['unsigned int']],
        'FileAttributes': [0x34, ['unsigned int']],
        'FileNameLength': [0x38, ['unsigned short']],
        'FileNameOffset': [0x3A, ['unsigned short']],
        'FileName': [0x3C, ['String', dict(encoding='utf16', length = lambda x: x.FileNameLength)]]
    }]
}

class FILE_REFERENCE(obj.CType):
    @property
    def RecordNumber(self):
        high = self.RecordNumberHigh << 32
        return self.RecordNumberLow | high
    

class USN_RECORD_V2(obj.CType):
    Attributes = []
    AttributeList = u"" 
    
    def __init__(self, theType, offset, vm, name = None, members = None, struct_size = 0, **kwargs):
        obj.CType.__init__(self, theType, offset, vm, name, members, struct_size, **kwargs)

    @property
    def Reasons(self):
        # Init reasons
        reasons = []
        try:
            reasonkeys = REASONSCODES.keys()
            for k in reasonkeys:
                if k & self.ReasonCode == k:
                    reasons.append(k)
        except Exception as i:
            pass
        return reasons

    @property
    def ReasonList(self):
        # Init reason list
        reasonList = u""
        try:
            for k in self.Reasons:
                if len(reasonList) > 0:
                    reasonList = reasonList + " " + REASONSCODES[k]
                else:
                    reasonList = REASONSCODES[k]
        except Exception as i:
            pass
        return reasonList
        
    @property
    def Attributes(self):
        # Init attributes
        attributes = []
        try:
            attrkeys = ATTRIBUTES.keys()
            for k in attrkeys:
                if k & self.FileAttributes == k:
                    attributes.append(k)
        except:
            pass
        return attributes
        
    @property
    def AttributeList(self):
        # Init attribute list
        attributeList = u""
        try:
            for k in self.Attributes:
                if len(attributeList) > 0:
                    attributeList = attributeList + " " + ATTRIBUTES[k]
                else:
                    attributeList = ATTRIBUTES[k]
        except Exception as i:
            pass
        return attributeList

    @property
    def isValid(self):
        if self.FileNameLength > 0 and \
           self.FileNameLength < 512 and \
           self.RecordLength < (0x3C + self.FileNameLength + 100):
            return True
        else:
            return False

    def __str__(self):
        if self.isValid:
            return "{0}\t{1}\t{2}\t{3}\t{4}\t{5}".format(
                str(self.TimeStamp),
                str(self.FileReferenceNumber.RecordNumber),
                str(self.ParentFileReferenceNumber.RecordNumber),
                str(self.USN),
                str(self.FileName.v().decode('utf-16')),
                str(self.ReasonList))
        else:
            print "Corrupt entry"
        return ""
    
    def csv(self, offset):
        if self.isValid:
            return [self.TimeStamp,
                    self.FileReferenceNumber.RecordNumber,
                    self.ParentFileReferenceNumber.RecordNumber,
                    self.USN,
                    self.FileName.v().decode('utf-16').encode('utf-8'),
                    self.FileAttributes,
                    self.AttributeList,
                    self.ReasonCode,
                    self.ReasonList]
        else:
            return None

    def body(self, offset):
        #
        # This output is only experimental
        #
        if not self.isValid:
            return ""
        
        AccessTime = 0
        ModifiedTime = 0
        MFTAlteredTime = 0
        CreationTime = 0
        for r in self.Reasons:
            if r in [0x01,0x02,0x04,0x10,0x20, 0x40,
                     0x0100, 0x0200, 0x400,
                     0x800, 0x4000, 0x8000, 0x10000,
                     0x100000, 0x200000, 0x80000000]:
                ModifiedTime = self.TimeStamp.v()
            if r in [0x100, 0x200, 0x1000, 0x2000]:
                MFTAlteredTime = self.TimeStamp.v()
            if r in [0x100, 0x200]:
                CreationTime = self.TimeStamp.v()
                AccessTime = self.TimeStamp.v()
        return "0|{0} (Offset: 0x{1:x})|{2}||0|0|0|{3}|{4}|{5}|{6}".format(
            self.FileName.v().decode('utf-16').encode('utf-8'),
            offset,
            self.FileReferenceNumber.RecordNumber,
            AccessTime,
            ModifiedTime,
            MFTAlteredTime,
            CreationTime)

class USN_RECORD(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.object_classes.update({
            'USN_RECORD_V2' : USN_RECORD_V2,
            'FILE_REFERENCE': FILE_REFERENCE,
        })
        profile.vtypes.update(USN_RECORDS)

class USNScanner(scan.BaseScanner):
    checks = [ ]
    overlap = 0x3c

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("RegExCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class RegExCheck(scan.ScannerCheck):
    """ Checks for multiple strings per page """
    
    regexs = []

    def __init__(self, address_space, needles = None):
        scan.ScannerCheck.__init__(self, address_space)
        if not needles:
            needles = []
        self.needles = needles
        self.maxlen = 0x3c
        for needle in needles:
            r = re.compile(needle)
            self.regexs.append(re.compile(needle))
        if not self.maxlen:
            raise RuntimeError("No needles of any length were found for the " + self.__class__.__name__)

    def check(self, offset):
        usn_buff = self.address_space.read(offset, 0x3c + 256)
        for regex in self.regexs:
            if regex.match(usn_buff) != None:
                return True
        return False

    def skip(self, data, offset):
        for regex in self.regexs:
            ue = regex.search(data)
            if ue == None:
                return len(data) - offset
            else:
                return ue.start()


class USNJRNL(common.AbstractWindowsCommand):
    """ Scans for and parses potential USNJRNL entries """
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')
        scanner = USNScanner(needles = ['.{2}\x00\x00\x02\x00\x00\x00.{31}\x01.{17}[\x00\x01]\x3C\x00'])

        usn_entries = []
        #print "Scanning for USNJRNL entries"
        
        for offset in scanner.scan(address_space):
            usn_buff = address_space.zread(offset, 0x3c + 1024)
            bufferas = addrspace.BufferAddressSpace(self._config, data = usn_buff)
            usn_entry = obj.Object('USN_RECORD_V2', vm = bufferas,
                               offset = 0)
            if usn_entry.isValid:
                yield offset, usn_entry

    def render_text(self, outfd, data):
        for offset, usn_entry in data:
            #print "Offset: " + str(offset)
            print str(usn_entry)
            #print "*" * 80
    
    def render_body(self, outfd, data):
        print "This output method is only experimental"
        for offset, usn_entry in data:
            print usn_entry.body(offset)

    def render_csv(self, outfd, data):
        w = csv.writer(sys.stdout, dialect='excel', quoting=csv.QUOTE_ALL)
        w.writerow(["TimeStamp", "MFT", "Parent MFT", "USN", "FileName", "Attributes", "AttributeList", "ReasonCode", "ReasonList"])
        for offset, usn_entry in data:
            ue = usn_entry.csv(offset)
            if ue != None:
                w.writerow(ue)