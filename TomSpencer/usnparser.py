# Copyright (c) 2013-2014 Tom Spencer <tomspencer989@gmail.com>
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
#
# usnparser.py
# Scans and parses raw memory (or even disk dumps) for USN records
#
# Should work for memdumps from any version of Windows that supports the
# USN journal. Should also play nicely with unicode file names, including
# calling out interesting unicode artifacts like text direction changes.
#
# Thanks to Lance Mueller for his previous work on the USN journal


"""
@author:       Tom Spencer
@license:      GNU General Public License 2.0
@contact:      tomspencer989@gmail.com
@organization: Qualcomm, Inc.
"""

import volatility.plugins.common as common
import volatility.plugins.overlays.windows.windows as windows
import volatility.scan as scan
import volatility.obj as obj
import volatility.utils as utils
import volatility.debug as debug
import re

# USN change reasons, source flags, and structures taken/adapted from MSDN
# V2 - http://msdn.microsoft.com/en-us/library/windows/desktop/aa365722%28v=vs.85%29.aspx
# V3 - http://msdn.microsoft.com/en-us/library/windows/desktop/hh802708%28v=vs.85%29.aspx
#
# Added flag 0x00400000 from testing. This flag is valid but undocumented,
# and represents changes made through Transactional NTFS (TxF) which
# provides read-commited consistency.
CHANGE_REASON_FLAGS = {
    0x00000001:'OVERWRITE',
    0x00000002:'EXTEND',
    0x00000004:'TRUNCATION',
    0x00000010:'NAMED_DATA_OVERWRITE',
    0x00000020:'NAMED_DATA_EXTEND',
    0x00000040:'NAMED_DATA_TRUNCATION',
    0x00000100:'CREATE',
    0x00000200:'DELETE',
    0x00000400:'EA_CHANGE',   # EA - Extended Attributes
    0x00000800:'SECURITY_CHANGE',
    0x00001000:'RENAME_OLD_NAME',
    0x00002000:'RENAME_NEW_NAME',
    0x00004000:'INDEXABLE_CHANGE',
    0x00008000:'BASIC_INFO_CHANGE',
    0x00010000:'HARD_LINK_CHANGE',
    0x00020000:'COMPRESSION_CHANGE',
    0x00040000:'ENCRYPTION_CHANGE',
    0x00080000:'OBJECT_ID_CHANGE',
    0x00100000:'REPARSE_POINT_CHANGE',
    0x00200000:'STREAM_CHANGE',
    0x00400000:'TRANSACTED_CHANGE',   # Found from testing, see above
    0x80000000:'CLOSE'
}

# USN source info values & descriptions taken from MSDN
SOURCE_INFO_FLAGS = {
    0x00000001:'DATA_MANAGEMENT',
    0x00000002:'AUXILIARY_DATA',
    0x00000004:'REPLICATION_MANAGEMENT'
}

# File Attribute info values & descriptions taken from MSDN
# http://msdn.microsoft.com/en-us/library/windows/desktop/gg258117%28v=vs.85%29.aspx
FILE_ATTRIBUTE_FLAGS = {
    0x0001:'READONLY',
    0x0002:'HIDDEN',
    0x0004:'SYSTEM',
    0x0010:'DIRECTORY',
    0x0020:'ARCHIVE',
    0x0040:'DEVICE',
    0x0080:'NORMAL',
    0x0100:'TEMPORARY',
    0x0200:'SPARSE_FILE',
    0x0400:'REPARSE_POINT',
    0x0800:'COMPRESSED',
    0x1000:'OFFLINE',
    0x2000:'NOT_CONTENT_INDEXED',
    0x4000:'ENCRYPTED',
    0x8000:'INTEGRITY_STREAM',
    0x10000:'VIRTUAL',
    0x20000:'NO_SCRUB_DATA'
}

# Short file flags from above for body format
# lettering taken from mftscan by tecamac in issue 309:
# http://code.google.com/p/volatility/issues/detail?id=309
SHORT_FILE_ATTRIBUTE_FLAGS = {
    0x0001:'r',  # read only
    0x0002:'h',  # hidden
    0x0004:'s',  # system
    0x0020:'a',  # archive
    0x0040:'d',  # device
    0x0080:'n',  # normal
    0x0100:'t',  # temporary
    0x0200:'S',  # sparse file
    0x0400:'r',  # reparse point
    0x0800:'c',  # compressed
    0x1000:'o',  # offline
    0x2000:'I',  # not context indexed
    0x4000:'e',  # encrypted
    0x10000000:'D'  # directory - We use 0x10000000 here consistent with flag order, but adjust to 0x10 when checking
}

# USN RECORD structures adapted from MSDN here
USN_RECORD_TYPES = {
    'USNRecordV2': [None, {
        'RecordLength': [0x0, ['unsigned int']],   # Length of record padded to 8 bytes
        'MajorVersion': [0x4, ['unsigned short']],  # Should be 02 00 for version 2 records, used in sig
        'MinorVersion': [0x6, ['unsigned short']],  # Always 00 00 for all records I've found, also used in sig
        'FileReferenceNumber': [0x8, ['SixByteLong']],
        'FileReferenceNumberUSN':[0xe, ['unsigned short']],
        'ParentFileReferenceNumber': [0x10, ['SixByteLong']],
        'ParentFileReferenceNumberUSN': [0x16, ['unsigned short']],
        'USN': [0x18, ['unsigned long long']],
        'TimeStamp': [0x20, ['WinTimeStampU']],
        'Reason': [0x28, ['unsigned int']],        # Reason flags are defined above
        'SourceInfo': [0x2c, ['unsigned int']],    # Source flags are defined above
        'SecurityId': [0x30, ['unsigned int']],    # Always 0s in my testing
        'FileAttributes': [0x34, ['unsigned int']],
        'FileNameLength': [0x38, ['unsigned short']],  # Length of files in unicode
        'FileNameOffset': [0x3a, ['unsigned short']],  # Always contains 0x3c, use this as part of our signature to find USN journal records
        'FileName': [0x3c, ['String', dict(length = lambda x: min(x.FileNameLength, MAX_COMPONENT_LENGTH), encoding = 'utf_16')]]
    }],
    'USNRecordV3': [None, {
        'RecordLength': [0x0, ['unsigned int']],   # Length of record padded to 8 bytes
        'MajorVersion': [0x4, ['unsigned short']],  # Should be 03 00 for version 3 records, used in sig
        'MinorVersion': [0x6, ['unsigned short']],  # Always 00 00 for all records I've found, also used in sig
        'FileReferenceNumber': [0x8, ['unsigned long long']],
        'FileReferenceNumberUSN':[0x10, ['unsigned long long']],
        'ParentFileReferenceNumber': [0x18, ['unsigned long long']],
        'ParentFileReferenceNumberUSN': [0x20, ['unsigned long long']],
        'USN': [0x28, ['unsigned long long']],
        'TimeStamp': [0x30, ['WinTimeStampU']],
        'Reason': [0x38, ['unsigned int']],        # Reason flags are defined above
        'SourceInfo': [0x3c, ['unsigned int']],    # Source flags are defined above
        'SecurityId': [0x40, ['unsigned int']],    # Always 0s in my testing
        'FileAttributes': [0x44, ['unsigned int']],
        'FileNameLength': [0x48, ['unsigned short']],  # Length of files in unicode
        'FileNameOffset': [0x4a, ['unsigned short']],  # Always contains 0x4c, use this as part of our signature to find USN journal records
        'FileName': [0x4c, ['String', dict(length = lambda x: min(x.FileNameLength, MAX_COMPONENT_LENGTH), encoding = 'utf_16')]]
    }]
}

# Output fields (and their widths for render_text)
OUTPUT_FIELDS = [
    ('timestamp', '23'),
    ('MFTEntry', '10'),
    ('MFTEntryUSN', '10'),
    ('Parent', '10'),
    ('ParentUSN', '10'),
    ('usn#', '26'),
    ('Filename', '64'),
    ('Reason', '32'),
    ('Attributes', '70'),
    # ('Source', '12'),  # Useless, always 0
    # ('SID', '40'),  # Useless, always 0
]

# This is how we find these records in memory, the FileNameOffset is constant
# for a given record version (i.e. always \x3c\x00 for v2)
USN_RECORD_SEARCHDATA = {
    2: {
        'name':'USNRecordV2',
        'needle':['\x3c\x00'],  # offset of FileName, from FileNameOffset
        'yield_offset':0x3a  # offset to FileNameOffset
    },
    3: {
        'name':'USNRecordV3',
        'needle':['\x4c\x00'],  # offset of FileName, from FileNameOffset
        'yield_offset':0x4a  # offset to FileNameOffset
    }
}

# Unix time_t epoch (Jan, 1970) as a 64-bit Windows Timestamp
WINTIME_UNIX_EPOCH = 116444736000000000

# Largest Unix time_t value (Jan, 2038) as a 64-bit Windows Timestamp
WINTIME_UNIX_MAX = 137919572470000000

# Call out text direction markings
DIRECTION_MARKS = {
    '\xe2\x80\xaa':'<LRE>',  # Left to Right Embedding
    '\xe2\x80\xab':'<RLE>',  # Right to Left Embedding
    '\xe2\x80\xac':'<PDF>',  # Pop Directional Formatting
    '\xe2\x80\xad':'<LRO>',  # Left to Right Override
    '\xe2\x80\xae':'<RLO>',  # Right to Left Override
    '\xe2\x80\x8e':'<LRM>',  # Left to Right Mark
    '\xe2\x80\x8f':'<RLM>',  # Right to Left Mark
}

# Standard NTFS MaxComponentLength is 512 bytes
MAX_COMPONENT_LENGTH = 0x200

# v2 USN record MFT Reference #s are actually a 6-byte record number and a
# short sequence number, this provides a friendly way to handle the record #
class SixByteLong(obj.NativeType):
    """SixByteLong for 48-bit MFT records"""

    def __init__(self, theType, offset, vm, **kwargs):
        obj.NativeType.__init__(self, theType, offset, vm, format_string = 'Q', **kwargs)

    def v(self):
        return obj.NativeType.v(self) & 0xffffff  # ignore 2 high bytes

    def __nonzero__(self):
        return self.v() != 0


# Workaround for corrupted negative timestamps which screw up our formatting
# You can use "-C" to reject any entries that don't have reasonable timestamps
class WinTimeStampU(windows.WinTimeStamp):
    """An unsigned windows timestamp"""

    def __init__(self, theType, offset, vm, is_utc = False, **kwargs):
        self.is_utc = is_utc
        obj.NativeType.__init__(self, theType, offset, vm, format_string = 'Q', **kwargs)

# Core USN class, provides validation and parsing regardless of record version
class USNRecord(obj.CType):
    """Base USN record class inherited by specific version classes"""

    # Verify that flags contains only values present in goodFlags
    def valid_flags(self, flags, goodFlags):
        """Returns True only if all bit flags in 'flags' exist in 'goodFlags'"""

        for i in range(31):
            if (flags & (1 << i)) and not ((1 << i) in goodFlags):
                return False

        return True

    # Pretty print flags - code taken from mftparser "get_type"
    def get_flags(self, flags, flagList):
        """Returns flags in a human readable ' & ' separated string"""

        if flags == None:
            return 'no flags'

        flagString = None
        for i in flagList:
            if (i & flags):
                if flagString == None:
                    flagString = flagList[i]
                else:
                    flagString += ' & ' + flagList[i]

        if flagString == None:
            flagString = '-'

        return flagString

    # This is the main validation routine used to verify that what our search needle has
    # found is a real and clean USN record. The needles are generic enough as to come up
    # fairly frequently just by chance, so we need to be somewhat thorough in validation
    # to ensure that this is a USN record and that its data can be trusted.
    # This validation can be made even stricter by enabling the checktime and strict flags
    def is_valid(self, checktime = False, strict = False):
        """Validate this is a real USN record that is clean enough to be trusted"""

        # basic validation checks
        # Records are padded to 8 bytes, so length must be multiple of 8
        if self.RecordLength % 8 != 0:
            return False

        # Record must be a valid length
        if self.RecordLength < self._minLength or self.RecordLength > self._maxLength:
            return False

        # Match Major and Minor version numbers
        if self.MajorVersion != self._majorVersion:
            return False

        if self.MinorVersion != self._minorVersion:
            return False

        # the offset of the filename + its length, padded to 8 bytes, should equal the record size
        # this also serves as an implied check that FileNameLength is not unduly long, as the
        # RecordLength has already been sanity-checked at this point
        if self.RecordLength != ((self.FileNameOffset + self.FileNameLength + 7) & 0xfffffff8):
            return False

        # accept records only if they have valid timestamps?
        if checktime:
            timestamp = self.TimeStamp.as_windows_timestamp()

            # Consider timestamps outside of unix epoch range as invalid
            if (timestamp < WINTIME_UNIX_EPOCH or timestamp > WINTIME_UNIX_MAX):
                return False

        # even stricter checks, validate flags and ensure that filename decodes cleanly
        if strict:
            name = self.FileName.v()

            try:
                name.decode('utf_16', 'strict')
            except UnicodeDecodeError:
                return False

            if not self.valid_flags(self.Reason, CHANGE_REASON_FLAGS):
                return False

            if not self.valid_flags(self.SourceInfo, SOURCE_INFO_FLAGS):
                return False

            if not self.valid_flags(self.FileAttributes, FILE_ATTRIBUTE_FLAGS):
                return False

            # Normal flag (0x80) is only valid by itself
            if (self.FileAttributes & 0x80) and (self.FileAttributes != 0x80):
                return False

            # Valid records must have at least one attribute flag (NORMAL if nothing else)
            if self.FileAttributes == 0:
                return False

        return True

    # Handles properly converting the utf16 filenames into clean utf8,
    # including dropping invalid characters caused by corruption and
    # calling out notable unicode characteristics like bi-directional
    # text markings
    def _get_unicode_filename(self):
        """Converts filename from questionable utf16 into clean utf8"""

        name = self.FileName.v()
        name = name.decode('utf_16', 'replace')
        name = name.encode('utf_8', 'replace')

        # Replace unprintable and other potentially problematic charachers.
        # None of these are valid in a filename anyway.
        name = re.sub(r'[\x00-\x1F\\/:\*\"<>\|\x7F]', '?', name)

        # Replace unicode text direction markings with text indicators
        # Very helpful for calling out things using direction changes
        # to hide the real file extension
        for mark in DIRECTION_MARKS:
            name = name.replace(mark, DIRECTION_MARKS[mark])

        return name

    # We go through the unicode steps regardless of final output encoding
    # so we can carve out some interesting unicode artifacts. This also
    # preserves the proper file name length better with corrupted data
    def get_name(self, unicodeName = False):
        """Return a clean filename in ascii or utf8 as requested"""

        name = self._get_unicode_filename()

        # convert the utf-8 into ascii if the user has not requested unicode names
        if not unicodeName:
            name = name.decode('utf_8', 'replace').encode('ascii', 'replace')
        return name

    # Get the timestamp in either 64-bit windows format or 32-bit unix format
    def get_time(self, unixtime = False):
        """Return timestamps as windows or unix epoch strings"""

        if unixtime:
            return str(long(self.TimeStamp))

        return str(self.TimeStamp.as_windows_timestamp())

    # Get a nicely formatted human-readable time
    # Will return dash if timestamp is outside of unix epoch range
    # unixtime means 32-bit unix epoch time which has no subsecond precision
    # windows time technically has 100 nanosecond precision but in practice
    # milliseconds seems to be the precision limit for USN records anyway
    def get_time_pretty(self, unixtime = False):
        """Return human-readable time having epoch-corresponding precision"""

        timestamp = self.TimeStamp.as_windows_timestamp()

        # Consider timestamps outside of unix epoch range as invalid
        if (timestamp < WINTIME_UNIX_EPOCH or timestamp > WINTIME_UNIX_MAX):
            return '-'

        dt = self.TimeStamp.as_datetime()

        # datetime returns a NoneObject if it fails conversion
        # this shouldn't happen since we checked our range above
        if isinstance(dt, obj.NoneObject):
            return '-'

        if unixtime:
            return str(dt)

        # 3 decimal precision to give us millisecond accuracy
        subsecond = int(round((timestamp % 10000000) / 10000.0))

        return '{}.{:03d}'.format(dt, subsecond)

    # Pretty print source flags, always nothing in testing so far
    def get_sources(self):
        """Return sources as a human-readable string"""

        return self.get_flags(self.SourceInfo, SOURCE_INFO_FLAGS)

    # Pretty print reason flags
    def get_reasons(self):
        """Return reasons as a human-readable string"""

        return self.get_flags(self.Reason, CHANGE_REASON_FLAGS)

    # Pretty print attribute flags
    def get_attributes(self):
        """Return attributes as a human-readable string"""

        return self.get_flags(self.FileAttributes, FILE_ATTRIBUTE_FLAGS)


# Record type for Windows Vista/7/2k8/2k8R2
class USNRecordV2(USNRecord):
    """v2 record classs"""

    _majorVersion = 2
    _minorVersion = 0
    _minLength = 0x40
    _maxLength = _minLength + MAX_COMPONENT_LENGTH


# Supposed record type for Windows 8/2012 and foreseeable future,
# however testing shows that all of these OS's still use v2 records
# in memory. As such no profiles currently default to this type,
# although it can be manually selected via the -R option (-R3)
class USNRecordV3(USNRecord):
    """v3 record classs"""

    _majorVersion = 3
    _minorVersion = 0
    _minLength = 0x50
    _maxLength = _minLength + MAX_COMPONENT_LENGTH


class USNRecordTypes(obj.ProfileModification):
    """Registers our custom object classes"""

    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        profile.object_classes.update({
            'SixByteLong':SixByteLong,
            'WinTimeStampU':WinTimeStampU,
            'USNRecordV2':USNRecordV2,
            'USNRecordV3':USNRecordV3
        })
        profile.vtypes.update(USN_RECORD_TYPES)


class USNScanner(scan.BaseScanner):
    """Scans entire memoryspace for potential USN records"""

    checks = []

    def __init__(self, needles = None, yield_offset = 0):
        self.needles = needles
        self.yield_offset = yield_offset
        self.checks = [('MultiStringFinderCheck', {'needles':needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset - self.yield_offset


class USNParser(common.AbstractWindowsCommand):
    """Scans for and parses USN journal records"""

    @staticmethod
    def get_record_version(profile):
        """Select appropriate record version for given profile"""

        record_version = 0

        if (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) >= 5):

            # In testing so far every version of windows that supports USN journals
            # seems to actually use version 2, even if they natively use v3 structs
            # in the APIs. For instance 2012R2 claims its records are v3, but if you
            # check on disk and in memory they are really v2 records that seem to
            # get converted on the fly to fit the expected v3 struct for API calls.

            # If we do find an OS version that actually does use v3 records in memory,
            # we can add logic to automatically select it for people here.

            record_version = 2

        return record_version

    def get_record_info(self, profile):
        """Get search metadata for the appropriate record version for this profile"""

        record_info = None

        record_version = self.get_record_version(profile)

        if self._config.RECORDTYPE:
            debug.info('Forcing record version {}'.format(self._config.RECORDTYPE))

            if self._config.RECORDTYPE != record_version:
                debug.warning('Overriding expected profile record version {} with user-specified version {}'.format(record_version, self._config.RECORDTYPE))

            record_version = self._config.RECORDTYPE

        if record_version in USN_RECORD_SEARCHDATA:
            record_info = USN_RECORD_SEARCHDATA[record_version]

        return record_info

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('TIMESTAMP', short_option = 'T', default = False,
                          help = 'Print timestamps instead of human-readable dates',
                          action = 'store_true')

        config.add_option('UNIXTIME', short_option = 'X', default = False,
                          help = 'Use Unix Epoch 32-bit timestamps instead of native \
                                  Windows 64-bit timestamps (loses subsecond accuracy). \
                                  DOES NOT imply -T above.',
                          action = 'store_true')

        config.add_option('CHECK', short_option = 'C', default = False,
                          help = 'Don\'t show entries with timestamps outside of unix \
                                  epoch range to reduce corrupt entries',
                          action = 'store_true')

        config.add_option('STRICT', short_option = 'S', default = False,
                          help = 'Enable stricter checks on record integrity to further \
                                  reduce corrupt entries',
                          action = 'store_true')

        config.add_option('OFFSET', short_option = 'O', default = False,
                          help = 'Show the physical offset for each record',
                          action = 'store_true')

        config.add_option('RECORDTYPE', short_option = 'R', default = False,
                          help = 'Force version of USN record (2 or 3) to search for. In \
                                  testing so far all OS\'s seem to use version 2 records \
                                  in memory (even 8.1/2012r2 which purport to use R3). \
                                  As such, default is R2.',
                          action = 'store', type = 'int')

        config.add_option('UNICODE', short_option = 'U', default = False,
                          help = 'Show unicode (utf-8) filenames. Be aware that due to \
                                  corrupted records there will likely be strange \
                                  characters in some places. Using -C and -S can help \
                                  cut this down.',
                          action = 'store_true')

    def calculate(self):
        """Scans physical memory for legitimate USN records and yields them to the renderer"""

        address_space = utils.load_as(self._config, astype = 'physical')

        record_type = self.get_record_info(address_space.profile)

        if not record_type:
            debug.error('This plugin does not support the selected profile.')

        scanner = USNScanner(needles = record_type['needle'], yield_offset = record_type['yield_offset'])

        for offset in scanner.scan(address_space):
            # Legitimate USN records begin on 8 bytes boundaries, so don't bother checking otherwise
            if offset % 8:
                continue

            usn_record = obj.Object(record_type['name'], vm = address_space, offset = offset)

            if usn_record.is_valid(checktime = self._config.CHECK, strict = self._config.STRICT):
                yield usn_record

    # common rendering helper function to get the record data
    def _get_row(self, usn_record):
        """Pull out the USN data into an ordered list of strings"""

        # human time or timestamps?
        if self._config.TIMESTAMP:
            time = usn_record.get_time(self._config.UNIXTIME)
        else:
            time = usn_record.get_time_pretty(self._config.UNIXTIME)

        # build our row
        row = [time,
               hex(usn_record.FileReferenceNumber),
               hex(usn_record.FileReferenceNumberUSN),
               hex(usn_record.ParentFileReferenceNumber),
               hex(usn_record.ParentFileReferenceNumberUSN),
               hex(usn_record.USN),
               usn_record.get_name(self._config.UNICODE),
               usn_record.get_reasons(),
               usn_record.get_attributes(),
               # usn_record.get_sources(),  # Always blank so removed
               # hex(usn_record.SecurityId),  # Always blank so removed
               ]

        # insert the offset if the user asked for it
        if self._config.OFFSET:
            row.insert(1, hex(usn_record.obj_offset))

        return row

    def render_text(self, outfd, data):
        """Renders records in traditional volatility style"""

        headers = OUTPUT_FIELDS

        # insert the offset if the user asked for it
        if self._config.OFFSET:
            headers.insert(1, ('offset', '12'))

        # Shrink timestamp field a bit if we're using UNIXTIME, less precision takes less room
        if self._config.UNIXTIME:
            headers[0] = ('timestamp', '19')

        # write headers
        self.table_header(outfd, headers)

        # write journal rows
        for usn_record in data:
            row = self._get_row(usn_record)
            self.table_row(outfd, *row)

    def render_csv(self, outfd, data):
        """Renders records as a CSV"""

        fmtdata = [i[0] for i in OUTPUT_FIELDS]

        # insert the offset if the user asked for it
        if self._config.OFFSET:
            fmtdata.insert(1, 'offset')

        # build format string to match the columns requested
        fmtstr = ['{}'] * len(fmtdata)

        # File names can contain commas so wrap them in quotes
        filenameindex = fmtdata.index('Filename')
        fmtstr[filenameindex] = '"{}"'

        # putting the c in csv
        fmtstr = ','.join(fmtstr) + '\n'

        # write headers
        outfd.write(fmtstr.format(*fmtdata))

        # write journal rows
        for usn_record in data:
            row = self._get_row(usn_record)
            outfd.write(fmtstr.format(*row))

    def render_body(self, outfd, data):
        """Renders records in TSK 'body' v3 format"""

        # format spec take from here: http://wiki.sleuthkit.org/index.php?title=Body_file
        # MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        # We don't have an analagous MD5, UID, GID, or size so those are 0'd out
        fmtstr = '0|{0}|{1}|{2}|0|0|0|{3}|{3}|{3}|{3}\n'

        for usn_record in data:
            # body format always uses unix epoch timestamps
            time = usn_record.get_time(unixtime=True)

            # Decimal formated MFT record # is used as inode
            inode = str(usn_record.FileReferenceNumber)

            # Create the mode_as_string flags
            # USN records do not set attributes for all of these, so we only
            # set the ones that are actually valid in USN records
            # adapted from "get_type_short" in mftparser
            modestr = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}-"
            modedata = []
            for i, j in sorted(SHORT_FILE_ATTRIBUTE_FLAGS.items()):

                if i == 0x10000000:
                    i = 0x10  # Directory flag is actually 0x10 for USN

                if i & usn_record.FileAttributes:
                    modedata += [j]
                else:
                    modedata += ['-']

            mode = modestr.format(*modedata)

            # Create the "name" denoting the data source, filename, and
            # other meaningful record data
            namestr = '[USN JOURNAL] {} {}/USN: {}/PARENT MFT: {}'
            namedata = [usn_record.get_name(self._config.UNICODE),
                        usn_record.get_reasons(),
                        str(usn_record.USN),
                        str(usn_record.ParentFileReferenceNumber)
                        ]

            name = namestr.format(*namedata)

            outfd.write(fmtstr.format(name,inode,mode,time))
