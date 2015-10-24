# Copyright (C) 2015 Bartosz Inglot (@BartInglot) <inglotbartosz@gmail_com>
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
@author:       Bartosz Inglot (@BartInglot)
@license:      GNU General Public License 2.0 or later
@contact:      inglotbartosz@gmail_com
"""

# Information for this script was taken from [...]

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import volatility.constants as constants
import os, re, struct

class JobParser:
    # ==========================================================================
    # The parser's code was copied from Gleeda's JobParser.py
    # https://github.com/gleeda/misc-scripts/raw/master/misc_python/jobparser.py
    # ==========================================================================

    # https://msdn.microsoft.com/en-us/library/2d1fbbab-fe6c-4ae5-bdf5-41dc526b2439.aspx#id11
    products = {
        0x400:"Windows NT 4.0",
        0x500:"Windows 2000",
        0x501:"Windows XP",
        0x600:"Windows Vista",
        0x601:"Windows 7",
        0x602:"Windows 8",
        0x603:"Windows 8.1",
        0xa00:"Windows 10",
    }

    # http://winforensicaanalysis.googlecode.com/files/jobparse.pl
    task_status = {
        0x41300:"Task is ready to run",
        0x41301:"Task is running",
        0x41302:"Task is disabled",
        0x41303:"Task has not run",
        0x41304:"No more scheduled runs",
        0x41305:"Properties not set",
        0x41306:"Last run terminated by user",
        0x41307:"No triggers/triggers disabled",
        0x41308:"Triggers do not have set run times",
    }

    # https://msdn.microsoft.com/en-us/library/cc248283.aspx
    flags = {
        0x00000080:"TASK_APPLICATION_NAME",
        0x00040000:"TASK_FLAG_RUN_ONLY_IF_LOGGED_ON",
        0x00080000:"TASK_FLAG_SYSTEM_REQUIRED",
        0x00100000:"TASK_FLAG_RESTART_ON_IDLE_RESUME",
        0x00200000:"TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET",
        0x00400000:"TASK_FLAG_HIDDEN",
        0x00800000:"TASK_FLAG_RUN_ONLY_IF_DOCKED",
        0x01000000:"TASK_FLAG_KILL_IF_GOING_ON_BATTERIES",
        0x02000000:"TASK_FLAG_DONT_START_IF_ON_BATTERIES",
        0x04000000:"TASK_FLAG_KILL_ON_IDLE_END",
        0x08000000:"TASK_FLAG_START_ONLY_IF_IDLE",
        0x20000000:"TASK_FLAG_DISABLED",
        0x40000000:"TASK_FLAG_DELETE_WHEN_DONE",
        0x80000000:"TASK_FLAG_INTERACTIVE",
    }

    # https://msdn.microsoft.com/en-us/library/cc248286.aspx
    priorities = {
        0x0800000:"NORMAL_PRIORITY_CLASS",
        0x1000000:"IDLE_PRIORITY_CLASS",
        0x2000000:"HIGH_PRIORITY_CLASS",
        0x4000000:"REALTIME_PRIORITY_CLASS",
    }

    class JobDate:
        weekdays = {
            0x0:"Sunday",
            0x1:"Monday",
            0x2:"Tuesday",
            0x3:"Wednesday",
            0x4:"Thursday",
            0x5:"Friday",
            0x6:"Saturday",
        }

        months = {
            0x1:"Jan",
            0x2:"Feb",
            0x3:"Mar",
            0x4:"Apr",
            0x5:"May",
            0x6:"Jun",
            0x7:"Jul",
            0x8:"Aug",
            0x9:"Sep",
            0xa:"Oct",
            0xb:"Nov",
            0xc:"Dec",
        }
        def __init__(self, data, scheduled = False):
            # scheduled is the time the job was scheduled to run
            self.scheduled = scheduled
            self.Year = struct.unpack("<H", data[:2])[0]
            self.Month = struct.unpack("<H", data[2:4])[0]
            if not self.scheduled:
                self.Weekday = struct.unpack("<H", data[4:6])[0]
                self.Day = struct.unpack("<H", data[6:8])[0]
                self.Hour = struct.unpack("<H", data[8:10])[0]
                self.Minute = struct.unpack("<H", data[10:12])[0]
                self.Second = struct.unpack("<H", data[12:14])[0]
                self.Milliseconds = struct.unpack("<H", data[14:16])[0]
            else:
                self.Weekday = None
                self.Day = struct.unpack("<H", data[4:6])[0]
                self.Hour = struct.unpack("<H", data[12:14])[0]
                self.Minute = struct.unpack("<H", data[14:16])[0]
                self.Second = struct.unpack("<H", data[16:18])[0]
                self.Milliseconds = struct.unpack("<H", data[18:20])[0]

        def __repr__(self):
            day = self.weekdays.get(self.Weekday, None)
            mon = self.months.get(self.Month, None)
            if day != None and mon != None and not self.scheduled:
                return "{0} {1} {2} {3:02}:{4:02}:{5:02}.{6} {7}".format(day,
                        mon, self.Day, self.Hour, self.Minute, self.Second,
                        self.Milliseconds, self.Year)
            elif self.scheduled:
                return "{0} {1} {2:02}:{3:02}:{4:02}.{5} {6}".format(mon,
                        self.Day, self.Hour, self.Minute, self.Second,
                        self.Milliseconds, self.Year)
            return "Task not yet run"

        def simple_date(self):
            day = self.weekdays.get(self.Weekday, None)
            mon = self.months.get(self.Month, None)
            if self.scheduled or (not self.scheduled and day and mon):
                return "{0}-{1:02}-{2:02} {3:02}:{4:02}:{5:02}.{6:03}".format(
                    self.Year, self.Month, self.Day, self.Hour,
                    self.Minute, self.Second, self.Milliseconds)
            return 'Not run yet'

    # https://msdn.microsoft.com/en-us/library/aa379358(v=vs.85).aspx
    # https://msdn.microsoft.com/en-us/library/cc248286.aspx
    class UUID:
        def __init__(self, data):
            self.UUID0 = struct.unpack("<I", data[:4])[0]
            self.UUID1 = struct.unpack("<H", data[4:6])[0]
            self.UUID2 = struct.unpack("<H", data[6:8])[0]
            self.UUID3 = struct.unpack(">H", data[8:10])[0]
            self.UUID4 = struct.unpack(">H", data[10:12])[0]
            self.UUID5 = struct.unpack(">H", data[12:14])[0]
            self.UUID6 = struct.unpack(">H", data[14:16])[0]

        def __repr__(self):
            return "{" + "{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:02X}{5:02X}{6:02X}"\
                    .format(self.UUID0, self.UUID1, self.UUID2,
                    self.UUID3, self.UUID4, self.UUID5, self.UUID6) + "}"

    # https://msdn.microsoft.com/en-us/library/cc248285.aspx
    def __init__(self, data):
        '''
        Fixed length section
        https://msdn.microsoft.com/en-us/library/cc248286.aspx
        '''
        self.ProductInfo = struct.unpack("<H", data[:2])[0]
        self.FileVersion = struct.unpack("<H", data[2:4])[0]
        self.UUID = self.UUID(data[4:20])
        self.AppNameLenOffset = struct.unpack("<H", data[20:22])[0]
        self.TriggerOffset = struct.unpack("<H", data[22:24])[0]
        self.ErrorRetryCount = struct.unpack("<H", data[24:26])[0]
        self.ErrorRetryInterval = struct.unpack("<H", data[26:28])[0]
        self.IdleDeadline = struct.unpack("<H", data[28:30])[0]
        self.IdleWait = struct.unpack("<H", data[30:32])[0]
        self.Priority = struct.unpack(">I", data[32:36])[0]
        self.MaxRunTime = struct.unpack("<i", data[36:40])[0]
        self.ExitCode = struct.unpack("<i", data[40:44])[0]
        self.Status = struct.unpack("<i", data[44:48])[0]
        self.Flags = struct.unpack(">I", data[48:52])[0]
        self.RunDate = self.JobDate(data[52:68]).simple_date()
        '''
        Variable length section
        https://msdn.microsoft.com/en-us/library/cc248287.aspx
        '''
        self.RunningInstanceCount = struct.unpack("<H", data[68:70])[0]
        self.NameLength = struct.unpack("<H", data[70:72])[0]
        self.cursor = 72 + (self.NameLength * 2)
        if self.NameLength > 0:
            self.Name = data[72:self.cursor].replace('\x00', "")
        self.ParameterSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
        self.cursor += 2
        self.Parameter = ""
        if self.ParameterSize > 0:
            self.Parameter = data[self.cursor:self.cursor + \
                self.ParameterSize * 2].replace("\x00", "")
            self.cursor += (self.ParameterSize * 2)
        self.WorkingDirectorySize = struct.unpack("<H",
            data[self.cursor:self.cursor + 2])[0]
        self.cursor += 2
        self.WorkingDirectory = "(N/A)"
        if self.WorkingDirectorySize > 0:
            self.WorkingDirectory = data[self.cursor:self.cursor + \
                (self.WorkingDirectorySize * 2)].replace('\x00', "")
            self.cursor += (self.WorkingDirectorySize * 2)
        self.UserSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
        self.cursor += 2
        self.User = "(N/A)"
        if self.UserSize > 0:
            self.User = data[self.cursor:self.cursor + \
                self.UserSize * 2].replace("\x00", "")
            self.cursor += (self.UserSize * 2)
        self.CommentSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
        self.cursor += 2
        self.Comment = "(N/A)"
        if self.CommentSize > 0:
            self.Comment = data[self.cursor:self.cursor + \
                self.CommentSize * 2].replace("\x00", "")
            self.cursor += self.CommentSize * 2
        # this is probably User Data + Reserved Data:
        self.UserData = data[self.cursor:self.cursor + 18]
        self.cursor += 18
        # This isn't really documented, but this is the time the job was
        # scheduled to run:
        self.ScheduledDate = self.JobDate(data[self.cursor:self.cursor + 20],
            scheduled = True).simple_date()

class GenericJobsScanner(scan.BaseScanner):
    FIXED_SECTION_LEN = 68

    JOB_MATCHING_REGEX = re.compile(r"""
    # The Regex matches the entire Fixed Section of a JOB file (68 bytes)

     .{4}                          # Should be fixed, but observed random values
     .{16}                         # UUID, random 16 bytes
     .{1}\x00                      # AppNameLenOffset, should be a small number
     .{10}                         # 5 x 2byte unpredictable fields
     .{1}\x00\x00\x00              # Priority, only bytes 23-26 change
     .{4}                          # MaxRunTime, unpredictable
     \x00\x00\x00\x00              # ExitCode, should be always 4 x "00"
     [\x00-\x08]\x13\x04\x00       # Status, values from jobparser.py by Gleeda
     .{4}                          # Flags
     .{3}\x00.{1}\x00.{1}\x00      # RunDate, besides the year and milisecods
     .{1}\x00.{1}\x00.{1}\x00.{2}  #   the 2nd byte are always zeros
    """, re.DOTALL | re.VERBOSE)

    RUNDATE_MATCHING_REGEX = re.compile(r"""
      # The Regex matches the last 16 bytes of Fixed Section which is RunDate
      # it was also observed to be filled with only zeros
      (?:
        (?:
        \x00{16}                        # Only zeros
        )
      |
        (?:
        .{1}\x07                        # Year, between 1601 and 30827
        [\x01-\x0c]\x00                 # Month, between 1 and 12
        [\x00-\x06]\x00                 # Weekday, between 0 and 6
        [\x01-\x1f]\x00                 # Day, between 1 and 31
        [\x00-\x17]\x00                 # Hour, between 0 and 23
        [\x00-\x3b]\x00                 # Minute, between 0 and 59
        [\x00-\x3b]\x00                 # Second, between 0 and 59
        .{1}[\x00-\x03]                 # MiliSeconds, between 0 and 999
        )
      $)                                # Ensure it's the last bytes
        """, re.DOTALL | re.VERBOSE)

    PRIORITY_MATCHING_REGEX = re.compile(r"""
      # The Regex matches Priority in the Fixed Length section, which is limited
      # to only 4 values.
      (?:^
        .{32}                           # Skip the bytes before
        [\x08\x10\x20\x40]\x00\x00\x00  # Priority
        .{32}                           # Skip the bytes after
      )$
        """, re.DOTALL | re.VERBOSE)

    def __init__(self, needles = None):
        # Allow a good margin of overlap between buffers
        self.overlap = self.FIXED_SECTION_LEN
        scan.BaseScanner.__init__(self)

    def _pass_verification(self, data):
        """
        For performance reasons, the JOB matching regular expression is not as
        strict as it could be. This method attempts to validate the remaining
        fields to reduce the amount of false positives.
        """
        if not self.RUNDATE_MATCHING_REGEX.search(data):
            return False
        if not self.PRIORITY_MATCHING_REGEX.search(data):
            return False
        # The Flags field should be predictable too but some completely random
        # values were observed and therefore the regex is not implemented.
    ##    if not FLAGS_MATCHING_REGEX.search(data):
    ##        return False
        # Finally, the maximum job file size is unknown but let's set a limit to
        # avoid accidental export of large files.
        if len(data) > 0x2000:
            return False
        return True

    @staticmethod
    def _is_valid_unicode_str(buf, start_offset, end_offset):
        """
        Verify a set of bytes could be a valid Unicode string.
        It's done by assuming the following criteria:
         1) It's even length
         2) It ends with two NULL bytes
         3) It's split into two-byte pairs: 1st is never NULL, 2nd is always NULL
        """
        str_len = end_offset - start_offset - 2
        if str_len > 0:
            # Can't be odd length!
            if str_len % 2 == 1:
                return False
            # Check the bytes
            text = buf.read(start_offset, str_len)
            for i in xrange(str_len / 2):
                pair_byte_1 = text[i*2]
                pair_byte_2 = text[i*2 + 1]
                if pair_byte_1 == '\x00' or pair_byte_2 != '\x00':
                    return False
        return True

    def _var_size_section_len(self, buf, start_offset):
        """
        Find the size of the variable-length data section. It's done by ignoring
        the first 2 bytes (Running Instance Count) and then jumping over 5 fields
        by locating two nulls that end specially formatted Unicode strings. The
        fields are Application Name, Parameters, Working Directory, Author,
        Comment. Then we jump the User Data and Reserved Data fields by reading
        their size. The following field are triggers, we jump over by reading
        the count number and multiplying by the fixed length of each trigger (48
        bytes). Finally, we check if the optional Job Signature Header is
        available and if so we jump over the Job Signature; otherwise we return
        we the triggers end.
        """
        def find_double_nulls(buf, offset):
            while True:
                pair_bytes = buf.read(offset, 2)
                offset += 2
                if pair_bytes == '\x00\x00':
                    return offset

        # Jump the Running Instance Count field
        end_offset = start_offset + 2
        # Jump 5 fields that end with two null bytes
        for _ in xrange(5):
            str_offset = end_offset # Before finding out where the string ends
            end_offset = find_double_nulls(buf, end_offset)
            # Fail if the strings aren't Unicode
            if not self._is_valid_unicode_str(buf, str_offset, end_offset):
                return -1
        # jump User Data
        user_data_len = struct.unpack('<H', buf.read(end_offset, 2))[0]
        end_offset += 2 + user_data_len
        # jump Reserved Data
        reserved_data_len = struct.unpack('<B',
            buf.read(end_offset, 2)[0])[0] # skip TASKRESERVED1
        end_offset += 2 + reserved_data_len
        # jump Triggers (48 bytes each)
        triggers_count = struct.unpack('<H', buf.read(end_offset, 2))[0]
        end_offset += 2 + triggers_count*48
        # jump Job Signature (*optional*)
        job_signature_header = buf.read(end_offset, 4)
        if job_signature_header == '\x01\x00\x01\x00':
            end_offset += 12

        # voila!
        return end_offset - start_offset

    def _get_var_len_section(self, buf, offset):
        """
        Get the section length, validate it and then carve it.
        """
        try:
            variable_len_size = self._var_size_section_len(buf, offset)
            if variable_len_size > 0:
                data = buf.read(offset, variable_len_size)
                # Extra verification step: it can't be just null bytes
                return data if data != ''.join(('\00',)*16) else None
        except:
            pass
        return None

    def carve(self, address_space, offset):
        """
        Flush the job file.
        """
        fixed_len_data = address_space.read(offset, self.FIXED_SECTION_LEN)
        variable_len_data = self._get_var_len_section(address_space,
                                offset + self.FIXED_SECTION_LEN)
        if not variable_len_data:
            return None
        return fixed_len_data + variable_len_data

    def scan(self, address_space, offset = 0, maxlen = None):
        current_offset = offset

        for (range_start, range_size) in sorted(address_space.get_available_addresses()):
            # Jump to the next available point to scan from
            # self.base_offset jumps up to be at least range_start
            current_offset = max(range_start, current_offset)
            range_end = range_start + range_size

            # Run checks throughout this block of data
            while current_offset < range_end:
                job_offset = -1
                # Figure out how much data to read
                l = min(constants.SCAN_BLOCKSIZE + self.overlap, range_end - current_offset)
                # Populate the buffer with data
                data = address_space.zread(current_offset, l)

                while True:
                    match = self.JOB_MATCHING_REGEX.search(data, job_offset + 1)
                    if not match:
                        break
                    job_offset = match.start()
                    # Sanity checks on the Fixed Length data section
                    if self._pass_verification(match.group()):
                        yield current_offset + job_offset
                current_offset += min(constants.SCAN_BLOCKSIZE, l)

class AtJobsScanner(scan.BaseScanner):
    """Scans for the comment embedded in seemingly all AT job files."""

    JOB_COMMENT = 'Created by NetScheduleJobAdd.'
    FIXED_SECTION_LEN = 68
    EXIT_CODE_OFFSET = 40
    EXIT_CODE_AND_STATUS_REGEX = re.compile(r'\x00\x00\x00\x00.\x13\x04\x00')

    """
    We assume that the variable section's length is no larger than 640 bytes,
    it's an arbitrary number but AT jobs tend to be small so it should parse
    correctly, in case it failed, go ahead and increase it.
    """
    MAX_JOB_FILE_SIZE = FIXED_SECTION_LEN + 640 #: increase if .JOB fails to parse


    def __init__(self, needles = None):
        # The magic string is a unicode comment that's preceded by its size
        magic_string = ('%c%s' %
            (len(self.JOB_COMMENT)+1, self.JOB_COMMENT)).encode('utf-16-le')
        self.checks = [('MultiStringFinderCheck', {'needles':[magic_string]})]
        scan.BaseScanner.__init__(self)

    def _find_job_beginning(self, buf, offset):
        """
        There should be 5 variable length values before the fixed length section,
        see https://msdn.microsoft.com/en-us/library/cc248287.aspx

        Each of them terminates with double null, let's jump 5 x double-nulls back,
        we'll land somewhere in the fixed length section (can't land exactly
        where it ends because there's no unique value separating the two
        sections), read a chunk of memory before and after where we landed and
        find in this chunk a unique value that is always at a given offset in the
        fixed length section.

        The unique value that was used is '0000 0000 ??13 0400', which are Exit
        Code (offset: 40-44) and Status (offset: 44-48). Once identified, we just
        jump back to the beginning of the fixed length section and grab enough
        bytes to carve the entire job (the excess bytes are ignored by the parser).

        """
        def go_back_to_nulls(buf, offset):
            previous = None
            i = 0
            while True:
                current = buf.read(offset - i, 1)
                if current == '\x00' and previous == '\x00':
                    return offset - i
                i += 1
                previous = current

        new_offset = offset + 2 # Adding 2 because we'll subtract 2 in the loop
        for _ in xrange(5):
            # Subtracting 2 to avoid '\x00\x??\x00\x00\x00' being hit on twice
            new_offset = go_back_to_nulls(buf, new_offset - 2)

        # Grab a chunk of memory and search it with EXIT_CODE_AND_STATUS_REGEX
        if new_offset - self.FIXED_SECTION_LEN < 0:
            return None
        snippet = buf.read(new_offset - self.FIXED_SECTION_LEN,
                            self.FIXED_SECTION_LEN + 8)
        match = self.EXIT_CODE_AND_STATUS_REGEX.search(snippet)
        if not match:
            # Failed verification, probably a false positive
            return None
        status_code_offset = match.start()
        return (new_offset - self.FIXED_SECTION_LEN + status_code_offset \
                - self.EXIT_CODE_OFFSET)

    def carve(self, address_space, offset):
        """
        Flush the job file.
        """
        # Yes, I could use the method provided in GenericJobsScanner to get the
        # exact size of the data, but this works too:) and is marginally quicker
        return address_space.read(offset, self.MAX_JOB_FILE_SIZE)

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            job_offset = self._find_job_beginning(address_space, offset)
            if job_offset:
                yield job_offset

class SchTasks(common.AbstractWindowsCommand):
    """Scans for and parses potential Scheduled Task (.JOB) files"""
    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows')

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                        help = 'Directory in which to dump the files')
        config.add_option('QUICK', short_option = 'Q', default = False,
                        action = 'store_true',
                        help = 'Only search for AT jobs (very quick)')
        # Don't parse and run sanity checks on the Variable Length section,
        # which might be corrupted, but instead grab 1024 bytes that follow the
        # Fixed Length data section.
        config.add_option('NOCHECK', short_option = 'N', default = False,
                          help = 'Don\'t check variable-length data section',
                          action = 'store_true')

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(address_space.profile):
            debug.error('This command does not support the selected profile.')

        if self._config.QUICK:
            scanner = AtJobsScanner()
        else:
            # Regex matching... slow!
            scanner = GenericJobsScanner()
        for offset in scanner.scan(address_space):
            if self._config.verbose:
                debug.info('[+] Found hit: 0x%x' % offset)
            data = scanner.carve(address_space, offset)
            if data:
                yield offset, data
            elif self._config.verbose:
                debug.info('[-] Failed verification')
        return

    def render_text(self, outfd, data):
        if self._config.verbose and self._config.QUICK:
            debug.warning('The quick mode only carves At#.job files.')

        self.table_header(outfd,
                        [("Offset(P)", "[addrpad]"),
                         ("ScheduledDate", "23"),
                         ("MostRecentRunTime", "23"),
                         ("Application", "50"),
                         ("Parameters", "100"),
                         ("WorkingDir", "50"),
                         ("Author", "30"),
                         ("RunInstanceCount", "3"),
                         ("MaxRunTime", "10"),
                         ("ExitCode", "10"),
                         ("Comment", ""),
                        ])

        i = 1
        for offset, job_file in data:
            # Dump the data if --dump-dir was supplied
            if self._config.DUMP_DIR:
                path = os.path.join(self._config.DUMP_DIR, 'carved_%s.job' % i)
                fh = open(path, 'wb')
                fh.write(job_file)
                fh.close()
                i += 1
                if self._config.verbose:
                    debug.info('  Written: ' + os.path.basename(path))
            try:
                job = JobParser(job_file)
            except:
                if self._config.verbose:
                    debug.error('Failed parsing the hit at 0x%x' % offset)
                continue
            hours, ms = divmod(job.MaxRunTime, 3600000)
            minutes, ms = divmod(ms, 60000)
            seconds = ms / 1000
            self.table_row(outfd,
                        offset,
                        job.ScheduledDate,
                        job.RunDate,
                        job.Name,
                        job.Parameter,
                        job.WorkingDirectory,
                        job.User,
                        job.RunningInstanceCount,
                        '{0:02}:{1:02}:{2:02}.{3}'.format(
                            hours, minutes, seconds, ms),
                        '{0:#010x}'.format(job.ExitCode),
                        job.Comment,
                        )
