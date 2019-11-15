# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2009 Timothy D. Morgan (strings optimization)
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import math
import volatility.plugins.common as common
import volatility.plugins.filescan as filescan
import volatility.debug as debug
import volatility.win32 as win32
import volatility.utils as utils
import volatility.obj as obj
import volatility.exceptions as exceptions
import volatility.constants as constants

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


class PowerSh(common.AbstractWindowsCommand):
    """Identify Powershell processes"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("SCAN", short_option='S', default=False,
                          action='store_true', 
                          help='Use PSScan instead of PSList')
        config.add_option("INSPECT-VAD", short_option='I', default=False,
                          action='store_true', 
                          help='Inspect VAD for interesting powershell data')
        config.add_option("ENTROPY", short_option='E', default=3.0,
                          action='store', type='float',  
                          help='Min Shannon Entropy used to identify meaningful strings')
        config.add_option("PRINTABLE", short_option='P', default=60,
                          action='store', type='int',  
                          help='Min sequence of printable chars to consider it as meaningful strings')
        config.add_option('DUMP-DIR', short_option='D', default=None,
                          cache_invalidator=False,
                          help='Directory in which to dump interesting VAD files')
        config.add_option('MAX-SIZE', short_option='M', default=0x40000000,
                          action='store', type='long',
                          help='Set the maximum size (default is 1GB)')
        config.add_option('PID', short_option='p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='str')
        config.add_option("UNSAFE", short_option="u",
                          default=False, action='store_true',
                          help='Bypasses certain sanity checks when creating image')
        config.add_option("MEMORY", short_option="m", default=False, 
                          action='store_true',
                          help="Carve as a memory sample rather than exe/disk")
        config.add_option('FIX', short_option='x', default=False,
                          help='Modify the image base of the dump to the in-memory base address',
                          action='store_true')

    def dump_pe(self, space, base):
        """
        Dump a PE from an AS and return the content

        @param space: an AS to use
        @param base: PE base address

        @returns the PE file content
        """

        pe_file = obj.Object("_IMAGE_DOS_HEADER", offset=base, vm=space)

        pe_map = []
        try:
            for offset, code in pe_file.get_image(unsafe=self._config.UNSAFE,
                                                  memory=self._config.MEMORY,
                                                  fix=self._config.FIX):
                pe_map = pe_map[:offset] + list(code) + pe_map[offset:]
        except ValueError, ve:
            result = "Error: {0}".format(ve)
            debug.warning(result)
        except exceptions.SanityCheckException, ve:
            result = "Error: {0} Try -u/--unsafe".format(ve)
            debug.warning(result)

        return pe_map

    def is_powershell(self, pe_file):
        """
        Check if the process has the powershell.exe indicators. 
        Can be updated and extended.

        @param pe_file: the PE file carved from memory

        @returns True or False accordingly with what has been found
        """

        result = False

        # Define the indicators in YARA style :-)
        yara_powershell = 'rule powershell {                                 \
                             strings:                                        \
                               $str_Pdb         = "powershell.pdb"           \
                                                                             \
                               $str_Int_Name    = { 00 49 00 6E 00 74 00 65  \
                                                    00 72 00 6E 00 61 00 6C  \
                                                    00 4E 00 61 00 6D 00 65  \
                                                    00 00 00 50 00 4F 00 57  \
                                                    00 45 00 52 00 53 00 48  \
                                                    00 45 00 4C 00 4C        \
                                                  }                          \
                                                                             \
                               $str_Description = { 46 00 69 00 6C 00 65 00  \
                                                    44 00 65 00 73 00 63 00  \
                                                    72 00 69 00 70 00 74 00  \
                                                    69 00 6F 00 6E 00 00 00  \
                                                    00 00 57 00 69 00 6E 00  \
                                                    64 00 6F 00 77 00 73 00  \
                                                    20 00 50 00 6F 00 77 00  \
                                                    65 00 72 00 53 00 68 00  \
                                                    65 00 6C 00 6C           \
                                                   }                         \
                                                                             \
                               condition:                                    \
                                        any of ($str*) }'

        rules = yara.compile(source=yara_powershell)
        matched = rules.match(data=''.join(pe_file))
        if matched:
            result = True
            debug.debug("Powershell indicators found")

        return result

    def inspect_vad(self, path, vad, address_space):
        """
        Read VAD and check it for interesting string. If found, dumps it to 
        file. In order to avoid to hog RAM with huge VAD segments, everything 
        will be dumped to a file, but only interesting one will be kept.

        @param path: full path to output file
        @param vad: an MMVAD object
        @param address_space: process AS for the vad

        @retruns: path of dumped memory or null if nothing has been found
        """

        # Here we search for printable string > 60 (configurable), simple but 
        # effective
        yara_vad = 'rule vad {{ strings: $re1 = /[ -~]{{{0},}}/ condition: $re1 }}'.format(
            self._config.PRINTABLE)
        rules = yara.compile(source=yara_vad)

        result = ""

        fh = open(path, "wb")
        ever_matched = False

        if fh:
            offset = vad.Start
            vad_end = offset + vad.Length
            while offset < vad_end:
                to_read = min(constants.SCAN_BLOCKSIZE, vad_end - offset)
                data = address_space.zread(offset, to_read)
                if not data:
                    break
                fh.write(data)
                if ever_matched is False:
                    matched = rules.match(data=data)
                    if matched:
                        # Check entropy of strings to dump only meaningful 
                        # sections
                        debug.debug("Interesting VAD found")
                        for s in matched[0].strings:
                            if self.entropy(s[2]) > self._config.ENTROPY:
                                ever_matched = True
                                break

                offset += to_read

            fh.close()
            result = path
        else:
            debug.warning("Cannot open {0} for writing".format(path))
            result = ""

        # If interesting strings has been found, keep the file, otherwise 
        # drop everything
        if ever_matched is False:
            try:
                result = ""
                os.remove(path)
            except:
                debug.warning("Cannot remove file {0}".format(path))

        return result

    def entropy(self, string):
        """
        Compute Shannon entropy of a string

        @param string: string of which we have to calculate entropy	

        @returns: entropy
        """

        # Calculate probability
        probability = []
        for ch in dict.fromkeys(list(string)):
            probability.append(float(string.count(ch)) / len(string))

        # Entropy
        ent = []
        for prob in probability:
            ent.append(prob * math.log(prob) / math.log(2.0))

        return - sum(ent)

    def filter_tasks(self, tasks):
        """ 
        Reduce the tasks based on the user selectable PIDS parameter.

        Returns a reduced list or the full list if config.PIDS not specified.
        """

        if self._config.PID is None:
            return tasks

        try:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        except ValueError:
            debug.error("Invalid PID {0}".format(self._config.PID))

        return [t for t in tasks if t.UniqueProcessId in pidlist]

    def calculate(self):

        # Check if yara has been installed
        if not has_yara:
            debug.error("You must install yara to use this plugin")

        # Starts listing all running processes, using the selected method
        tasks = []
        if self._config.SCAN:
            tasks = self.filter_tasks(
                list(filescan.PSScan(self._config).calculate()))
        else:
            addr_space = utils.load_as(self._config)
            tasks = self.filter_tasks(win32.tasks.pslist(addr_space))

        procs = []
        dumped_files = []
        for task in tasks:
            task_space = task.get_process_address_space()
            if task_space is None:
                debug.warning(
                    "Cannot acquire process AS for process {0}".format(task.ImageFileName))
                continue
            elif task.Peb is None:
                debug.warning("PEB at {0:#x} is not available (paging?) for process {1}".format(
                    task.m('Peb'), task.m('ImageFileName')))
                continue
            elif task_space.vtop(task.Peb.ImageBaseAddress) is None:
                debug.warning("ImageBaseAddress at {0:#x} is not available (paging?) for process {1}".format(
                    task.Peb.ImageBaseAddress, task.ImageFileName))
                continue
            else:
                # Extracts the file and checks the indicators of powershell
                debug.debug("Processing file {0}".format(
                    task.m('ImageFileName')))
                pe_file = self.dump_pe(task_space, task.Peb.ImageBaseAddress)

                if pe_file and self.is_powershell(pe_file):
                    # Powershell found
                    procs.append(task)

                    # Check for VAD inspection
                    if self._config.INSPECT_VAD:
                        if self._config.DUMP_DIR is None:
                            debug.error(
                                "Please specify a dump directory (--dump-dir)")
                        if not os.path.isdir(self._config.DUMP_DIR):
                            debug.error(self._config.DUMP_DIR +
                                        " is not a directory")

                        offset = task_space.vtop(task.obj_offset)
                        # if this fails, we'll get its physical offset using kernel space
                        if offset is None:
                            offset = task.obj_vm.vtop(task.obj_offset)
                        if offset is None:
                            offset = 0

                        print "Inspecting VAD for " + str(task.UniqueProcessId)
                        def filter(x): return x.Length < self._config.MAX_SIZE
                        for vad, _aaddrspace in task.get_vads(vad_filter=filter, skip_max_commit=True):
                            # Compose file name
                            vad_start = self.format_value(
                                vad.Start, "[addrpad]")
                            vad_end = self.format_value(vad.End, "[addrpad]")

                            path = os.path.join(
                                self._config.DUMP_DIR, "{0}.{1:x}.{2}-{3}.dmp".format(
                                    task.ImageFileName, offset, vad_start, vad_end))

                            dumped_files.append((task.UniqueProcessId,
                                                 task.ImageFileName,
                                                 vad.Start,
                                                 vad.End,
                                                 self.inspect_vad(path, vad, task_space)))

        return procs, dumped_files

    def render_text(self, outfd, data):

        outfd.write(
            "\n\nPowershell indicators found in the following processes\n\n")

        self.table_header(outfd,
                          [("Pid", "10"),
                           ("Process", "20"),
                           ("Command Line", ""),
                           ])

        for task in data[0]:

            self.table_row(outfd,
                           task.UniqueProcessId,
                           task.ImageFileName,
                           str(task.Peb.ProcessParameters.CommandLine or ''))

        if self._config.INSPECT_VAD:
            outfd.write(
                "\n\nThe following VAD pages had interesting data:\n\n")

            self.table_header(outfd,
                              [("Pid", "10"),
                               ("Process", "20"),
                               ("Start", "[addrpad]"),
                               ("End", "[addrpad]"),
                               ("Result", ""),
                               ])

            for dumped in data[1]:
                if dumped[4]:                   # Check if the path is defined
                    self.table_row(outfd,
                                   dumped[0],          # Process ID
                                   dumped[1],          # Process Name
                                   dumped[2],          # Start Address
                                   dumped[3],          # End Address
                                   dumped[4])          # Path
