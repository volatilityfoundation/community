# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2014 Dave Lassalle <dave@superponible.com>
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
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


"""
@author:       Dave Lassalle (@superponible)
@license:      GNU General Public License 2.0 or later
@contact:      dave@superponible.com
@organization: N/A
"""

import os
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.taskmods as taskmods
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.overlays.windows.windows as windows
import volatility.constants as constants

try:
    import pydeep
    has_pydeep = True
except ImportError:
    has_pydeep = False

#--------------------------------------------------------------------------------
# functions 
#--------------------------------------------------------------------------------

class BaseSSDeepScanner(object):
    """An address space scanner for SSDeep/pydeep."""
    overlap = 1024

    def __init__(self, address_space = None, pydeep_hash = None):
        self.pydeep_hash = pydeep_hash
        self.address_space = address_space

    def scan(self, offset, maxlen):
        # Start scanning from offset until maxlen:
        i = offset
        
        pydeep_hash = self.pydeep_hash

        while i < offset + maxlen:
            # Read some data and match it.
            data = self.address_space.zread(i, 0x1000)
            if data:
                data_hash = pydeep.hash_buf(data)
                alike = pydeep.compare(pydeep_hash, data_hash)
                if alike > 10:
                    yield data_hash, i, alike

            i += 0x1000

class VadSSDeepScanner(BaseSSDeepScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task = None, **kwargs):
        """Scan the process address space through the Vads.

        Args:
          task: The _EPROCESS object for this task.
        """
        self.task = task
        BaseSSDeepScanner.__init__(self, address_space = task.get_process_address_space(), **kwargs)

    def scan(self, offset = 0, maxlen = None):
        for vad, self.address_space in self.task.get_vads(skip_max_commit = True):
            for sig, offset, alike in BaseSSDeepScanner.scan(self, vad.Start, vad.Length):
                yield sig, vad.Start, vad.Length, offset, alike

class DiscontigSSDeepScanner(BaseSSDeepScanner):
    """A Scanner for Discontiguous scanning."""

    def scan(self, start_offset = 0, maxlen = None):
        contiguous_offset = 0
        total_length = 0
        for (offset, length) in self.address_space.get_available_addresses():
            # Skip ranges before the start_offset
            if self.address_space.address_compare(offset, start_offset) == -1:
                continue

            # Skip ranges that are too high (if maxlen is specified)
            if maxlen != None:
                if self.address_space.address_compare(offset, start_offset + maxlen) > 0:
                    continue

            # Try to join up adjacent pages as much as possible.
            if offset == contiguous_offset + total_length:
                total_length += length
            else:
                # Scan the last contiguous range.
                for match in BaseSSDeepScanner.scan(self, contiguous_offset, total_length):
                    yield match

                # Reset the contiguous range.
                contiguous_offset = offset
                total_length = length

        if total_length > 0:
            # Do the last range.
            for match in BaseSSDeepScanner.scan(self, contiguous_offset, total_length):
                yield match

#--------------------------------------------------------------------------------
# ssdeepscan
#--------------------------------------------------------------------------------

class SSDeepScan(taskmods.DllList):
    "Scan process or kernel memory with SSDeep signatures"

    def __init__(self, config, *args, **kwargs):
        _addr_space = None
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("KERNEL", short_option = 'K', default = False, action = 'store_true',
                        help = 'Scan kernel modules')
        config.add_option("WIDE", short_option = 'W', default = False, action = 'store_true',
                        help = 'Match wide (unicode) strings')
        config.add_option('SSDEEP-SIG', short_option = 'Y', default = None,
                        help = 'SSDEEP signature to search for (TODO)')
        config.add_option('SSDEEP-FILE', short_option = 'y', default = None,
                        help = 'File to hash with SSDEEP (TODO)')
        config.add_option('SSDEEP_PIDOFF', short_option = 'T', default = None,
                        help = 'PID:BASE to search for (e.g. 860:0x50000',
                        action = 'store', type = 'str')
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                        help = 'Directory in which to dump the files')
        config.add_option('SIZE', short_option = 's', default = 256,
                          help = 'Size of preview hexdump (in bytes)',
                          action = 'store', type = 'int')
        config.add_option('REVERSE', short_option = 'R', default = 0,
                          help = 'Reverse this number of bytes',
                          action = 'store', type = 'int')

    def _pydeep_page(self):
        """Run pydeep and return the hash"""
    
        page_sig = None
    
        try:
            if self._config.SSDEEP_SIG:
                #s = self._config.YARA_RULES
                ## Don't wrap hex or regex rules in quotes 
                #if s[0] not in ("{", "/"): s = '"' + s + '"'
                ## Scan for unicode strings 
                #if self._config.WIDE: s += "wide"
                #rules = yara.compile(sources = {
                            #'n' : 'rule r1 {strings: $a = ' + s + ' condition: $a}'
                            #})
                pass
            elif self._config.SSDEEP_FILE:
                #rules = yara.compile(self._config.YARA_FILE)
                pass
            elif self._config.SSDEEP_PIDOFF:
                (pid, base) = self._config.SSDEEP_PIDOFF.split(':')
                for proc in tasks.pslist(self._addr_space):
                    if proc.UniqueProcessId == int(pid):
                        process_space = proc.get_process_address_space()
                        page_data = process_space.zread(int(base, 16), 0x1000)
                        page_sig = pydeep.hash_buf(page_data)
                if page_sig == "3::":
                    debug.error('PID XXX and OFFSET YYY null or not found')
            else:
                debug.error("You must specify an ssdeep hash (-Y), a file to hash (-y), or a PID:BASE pair (-T)")
        except Exception as why:
            debug.error("Cannot compile rules: {0}".format(str(why)))
            
        return page_sig

    def calculate(self):

        if not has_pydeep:
            debug.error("Please install ssdeep and pydeep from http://ssdeep.sourceforge.net/ and https://github.com/kbandla/pydeep")

        addr_space = utils.load_as(self._config)
        self._addr_space = addr_space

        page_sig = self._pydeep_page()
        if page_sig == None:
            debug.error("Pydeep was not able to hash the input")

        if self._config.KERNEL:

            # Find KDBG so we know where kernel memory begins. Do not assume
            # the starting range is 0x80000000 because we may be dealing with
            # an image with the /3GB boot switch. 
            kdbg = tasks.get_kdbg(addr_space)

            start = kdbg.MmSystemRangeStart.dereference_as("Pointer")

            # Modules so we can map addresses to owners
            mods = dict((addr_space.address_mask(mod.DllBase), mod)
                        for mod in modules.lsmod(addr_space))
            mod_addrs = sorted(mods.keys())

            # There are multiple views (GUI sessions) of kernel memory.
            # Since we're scanning virtual memory and not physical, 
            # all sessions must be scanned for full coverage. This 
            # really only has a positive effect if the data you're
            # searching for is in GUI memory. 
            sessions = []

            for proc in tasks.pslist(addr_space):
                sid = proc.SessionId
                # Skip sessions we've already seen 
                if sid == None or sid in sessions:
                    continue

                session_space = proc.get_process_address_space()
                if session_space == None:
                    continue

                sessions.append(sid)
                scanner = DiscontigSSDeepScanner(address_space = session_space,
                                               rules = rules)

                for hit, address in scanner.scan(start_offset = start):
                    module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(address))
                    yield (module, address, hit, session_space.zread(address - self._config.REVERSE, self._config.SIZE))

        else:
            for task in self.filter_tasks(tasks.pslist(addr_space)):
                scanner = VadSSDeepScanner(task = task, pydeep_hash = page_sig)
                for sig, vStart, vLength, offset, alike in scanner.scan():
                    yield (task, sig, vStart, vLength, offset, alike, scanner.address_space.zread(offset, 0x1000))

    def render_text(self, outfd, data):

        if self._config.DUMP_DIR and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for o, sig, vs, vl, offset, alike, content in data:
            # print the ssdeep matching information
            outfd.write("ssdeep hash: {0}\n".format(sig))
            outfd.write("ssdeep score: {0}\n".format(alike))
            outfd.write("offset: {0}\n".format(hex(offset)))
            outfd.write("VAD region: {0}-{1}\n".format(hex(vs), hex(vs + vl - 1)))

            # Find out if the hit is from user or kernel mode 
            if o == None:
                outfd.write("Owner: (Unknown Kernel Memory)\n")
                filename = "kernel.{0:#x}.dmp".format(addr)
            elif o.obj_name == "_EPROCESS":
                outfd.write("Owner: Process {0} Pid {1}\n".format(o.ImageFileName,
                    o.UniqueProcessId))
                filename = "process.{0:#x}.{1:#x}.dmp".format(o.obj_offset, offset)
            else:
                outfd.write("Owner: {0}\n".format(o.BaseDllName))
                filename = "kernel.{0:#x}.{1:#x}.dmp".format(o.obj_offset, offset)

            # Dump the data if --dump-dir was supplied
            if self._config.DUMP_DIR:
                path = os.path.join(self._config.DUMP_DIR, filename)
                fh = open(path, "wb")
                fh.write(content)
                fh.close()

            # skip writing the hex dump
            #outfd.write("".join(
                #["{0:#010x}  {1:<48}  {2}\n".format(offset + o, h, ''.join(c))
                #for o, h, c in utils.Hexdump(content)
                #]))
            outfd.write("\n")
