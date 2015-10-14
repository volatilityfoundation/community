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

import re, ntpath
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware.apihooks as apihooks
import volatility.plugins.overlays.basic as basic
import volatility.plugins.procdump as procdump
import volatility.exceptions as exceptions

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

try:
    import pydeep
    has_pydeep = True
except ImportError:
    has_pydeep = False

#--------------------------------------------------------------------------------
# Whitelist Rules 
# The Sample is just a hash of random data and shouldn't match anything
# It's only meant as a reference for usage
#--------------------------------------------------------------------------------

whitelist_ssdeep = [
    ('Sample', '96:gd5l0eLAUpzGA73fBSu5yg7407l4WpE2eSHhhixk0EU0A:opLdpzL34u5dvZrp9/hwCA'),
]

class ApiHooksDeep(apihooks.ApiHooks):
    """Detect API hooks in process and kernel memory, with ssdeep for whitelisting"""

    def __init__(self, config, *args, **kwargs):
        apihooks.ApiHooks.__init__(self, config, *args, **kwargs)

        config.add_option("SSDEEP", short_option = 'S', default = True, action = 'store_false',
                        help = "Don't use SSDEEP hash whitelist")
        config.add_option('THRESHOLD', short_option = 'T', default = 25,
                          help = 'SSDEEP similarity threshold (0-100, 25 default)',
                          action = 'store', type = 'int')

    def calculate(self):

        addr_space = utils.load_as(self._config)

        if not has_distorm3:
            debug.error("Install distorm3 code.google.com/p/distorm/")

        if not self._config.SKIP_PROCESS:
            for proc in self.filter_tasks(tasks.pslist(addr_space)):
                process_name = str(proc.ImageFileName).lower()

                if (self._config.QUICK and
                        process_name not in self.critical_process):
                    #debug.debug("Skipping non-critical process {0} ({1})".format(
                    #    process_name, proc.UniqueProcessId))
                    continue

                process_space = proc.get_process_address_space()
                if not process_space:
                    #debug.debug("Cannot acquire process AS for {0} ({1})".format(
                    #    process_name, proc.UniqueProcessId))
                    continue

                module_group = apihooks.ModuleGroup(proc.get_load_modules())

                for dll in module_group.mods:

                    if not process_space.is_valid_address(dll.DllBase):
                        continue

                    dll_name = str(dll.BaseDllName or '').lower()

                    if (self._config.QUICK and
                            dll_name not in self.critical_dlls and
                            dll.DllBase != proc.Peb.ImageBaseAddress):
                        #debug.debug("Skipping non-critical dll {0} at {1:#x}".format(
                        #    dll_name, dll.DllBase))
                        continue

                    #debug.debug("Analyzing {0}!{1}".format(process_name, dll_name))

                    for hook in self.get_hooks(apihooks.HOOK_MODE_USER,
                            process_space, dll, module_group):
                        yield proc, dll, hook, process_space

        if not self._config.SKIP_KERNEL:
            process_list = list(tasks.pslist(addr_space))
            module_group = apihooks.ModuleGroup(modules.lsmod(addr_space))

            for mod in module_group.mods:

                #module_name = str(mod.BaseDllName or '')
                #debug.debug("Analyzing {0}".format(module_name))

                kernel_space = tasks.find_space(addr_space,
                    process_list, mod.DllBase)

                if not kernel_space:
                    #debug.debug("No kernel AS for {0} at {1:#x}".format(
                    #    module_name, mod.DllBase))
                    continue

                for hook in self.get_hooks(apihooks.HOOK_MODE_KERNEL,
                        kernel_space, mod, module_group):
                    yield None, mod, hook, kernel_space

    def render_text(self, outfd, data):
        for process, module, hook, addr_space in data:

            if not self._config.NO_WHITELIST:

                if process:
                    process_name = str(process.ImageFileName)
                else:
                    process_name = ''

                if self.whitelist(hook.hook_mode | hook.hook_type,
                                    process_name, hook.VictimModule,
                                    hook.HookModule, hook.Function):
                    #debug.debug("Skipping whitelisted function: {0} {1} {2} {3}".format(
                    #    process_name, hook.VictimModule, hook.HookModule, 
                    #    hook.Function))
                    continue

                if self._config.SSDEEP and has_pydeep:
                    skip = False
                    # read from the start of the page containing the hook, then hash it
                    page_address = hook.hook_address & 0xFFFFF000
                    hook_buf = addr_space.zread(page_address, 0x1000)
                    hook_hash = pydeep.hash_buf(hook_buf)
                    # loop through all the whitelist hashes and compare
                    for (whitelist_name, whitelist_hash) in whitelist_ssdeep:
                        alike = pydeep.compare(hook_hash, whitelist_hash)
                        # the comparison is greater than the threshold so display an informational message
                        # then skip the rest of the output in normal malfind
                        if alike > self._config.THRESHOLD:
                            if process:
                                outfd.write('Process: {0} ({1})\n'.format(
                                    process.UniqueProcessId, process.ImageFileName))
                            outfd.write("Hook at 0x{0:x} in page 0x{1:x} is {2}% similar to whitelist hook {3}\n".format(hook.hook_address, page_address, alike, whitelist_name))
                            #outfd.write("  hook: {0}\n".format(hook_hash))
                            #outfd.write("  whitelist: {0}\n".format(whitelist_hash))
                            outfd.write("\n")
                            skip = True
                            continue
                    if skip:
                        continue

            outfd.write("*" * 72 + "\n")
            outfd.write("Hook mode: {0}\n".format(hook.Mode))
            outfd.write("Hook type: {0}\n".format(hook.Type))

            if process:
                outfd.write('Process: {0} ({1})\n'.format(
                    process.UniqueProcessId, process.ImageFileName))

            outfd.write("Victim module: {0} ({1:#x} - {2:#x})\n".format(
                str(module.BaseDllName or '') or ntpath.basename(str(module.FullDllName or '')),
                module.DllBase, module.DllBase + module.SizeOfImage))

            outfd.write("Function: {0}\n".format(hook.Detail))
            outfd.write("Hook address: {0:#x}\n".format(hook.hook_address))
            outfd.write("Hooking module: {0}\n\n".format(hook.HookModule))

            for n, info in enumerate(hook.disassembled_hops):
                (address, data) = info
                s = ["{0:#x} {1:<16} {2}".format(o, h, i)
                        for o, i, h in
                        malfind.Disassemble(data, int(address), bits = "32bit" if hook.decode_bits == distorm3.Decode32Bits else "64bit")
                    ]
                outfd.write("Disassembly({0}):\n{1}".format(n, "\n".join(s)))
                outfd.write("\n\n")
