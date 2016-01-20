# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
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
@author:       Itay k
@license:      GNU General Public License 2.0
@contact:      itaykrk [at] Gmail [dot] com
@organization: CyberHat.co.il
@description: ApiFinder find specific windows api calls.
"""

import string
import distorm3
import sys
from volatility.plugins.procdump import ProcDump
from volatility import obj
from volatility.plugins import taskmods
from volatility.plugins.malware import impscan


class ApiFinder(taskmods.DllList):

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        self._instructions_history = []
        self._api_address = {}
        config.add_option("API-FUNCTION", short_option='A', default=None, cache_invalidator=False, help='Windows api function name.')
        config.add_option("DLL", short_option='D', default=None, cache_invalidator=False, help='Windows api function DLL name.')

    def calculate(self):
        return taskmods.DllList.calculate(self)

    def _get_functions_addresses(self, task):
        lib = self._config.DLL.lower()
        if not lib.endswith("dll"):
            lib += ".dll"
        dlls = (lib, str(task.ImageFileName))
        modules = []
        task_space = task.get_process_address_space()
        for mod in task.get_load_modules():
            if str(mod.BaseDllName).startswith(dlls):
                modules.append(mod)

        apis = impscan.ImpScan.enum_apis(modules)

        base_address = modules[0].DllBase
        size_to_read = modules[0].SizeOfImage
        data = task_space.zread(base_address, size_to_read)

        calls_imported = dict(
                (iat, call)
                for (_, iat, call) in impscan.ImpScan(self._config).call_scan(task_space, base_address, data)
                if call in apis
                )
        for iat, call in sorted(calls_imported.items()):
            if apis[call][1].lower().startswith(self._config.API_FUNCTION.lower()):
                yield hex(iat), apis[call][1]
        return

    def render_text(self, outfd, data):
        for task in data:
            if self._config.PID is not None:
                if int(task.UniqueProcessId) != int(self._config.PID):
                    continue
            if str(task.ImageFileName) == "System":
                continue

            task_space = task.get_process_address_space()

            #parse pe
            dos_header = obj.Object("_IMAGE_DOS_HEADER", offset=task.Peb.ImageBaseAddress, vm=task_space)
            nt_header = dos_header.get_nt_header()
            code_section = None
            data_section = None

            #find code and data sections
            for sec in nt_header.get_sections():
                if ".text" in str(sec.Name or '').lower():
                    code_section = sec
                elif "data" in str(sec.Name or '').lower():
                    data_section = sec
                    break

            code_section_start_offset = task.Peb.ImageBaseAddress + code_section.VirtualAddress

            codeSection = task_space.read(code_section_start_offset, code_section.Misc.VirtualSize)
            dataSection = task_space.read(task.Peb.ImageBaseAddress + data_section.VirtualAddress, data_section.Misc.VirtualSize)

            self._api_address = {}
            for address, func_name in self._get_functions_addresses(task):
                self._api_address[address] = func_name

            # Disassemble process code section
            for offset, hexdump, instruction in self.dis(code=codeSection):
                self._instructions_history.append((offset + code_section_start_offset, hexdump, instruction))
                try:
                    if instruction.startswith(("CALL", "JMP")):
                        address = instruction.split()[-1].strip("[").strip("]")
                        if address.startswith("0x"):
                            if self._api_address.has_key(address):
                                outfd.write("Process: {0} Pid: {1} Call Address: {2:<#8x}\nApi Call: {3}\n\n".format(str(task.ImageFileName), task.UniqueProcessId, offset + code_section_start_offset, self._api_address[address]))
                                last_instruction = self._instructions_history[-5:-1]
                                for i in last_instruction:
                                    if "PUSH DWORD" in i[2] and not i[2].endswith("]"):
                                        dword_pointer = int(i[2].split()[-1], 16)
                                        dword_start = dword_pointer - (task.Peb.ImageBaseAddress + data_section.VirtualAddress)
                                        dword = self._extract_string(dataSection, dword_start)
                                        outfd.write("{0:<#8x} {1:<32} {2} #{3}\n".format(i[0], i[1], i[2], dword))
                                    else:
                                        outfd.write("{0:<#8x} {1:<32} {2}\n".format(i[0], i[1], i[2]))
                                outfd.write("{0:<#8x} {1:<32} {2} #{3}\n".format(offset + code_section_start_offset, hexdump, instruction, self._api_address[address]))
                                outfd.write("\n")

                            else:
                                continue
                except Exception, e:
                    outfd.write("%s: %s" % (str(task.ImageFileName), e.message))


    def dis(self, address=0, length = 128, code = None, mode = None):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires distorm, available at
            http://www.ragestorm.net/distorm/

        The mode is '16bit', '32bit' or '64bit'. If not supplied, the disasm
        mode is taken from the profile.
        """
        if not sys.modules.has_key("distorm3"):
            print "ERROR: Disassembly unavailable, distorm not found"
            return
        data = code

        # if mode == None:
        #     mode = space.profile.metadata.get('memory_model', '32bit')
        # we'll actually allow the possiblility that someone passed a correct mode
        # if mode not in [distorm3.Decode16Bits, distorm3.Decode32Bits, distorm3.Decode64Bits]:
        #     if mode == '16bit':
        #         mode = distorm3.Decode16Bits
        #     elif mode == '32bit':
        mode = distorm3.Decode32Bits
            # else:
            #     mode = distorm3.Decode64Bits
        distorm_mode = mode

        iterable = distorm3.DecodeGenerator(address, data, distorm_mode)
        for (offset, _size, instruction, hexdump) in iterable:
            # print "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)
            yield offset, hexdump, instruction

    def _extract_string(self, dataSection, dword_start):
        result = ""
        unprintable_flag = False
        for c in dataSection[dword_start:]:
            if c in string.printable:
                result += c
                unprintable_flag = False
                continue
            elif unprintable_flag:
                return result
            else:
                unprintable_flag = True
                continue
        return result

