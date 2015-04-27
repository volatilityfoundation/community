# Volatility Hyper-V Plugins
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2014 Wyatt Roersma(wyattroersma@gmail.com)
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
@author:       Wyatt Roersma (Fannie Mae)
@codehelper:   Daniel Deneweth (Student)
@license:      GNU General Public License 2.0 or later
@contact:      wyattroersam@gmail.com	
@organization: wyattroersma.com
"""
import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.commands as commands
import volatility.win32.tasks as tasks
import volatility.plugins.taskmods as taskmods
from volatility.renderers import TreeGrid

#Plugin name vmconnect
class hpv_vmconnect(taskmods.DllList):  
    """Virtual Machine Console data"""
    def render_text(self, outfd, data):
        # basically the "data" that render_text receives is whatever the plugin's calculate() function yields or returns
        # and in this case Dlllist.calculate() yields a list of processes
        # so Dlllist.calculate() already takes care of creating the address space and filtering the list processes based
        # on -p PID, -o OFFSET, or whatever ~ mhl
        for task in data:
            if str(task.ImageFileName).lower() == "vmconnect.exe":
                # Each individual task creates its own array for its values
                outfd.write("Process            : {0}\n".format(str(task.ImageFileName)))
                outfd.write("PPID               : {0}\n".format(str(task.InheritedFromUniqueProcessId)))
                outfd.write("PID                : {0}\n".format(str(task.UniqueProcessId)))
                outfd.write("Create Time        : {0}\n".format(str(task.CreateTime)))
                # Process AS must be valid
                process_space = task.get_process_address_space()
                # Virtual Machine connect vmconnect.exe
                vmcusername=[("USERNAME=".encode("utf_16le"))]
                vmcuserdomain=[("USERDOMAIN=".encode("utf_16le"))]
                computername=[("COMPUTERNAME=".encode("utf_16le"))]
                connectedvmguid=[("Msvm_VirtualSystemSettingData.VirtualSystemIdentifier=".encode("utf_16le"))]
                for address in task.search_process_memory(computername):
                    cn = obj.Object("String",
                                    offset = address,
                                    vm = process_space,
                                    encoding = "utf16",
                                    length = 48)
                    # Apply string sanity checks for a valid string
                    if cn.is_valid():
                        cmn = str(cn)
                        hvcomputername = cmn[13:]
                outfd.write("Host Computer Name : {0}\n".format(str(hvcomputername)))
                for address in task.search_process_memory(vmcusername):
                    vmcu = obj.Object("String",
                                    offset = address,
                                    vm = process_space,
                                    encoding = "utf16",
                                    length = 48)
                    # Apply string sanity checks for a valid string
                    if vmcu.is_valid():
                        vmcus = str(vmcu)
                        vmconnectcuser = vmcus[9:]
                outfd.write("User Name          : {0}\n".format(str(vmconnectcuser)))
                for address in task.search_process_memory(vmcuserdomain):
                    vmcud = obj.Object("String",
                                       offset = address,
                                       vm = process_space,
                                       encoding = "utf16",
                                       length = 48)
                    # Apply string sanity checks for a valid string
                    if vmcud.is_valid():
                        vmcudomain = str(vmcud)
                        vmconnectuserdomain = vmcudomain[11:]
                # Last value in the process so include double space
                outfd.write("User Domain Name   : {0}\n".format(str(vmconnectuserdomain)))

                for address in task.search_process_memory(connectedvmguid):
                    vmcguid = obj.Object("String",
                                         offset = address,
                                         vm = process_space,
                                         encoding = "utf16",
                                         length = 182)
                    # Apply string sanity checks for a valid string
                    if vmcguid.is_valid():
                        vmconnectguid= str(vmcguid)
                        vmconnectguidvalue = vmconnectguid[-36:]
                outfd.write("VM GUID            : {0}\n\n".format(str(vmconnectguidvalue)))

#Plugin name hpv_clipboard
class hpv_clipboard(taskmods.DllList):    
    """Dump Virtual Machine Clipboard data"""
    def render_text(self, outfd, data):
        # basically the "data" that render_text receives is whatever the plugin's calculate() function yields or returns
        # and in this case Dlllist.calculate() yields a list of processes
        # so Dlllist.calculate() already takes care of creating the address space and filtering the list processes based
        # on -p PID, -o OFFSET, or whatever
        for task in data:
            if str(task.ImageFileName).lower() == "vmconnect.exe":
                # Each individual task creates its own array for its values
                outfd.write("Process : {0}".format(str(task.ImageFileName)))
                outfd.write("   PID : {0}\n".format(str(task.UniqueProcessId)))
            # Process AS must be valid
            process_space = task.get_process_address_space()
            # Virtual Machine connect vmconnect.exe
            clipboardvalue = [("Simulating typing".encode("utf_16le"))]
            for address in task.search_process_memory(clipboardvalue):
                cpbs = obj.Object("String",
                                  offset = address,
                                  vm = process_space,
                                  encoding = "utf16",
                                  length = 1024)
                # Apply string sanity checks for a valid string
                if cpbs.is_valid():
                    clipboardstring = str(cpbs)
                    outfd.write("Clipboard Data: {0}\n".format(str(clipboardstring)))

#Plugin name hpv_vmwp
class hpv_vmwp(taskmods.DllList):      
    """Display the Virtual Machine Process GUID for each running vm"""
    def unified_output(self, data):
        return TreeGrid([("Name", str),
                        ("PID", int),
                        ("PPID", int),
                        ("Create Time", str),
                        ("GUID", str)
                        ],
                        self.generator(data))
    def generator(self,data):
        for task in data:
            # Check for the virtual machin worker process vmwp.exe
            if str(task.ImageFileName).lower() == "vmwp.exe":
                # Process AS must be valid
                process_space = task.get_process_address_space()
                # Find Virtual Machine GUID In the vmwp.exe process
                ntvmname=[("NT VIRTUAL MACHINE".encode("utf_16le"))]
                for address in task.search_process_memory(ntvmname):
                    vmn = obj.Object("String",
                                     offset = address,
                                     vm = process_space,
                                     encoding = "utf16",
                                     length = 128)
                    # Apply string sanity checks for a valid string
                    if vmn.is_valid():
                        vmguid = str(vmn)
                        # Get rid of NT VIRTUAL MACHINE text
                        vmwpguid = vmguid[-36:]

                # Print out Virtual Machine Worker Process information plus the identified GUID
                yield(0, [str(task.ImageFileName),
                          int(task.UniqueProcessId),
                          int(task.InheritedFromUniqueProcessId),
                          str(task.CreateTime or ''),
                          str(vmwpguid),
                          ])

    def render_text(self, outfd, data):
        # Create table header early so users know its running
        self.table_header(outfd, [("Name", "16"),
                                  ("PID", "6"),
                                  ("PPID", "6"),
                                  ("Create Time", "30"),
                                  ("GUID", "40")])
        # basically the "data" that render_text receives is whatever the plugin's calculate() function yields or returns
        #  and in this case Dlllist.calculate() yields a list of processes
        # so Dlllist.calculate() already takes care of creating the address space and filtering the list
        # processes based on -p PID, -o OFFSET, or whatever ~ mhl
        for task in data:
            #Check for the virtual machin worker process vmwp.exe
            if str(task.ImageFileName).lower() == "vmwp.exe":
                # Process AS must be valid
                process_space = task.get_process_address_space()
                # Find Virtual Machine GUID In the vmwp.exe process
                ntvmname=[("NT VIRTUAL MACHINE".encode("utf_16le"))]
                for address in task.search_process_memory(ntvmname):
                    vmn = obj.Object("String",
                                     offset = address,
                                     vm = process_space,
                                     encoding = "utf16",
                                     length = 128)
                    # Apply string sanity checks for a valid string
                    if vmn.is_valid():
                        vmguid = str(vmn)
                        # Get rid of NT VIRTUAL MACHINE text
                        vmwpguid = vmguid[-36:]

                # Print out Virtual Machine Worker Process information plus the identified GUID
                self.table_row(outfd, str(task.ImageFileName),
                               str(task.UniqueProcessId),
                               str(task.InheritedFromUniqueProcessId),
                               str(task.CreateTime or ''),
                               str(vmwpguid))