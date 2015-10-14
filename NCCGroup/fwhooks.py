# Volatility Firewall Hook Drivers Plugin for Windows 2000/XP/2003
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (C) 2014-2015 NCC Group Plc
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

#
# Enumerates modules which are using Firewall Hook Drivers on Windows 2000/XP/2003
# 
# Released as open source by NCC Group Plc - http://www.nccgroup.com/
# 
# Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com
#              Zsolt Imre      , zsolt dot imre at nccgroup dot com
# 

#pylint: disable-msg=C0111

import struct
import itertools
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.win32 as win32
import volatility.utils as utils
import volatility.addrspace as addrspace

class FwHooks(common.AbstractWindowsCommand):
    # http://msdn.microsoft.com/en-us/library/windows/hardware/ff546499%28v=vs.85%29.asp
    """Enumerates modules which are using Firewall Hook Drivers on Windows 2000/XP/2003"""
    
    # Constructor
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    # Printer of output
    def render_text(self, outfd, data):
        
        data = list(data)
        
        for module in data:
            offset = module.obj_vm.vtop(module.obj_offset)
            if 'tcpip.sys' in str(module.BaseDllName  or ''):
                
                # Print out some information about the module we are interested in
                print "[FWHook] Found {0} at offset {1:#08x} with DllBase {2:#08x}".format(str(module.BaseDllName or ''),offset,module.DllBase)
                
                # Get mapping of the kernel virtual address space
                addr_space = utils.load_as(self._config)
                
                # Check we are only dealing with 32bit
                if addr_space.profile.metadata.get('memory_model', '32bit') == '32bit':
                    pack_format = "<I"
                else:
                    print "[FWHook] We can only deal with 32bit!"
                    return
            
                # This reads the first two bytes of the DllBase for debugging / testing - should return MZ
                #data = addr_space.read(module.DllBase, 2)
                #print "[FWHook] MZ == {0}".format(data)
                
                # This is XP SP3 latest TCPIP.SYS
                FQBlockOffset = 0x00051860;
                
                # ------
                # Generic PE / Image Base Address Calculations
                PEHDROffSetRAW = addr_space.read(module.DllBase + 0x3C,4)
                PEHDROffSet = struct.unpack(pack_format, PEHDROffSetRAW)[0]
                print "[FWHook] PE Header Offset: {0:#08x}".format(PEHDROffSet)
                PEHDRAddress = module.DllBase + PEHDROffSet
                # This reads the first two bytes of the PE Header for debugging / testing - should return PE
                #data = addr_space.read(PEHDRAddress, 2)
                #print "[FWHook] PE == {0}".format(data)
                ImageBaseAddressRAW = addr_space.read(PEHDRAddress + 0x34,4)
                ImageBaseAddress = struct.unpack(pack_format, ImageBaseAddressRAW )[0]
                print "[FWHook] Image Base Address: {0:#08x}".format(ImageBaseAddress)
                
                
                # ------
                # Identify where the internal structures are relative to the ImageBaseAddress
                FQBlockAddress = module.DllBase + (FQBlockOffset - ImageBaseAddress)
                print "[FWHook] FQ Block Address: {0:#08x}".format(FQBlockAddress)
                FQCounterAddress = FQBlockAddress + 0x20;
                print "[FWHook] FQ Counter Address: {0:#08x}".format(FQCounterAddress)
                FQCounterValueRAW = addr_space.read(FQCounterAddress,4)
                FQCounterValue = struct.unpack(pack_format, FQCounterValueRAW )[0]
                FQCounterValue = FQCounterValue & 0x1
                FQCounterValue = FQCounterValue << 4
                print "[FWHook] FQ Counter Value: {0} {1:#08x}".format(FQCounterValue,FQCounterValue)              
                FinalFQBlockAddress = FQBlockAddress + FQCounterValue
                print "[FWHook] Final FQ Block Address: {0:#08x}".format(FinalFQBlockAddress)
                
                # ------
                # Check to see if any hooks are registered and if they are count them
                FinalFQBlockAddressValueRAW = addr_space.read(FinalFQBlockAddress ,4)
                FinalFQBlockAddressValue = struct.unpack(pack_format, FinalFQBlockAddressValueRAW )[0]
                if FinalFQBlockAddressValue is FinalFQBlockAddress:
                    print "[FWHook] No hooks registered"
                    return

                FWHookCount = 0
                EAX = FinalFQBlockAddressValue 
                while (1):
                    if(FinalFQBlockAddress == EAX):
                        break
                    FWHookCount = FWHookCount + 1
                    FinalFQBlockAddressValueRAWTmp = addr_space.read(EAX,4)
                    FinalFQBlockAddressValueTmp = struct.unpack(pack_format, FinalFQBlockAddressValueRAWTmp )[0]
                    # print "[FWHook] {0} {1:#08x} {2:#08x} {3:#08x}".format(FWHookCount,  FinalFQBlockAddressValue, FinalFQBlockAddress, EAX)
                    EAX = FinalFQBlockAddressValueTmp
   
                print "[FWHook] Total hooks registered {0}".format(FWHookCount)

                # -----
                # Now walk the list again and get the module names
                
                EAX = FinalFQBlockAddressValue
                while(1):
                    if(FinalFQBlockAddress == EAX):
                        break
                    print "[FWHook] -----------------------------------------------------------------------------------"
                    FWHookCallOutAddressRAW = addr_space.read(EAX + 0x08,4)
                    FWHookCallOutAddress = struct.unpack(pack_format, FWHookCallOutAddressRAW )[0]
                    print "[FWHook] Call Out Address: {0:#08x}".format(FWHookCallOutAddress)
                    
                    FWHookAddr = (FWHookCallOutAddress | 0xFFF) + 1
                    while(1):
                        mzData = addr_space.read(FWHookAddr, 2)
                        # print "[FWHook] MZ == {0}".format(mzData)
                        if(mzData == "MZ"):
                            print "[FWHook] Module Base Address: {0:#08x}".format(FWHookAddr)
                            break
                        else:
                            FWHookAddr = FWHookAddr - 0x1000
                    
                    for moduleinner in data:
                        if (moduleinner.DllBase == FWHookAddr):
                            print "[FWHook] Module DLL Name {0}".format(str(moduleinner.BaseDllName  or ''))
                            print "[FWHook] Module Binary Path {0}".format(str(moduleinner.FullDllName  or ''))

                   
                    FinalFQBlockAddressValueRAWTmp = addr_space.read(EAX,4)
                    FinalFQBlockAddressValueTmp = struct.unpack(pack_format, FinalFQBlockAddressValueRAWTmp )[0]
                    EAX = FinalFQBlockAddressValueTmp
                                   
    # Doer in theory
    # although we do a lot of the heavy lifting in render_text
    def calculate(self):
        addr_space = utils.load_as(self._config)
        result = win32.modules.lsmod(addr_space)
        return result
