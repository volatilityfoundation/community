# Volatility
#
# Authors:
#   Fred House (fred.house@mandiant.com) - Mandiant, a FireEye Company
#   Andrew Davis (andrew.davis@mandiant.com) - Mandiant, a FireEye Company
#   Claudiu Teodorescu (claudiu.teodorescu@fireeye.com) - FireEye Inc.
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
import binascii
import datetime
import volatility.debug as debug
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.taskmods as taskmods
import volatility.utils as utils
import volatility.win32.modules as modules  
import volatility.win32.tasks as tasks  

###############################################################################
# Data Structures
###############################################################################

#######################################
# Windows XP (x86)
#######################################
shimcache_xp_x86 = {

    'SHIM_CACHE_HEADER' : [ 0x190, {
        'Magic' : [0x0, ['unsigned int']],
        'Unknown' : [0x4, ['unsigned int']],
        'NumEntries' : [0x8, ['unsigned int']],
        'Unknown' : [0xc, ['unsigned int']],
    } ],

    'SHIM_CACHE_ENTRY' : [ 0x228, {
        'Path' : [ 0x0, ['NullString', dict(length = 0x208, encoding = 'utf8')]],
        'LastModified' : [ 0x210, ['WinTimeStamp', dict(is_utc = True)]],
        'FileSize': [0x218, ['long long']],
        'LastUpdate' : [ 0x220, ['WinTimeStamp', dict(is_utc = True)]],
    } ],
}

shimcache_xp_sp2_x86 = {
    #redefine for consistency with XP SP3 definition below
    '_SEGMENT' : [ 0x40, {
      'ControlArea' : [ 0x0, ['pointer', ['_CONTROL_AREA']]],
      'TotalNumberOfPtes' : [ 0x4, ['unsigned long']],
      'NonExtendedPtes' : [ 0x8, ['unsigned long']],
      'WritableUserReferences' : [ 0xc, ['unsigned long']],
      'SizeOfSegment' : [ 0x10, ['unsigned long long']],
      'SegmentPteTemplate' : [ 0x18, ['_MMPTE']],
      'NumberOfCommittedPages' : [ 0x1c, ['unsigned long']],
      'ExtendInfo' : [ 0x20, ['pointer', ['_MMEXTEND_INFO']]],
      'SystemImageBase' : [ 0x24, ['pointer', ['void']]],
      'BasedAddress' : [ 0x28, ['pointer', ['void']]],
      'u1' : [ 0x2c, ['pointer', ['void']]],
      'u2' : [ 0x30, ['pointer', ['void']]],
      'PrototypePte' : [ 0x34, ['pointer', ['_MMPTE']]],
      'ThePtes' : [ 0x3c, ['array', 1, ['_MMPTE']]],
    } ],     
}

shimcache_xp_sp3_x86 = {
    #redefine as the sizes of SegmentPteTemplate and PrototypePte are incorrect
    # in the XP overlay (should be 8 bytes, not 4)
    '_SEGMENT' : [ 0x48, {
      'ControlArea' : [ 0x0, ['pointer', ['_CONTROL_AREA']]],
      'TotalNumberOfPtes' : [ 0x4, ['unsigned long']],
      'NonExtendedPtes' : [ 0x8, ['unsigned long']],
      'WritableUserReferences' : [ 0xc, ['unsigned long']],
      'SizeOfSegment' : [ 0x10, ['unsigned long long']],
      'SegmentPteTemplate' : [ 0x18, ['_MMPTE']],
      'NumberOfCommittedPages' : [ 0x20, ['unsigned long']],
      'ExtendInfo' : [ 0x24, ['pointer', ['_MMEXTEND_INFO']]],
      'SystemImageBase' : [ 0x28, ['pointer', ['void']]],
      'BasedAddress' : [ 0x2c, ['pointer', ['void']]],
      'u1' : [ 0x30, ['pointer', ['void']]],
      'u2' : [ 0x34, ['pointer', ['void']]],
      'PrototypePte' : [ 0x38, ['pointer', ['_MMPTE']]],
      'ThePtes' : [ 0x40, ['array', 1, ['_MMPTE']]],
    } ],
}

#######################################
# Windows Server 2003 (x86/x64)
#######################################
shimcache_2003_x86 = {
    'SHIM_CACHE_ENTRY' : [ None, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Path' : [ 0x8, ['_UNICODE_STRING']],
        'LastModified' : [0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'FileSize': [0x18, ['unsigned long']],
        'Padding': [0x20, ['unsigned long']],
    } ],
}

shimcache_2003_x64 = {
    'SHIM_CACHE_ENTRY' : [ 0x30, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Path' : [ 0x10, ['_UNICODE_STRING']],
        'LastModified' : [0x20, ['WinTimeStamp', dict(is_utc = True)]],
        'FileSize' : [0x28, ['unsigned long long']],
    } ],
}

#######################################
# Windows Vista (x86/x64)
# Windows Server 2008 (x86/x64)
#######################################
shimcache_vista_x86 = {
    'SHIM_CACHE_ENTRY' : [ 0x20, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Path' : [ 0x8, ['_UNICODE_STRING']],
        'LastModified' : [0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x18, ['unsigned int']],
        'ShimFlags' : [0x1c, ['unsigned int']],
    } ],
}

shimcache_vista_x64 = {
    'SHIM_CACHE_ENTRY' : [ 0x30, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Path' : [ 0x10, ['_UNICODE_STRING']],
        'LastModified' : [0x20, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x28, ['unsigned int']],
        'ShimFlags' : [0x2c, ['unsigned int']],
    } ],
}

#######################################
# Windows 7 (x86/x64) 
# Windows Server 2008 R2 (x86/x64)
#######################################
shimcache_win7_x86 = {
    'SHIM_CACHE_ENTRY' : [ None, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Path' : [ 0x08, ['_UNICODE_STRING']],
        'LastModified' : [0x10, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x18, ['unsigned int']],
        'ShimFlags' : [0x1c, ['unsigned int']],
        'BlobSize' : [0x20, ['unsigned int']],
        'BlobBuffer' : [0x24, ['unsigned long']],
    } ],
}

shimcache_win7_x64 = {
    'SHIM_CACHE_ENTRY' : [ None, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Path' : [ 0x10, ['_UNICODE_STRING']],
        'LastModified' : [0x20, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x28, ['unsigned int']],
        'ShimFlags' : [0x2c, ['unsigned int']],
        'BlobSize' : [0x30, ['unsigned long long']],
        'BlobBuffer' : [0x38, ['unsigned long long']],
    } ],
}

#######################################
# Windows 8 (x86/x64)
# Windows 8.1 (x86/x64)
# Windows Server 2012 (x86/x64)
# Windows Server 2012 R2 (x86/x64)
#######################################
shimcache_win8_x86 = {
    'SHIM_CACHE_ENTRY' : [ None, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Unknown1' : [ 0x8, ['unsigned long']],
        'Unknown2' : [ 0xc, ['unsigned long']],
        'Path' : [ 0x10, ['_UNICODE_STRING']],
        'Unknown3' : [ 0x18, ['unsigned long long']],
        'ListEntryDetail' : [ 0x20, ['pointer', ['SHIM_CACHE_ENTRY_DETAIL']]],
    } ],
}

shimcache_win8_x86_detail = {
    'SHIM_CACHE_ENTRY_DETAIL' : [ None, {
        'LastModified' : [0x0, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x08, ['unsigned int']],
        'ShimFlags' : [0x0c, ['unsigned int']],
        'BlobSize' : [0x10, ['unsigned long']],
        'BlobBuffer' : [0x14, ['unsigned long']],
    } ],
}

shimcache_win8_x64 = {
    'SHIM_CACHE_ENTRY' : [ None, {
        'ListEntry' : [0x0, ['_LIST_ENTRY']],
        'Unknown1' : [ 0x10, ['unsigned long long']],
        'Path' : [ 0x18, ['_UNICODE_STRING']],
        'Unknown2' : [ 0x28, ['unsigned long long']],
        'Unknown3' : [ 0x30, ['unsigned long long']],
        'ListEntryDetail' : [ 0x38, ['pointer', ['SHIM_CACHE_ENTRY_DETAIL']]],
    } ],
}

shimcache_win8_x64_detail = {
    'SHIM_CACHE_ENTRY_DETAIL' : [ None, {
        'LastModified' : [0x0, ['WinTimeStamp', dict(is_utc = True)]],
        'InsertFlags' : [0x08, ['unsigned int']],
        'ShimFlags' : [0x0c, ['unsigned int']],
        'BlobSize' : [0x10, ['unsigned long long']],
        'Padding' : [0x18, ['unsigned long long']],
        'BlobBuffer' : [0x20, ['unsigned long long']],
    } ],
}

shimcache_objs_x86 = {
    # explicitly define _RTL_BALANCED_LINKS and _RTL_AVL_TABLE as they are not
    # present in all OS platform overlays (e.g., 2003 x64)
    '_RTL_BALANCED_LINKS' : [ 0x10, {
        'Parent' : [ 0x0, ['pointer', ['_RTL_BALANCED_LINKS']]],
        'LeftChild' : [ 0x4, ['pointer', ['_RTL_BALANCED_LINKS']]],
        'RightChild' : [ 0x8, ['pointer', ['_RTL_BALANCED_LINKS']]],
        'Balance' : [ 0xc, ['unsigned char']],
        'Reserved' : [ 0xd, ['array', 3, ['unsigned char']]],
    } ],
    '_RTL_AVL_TABLE' : [ 0x38, {
        'BalancedRoot' : [ 0x0, ['_RTL_BALANCED_LINKS']],
        'OrderedPointer' : [ 0x10, ['pointer', ['void']]],
        'WhichOrderedElement' : [ 0x14, ['unsigned long']],
        'NumberGenericTableElements' : [ 0x18, ['unsigned long']],
        'DepthOfTree' : [ 0x1c, ['unsigned long']],
        'RestartKey' : [ 0x20, ['pointer', ['_RTL_BALANCED_LINKS']]],
        'DeleteCount' : [ 0x24, ['unsigned long']],
        'CompareRoutine' : [ 0x28, ['pointer', ['void']]],
        'AllocateRoutine' : [ 0x2c, ['pointer', ['void']]],
        'FreeRoutine' : [ 0x30, ['pointer', ['void']]],
        'TableContext' : [ 0x34, ['pointer', ['void']]],
    } ],
    # define shim cache handle objects found on Windows 8.x platforms.
    'SHIM_CACHE_HANDLE' : [ 0x8, {
        'eresource' : [ 0x0, ['pointer', ['_ERESOURCE']]],
        'rtl_avl_table' : [ 0x4, ['pointer', ['_RTL_AVL_TABLE']]],
    } ],
}

shimcache_objs_x64 = {
    '_RTL_BALANCED_LINKS' : [ 0x20, {
      'Parent' : [ 0x0, ['pointer64', ['_RTL_BALANCED_LINKS']]],
      'LeftChild' : [ 0x8, ['pointer64', ['_RTL_BALANCED_LINKS']]],
      'RightChild' : [ 0x10, ['pointer64', ['_RTL_BALANCED_LINKS']]],
      'Balance' : [ 0x18, ['unsigned char']],
      'Reserved' : [ 0x19, ['array', 3, ['unsigned char']]],
    } ],
    '_RTL_AVL_TABLE' : [ 0x68, {
      'BalancedRoot' : [ 0x0, ['_RTL_BALANCED_LINKS']],
      'OrderedPointer' : [ 0x20, ['pointer64', ['void']]],
      'WhichOrderedElement' : [ 0x28, ['unsigned long']],
      'NumberGenericTableElements' : [ 0x2c, ['unsigned long']],
      'DepthOfTree' : [ 0x30, ['unsigned long']],
      'RestartKey' : [ 0x38, ['pointer64', ['_RTL_BALANCED_LINKS']]],
      'DeleteCount' : [ 0x40, ['unsigned long']],
      'CompareRoutine' : [ 0x48, ['pointer64', ['void']]],
      'AllocateRoutine' : [ 0x50, ['pointer64', ['void']]],
      'FreeRoutine' : [ 0x58, ['pointer64', ['void']]],
      'TableContext' : [ 0x60, ['pointer64', ['void']]],
    } ],
    'SHIM_CACHE_HANDLE' : [ 0x10, {
      'eresource' : [ 0x0, ['pointer', ['_ERESOURCE']]],
      'rtl_avl_table' : [ 0x8, ['pointer', ['_RTL_AVL_TABLE']]],
    } ],
}

###############################################################################
# Complex Object Definitions
###############################################################################
class ShimCacheEntry(obj.CType):
    """An entry in the Shimcache LRU list. This complext object abstract the
       variations in the LRU list entry structure"""

    def get_file_size(self):
        """Return the file size if available, otherwise None"""
        if hasattr(self, 'FileSize') and self.FileSize >= 0:
            return self.FileSize
        else:
            return None

    def get_last_modified(self):
        """Windows 8 stores the last modified in a ListEntry attribute, 
           where as all other versions store it as an attribute of the 
           ShimCacheEntry object."""
        if hasattr(self, 'ListEntryDetail'):
            return self.ListEntryDetail.LastModified
        else:
            return self.LastModified

    def get_last_update(self):
        """Windows XP provides a LastUpdate attribute"""
        if hasattr(self, 'LastUpdate'):
            return self.LastUpdate
        else:
            return None

    def get_file_path(self, encoding = 'ascii'):
        """Return the shimcache entry file path, stripping any non-utf16
           characters; default encoding is ascii"""

        #the Path attribute has Buffer and Length attributes on every OS except
        #XP, in which case it is a null termined string; return the appropriate
        #path value here
        if not hasattr(self.Path, 'Buffer'):
            return self.Path
                
        file_path = self.obj_vm.read(self.Path.Buffer, self.Path.Length) or ''

        #remove any non-UTF16 characters
        file_path = file_path.decode('utf16', 'ignore')

        #re-encode is specified encoding
        file_path = file_path.encode(encoding, 'ignore')

        return file_path

    def get_exec_flag(self):
        """Checks if InsertFlags fields has been bitwise OR'd with a value of 2.
           This behavior was observed when processes are created by CSRSS."""
        exec_flag = ''
        if hasattr(self, 'ListEntryDetail') and hasattr(self.ListEntryDetail, 'InsertFlags'):
            exec_flag = self.ListEntryDetail.InsertFlags & 0x2 == 2
        elif hasattr(self, 'InsertFlags'):
            exec_flag = self.InsertFlags & 0x2 == 2
        return exec_flag
    
    def __str__(self):
        """String representation of ShimCacheEntry (intended for debugging)"""
      
        blob_off, blob_val = None,None
        try:
            blob_off = self.BlobSize.obj_offset
            blob_val = self.BlobSize.v()
        except AttributeError as e:
            pass

        try:
            last_mod_offset = self.LastModified.obj_offset
        except AttributeError as e:
            last_mod_offset = self.ListEntryDetail.LastModified.obj_offset

        try:
            last_upd_offset = self.LastUpdate.obj_offset
        except AttributeError as e:
            last_upd_offset = None

        if hasattr(self, 'ListEntry'):
            shim_str = "Shimcache Entry at (0x{0:08x})\n".format(self.ListEntry) + \
                       "\tFlink      (0x{0:08x}) = 0x{1:08x}\n".format(self.ListEntry, self.ListEntry.Flink.dereference().obj_offset) + \
                       "\tBlink      (0x{0:08x}) = 0x{1:08x}\n".format(self.ListEntry.obj_offset+self.ListEntry.Flink.size(), self.ListEntry.Blink.dereference().obj_offset) + \
                       "\tPath       (0x{0:08x}) = {1}\n".format(self.Path.obj_offset, self.get_file_path()) + \
                       "\tPath Size  (0x{0:08x}) = {1:d}\n".format(self.Path.Length.obj_offset, self.Path.Length.v()) + \
                       "\tLast Mod   (0x{0:08x}) = {1}\n".format(last_mod_offset, self.get_last_modified())
            if blob_off and blob_val:
                shim_str += "\tBlob Size  (0x{0:08x}) = {1:d}\n".format(self.BlobSize.obj_offset, self.BlobSize.v())
        else:
            shim_str = "Shimcache Entry at (0x{0:08x})\n".format(self.obj_offset) + \
                       "\tPath     (0x{0:08x}) = {1}\n".format(self.Path.obj_offset, self.get_file_path()) + \
                       "\tFile Sz  (0x{0:08x}) = {1}\n".format(self.FileSize.obj_offset, self.get_file_size()) + \
                       "\tLast Mod (0x{0:08x}) = {1}\n".format(last_mod_offset, self.get_last_modified()) + \
                       "\tLast Upd (0x{0:08x}) = {1}\n".format(last_upd_offset, self.get_last_update())

        return shim_str

    def is_valid(self):
        """Shim cache validation is limited to ensuring that a subset of the 
           pointers in the LIST_ENTRY field are valid (similar to validation of 
           ERESOURCE)"""
    
        if not obj.CType.is_valid(self):
            debug.debug("Invalid SHIM_CACHE_ENTRY object at 0x{0:08x}".format(self.v()))
            return False

        #shim entries on Windows XP do not have list entry attributes; in this case,
        #perform a different set of validations
        if not hasattr(self, 'ListEntry'):
            return self.LastModified and self.LastModified.is_valid() and \
                   self.LastUpdate and self.LastUpdate.is_valid() and \
                   self.FileSize and self.FileSize.is_valid()
            
        # on some platforms ListEntry.Blink is null, so this cannot be validated  
        if (self.ListEntry.Flink != None and
            self.ListEntry.Blink.v() != self.ListEntry.Flink.v() and
            self.ListEntry.Flink.Blink == self.ListEntry.Flink.Blink.dereference().obj_offset):
    
            debug.info("SHIM_CACHE_ENTRY candidate found at 0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
            debug.debug("\tListEntry.Flink       (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Flink, self.ListEntry.Flink.dereference().obj_offset))
            debug.debug("\tListEntry.Blink       (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Blink, self.ListEntry.Blink.dereference().obj_offset))
            debug.debug("\tListEntry.Flink.Blink (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Flink.Blink, self.ListEntry.Flink.Blink.dereference().obj_offset))
            debug.debug("\tListEntry.Blink.Flink (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Blink.Flink, self.ListEntry.Blink.Flink.dereference().obj_offset))
            return True
        else:
            debug.info("Invalid SHIM_CACHE_ENTRY candidate found at 0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
            debug.debug("\tListEntry.Flink       (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Flink, self.ListEntry.Flink.dereference().obj_offset))
            debug.debug("\tListEntry.Blink       (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Blink, self.ListEntry.Blink.dereference().obj_offset))
            debug.debug("\tListEntry.Flink.Blink (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Flink.Blink, self.ListEntry.Flink.Blink.dereference().obj_offset))
            debug.debug("\tListEntry.Blink.Flink (0x{0:08x}) = 0x{1:08x}".format(self.ListEntry.Blink.Flink, self.ListEntry.Blink.Flink.dereference().obj_offset))
        
        debug.debug("Invalid SHIM_CACHE_ENTRY candidate at  0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
    
        return False
            
###############################################################################
# Complex Object Definition
###############################################################################
class _RTL_AVL_TABLE(obj.CType):
    """Override the RTL_AVL_TABLE object to include a ShimCache-specific 
       validation method"""

    def is_valid(self, page_start, page_end):
        """This function implements the following validations:
           1) BalancedRoot.Parent points to the _RTL_AVL_TABLE object
           2) Allocate, Compare, and Free functions points to virtual memory
              offsets on the same memory page as the loaded module
           3) Allocate, Compare, and Free function pointers are unique values
        """

        if self.BalancedRoot.Parent != self.BalancedRoot:
            debug.debug("0x{0:08x} (0x{1:08x}) - RTL_AVL_TABLE.BalancedRoot.Parent (0x{2:08x}) != RTL_AVL_TABLE.BalancedRoot (0x{3:08x})".format( \
                        self.v(),
                        self.obj_vm.vtop(self.v()),
                        self.BalancedRoot.Parent, 
                        self.BalancedRoot))
            return False

        elif self.AllocateRoutine < page_start or self.AllocateRoutine > page_end:
            debug.debug("RTL_AVL_TABLE.AllocateRoutine pointer (0x{0:08x}) not between 0x{1:08x} - 0x{2:08x}".format(self.AllocateRoutine, page_start, page_end))
            return False
        
        elif self.CompareRoutine < page_start or self.CompareRoutine > page_end:
            debug.debug("RTL_AVL_TABLE.CompareRoutine pointer (0x{0:08x}) not between 0x{1:08x} - 0x{2:08x}".format(self.CompareRoutine, page_start, page_end))
            return False
        
        elif self.FreeRoutine < page_start or self.FreeRoutine > page_end:
            debug.debug("RTL_AVL_TABLE.FreeRoutine pointer (0x{0:08x}) not between 0x{1:08x} - 0x{2:08x}".format(self.FreeRoutine, page_start, page_end))
            return False

        elif (self.AllocateRoutine == self.CompareRoutine) or \
             (self.AllocateRoutine == self.FreeRoutine)    or \
             (self.CompareRoutine  == self.FreeRoutine):
            debug.debug("RTL_AVL_TABLE.AllocateRoutine (0x{0:08x}), CompareRoutine (0x{0:08x}), FreeRoutine (0x{0:08x}) not unique".format(\
                       self.AllocateRoutine,
                       self.FreeRoutine,
                       self.CompareRoutine))
            return False

        debug.debug("RTL_AVL_TABLE candidate found at 0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
        debug.debug("\tBalancedRoot        = 0x{0:08x}".format(self.BalancedRoot))
        debug.debug("\tBalancedRoot.Parent = 0x{0:08x}".format(self.BalancedRoot.Parent))
        debug.debug("\tAllocateRoutine     = 0x{0:08x}".format(self.AllocateRoutine))
        debug.debug("\tCompareRoutine      = 0x{0:08x}".format(self.CompareRoutine))
        debug.debug("\tFreeRoutine         = 0x{0:08x}".format(self.FreeRoutine))

        return True

###############################################################################
# Complex Object Definition
###############################################################################
class _ERESOURCE(obj.CType):
    """Shimcache consists of ERESOURCE + RTL_AVL_TABLE + LIST_ENTRY"""

    def is_valid(self):
        """Validate that the ERESOURCE object's LIST_ENTRY pointer are valid
           and that the SharedWaiters fields are 0"""
        
        if not obj.CType.is_valid(self):
            debug.debug("Invalid _ERESOURCE candidate at 0x{0:08x}".format(self.v()))
            return False

        if (self.SystemResourcesList.Flink != None and
            self.SystemResourcesList.Blink != None and 
            self.SystemResourcesList.Blink.v() != self.SystemResourcesList.Flink.v() and
            self.SystemResourcesList.Flink.Blink == self.v() and
            self.SystemResourcesList.Blink.Flink == self.v() and
            self.SharedWaiters == 0 and
            self.NumberOfSharedWaiters == 0):

            debug.debug("_ERESOURCE candidate found at 0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
            debug.debug("\tSystemResourcesList.Flink       (0x{0:08x}) = 0x{1:08x}".format(self.SystemResourcesList.Flink, self.SystemResourcesList.Flink.dereference().obj_offset))
            debug.debug("\tSystemResourcesList.Blink       (0x{0:08x}) = 0x{1:08x}".format(self.SystemResourcesList.Blink, self.SystemResourcesList.Blink.dereference().obj_offset))
            debug.debug("\tSystemResourcesList.Flink.Blink (0x{0:08x}) = 0x{1:08x}".format(self.SystemResourcesList.Flink.Blink, self.SystemResourcesList.Flink.Blink.dereference().obj_offset))
            debug.debug("\tSystemResourcesList.Blink.Flink (0x{0:08x}) = 0x{1:08x}".format(self.SystemResourcesList.Blink.Flink, self.SystemResourcesList.Blink.Flink.dereference().obj_offset))
            debug.debug("\tSharedWaiters                   = 0x{0:08x}".format(self.SharedWaiters))
            debug.debug("\tNumberOfSharedWaiters           = {0:d}".format(self.NumberOfSharedWaiters))

            return True

        debug.debug("Invalid _ERESOURCE candidate at  0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
        return False

###############################################################################
# Complex Object Definition
###############################################################################
class ShimCacheHandle(obj.CType):
    """A Shim cache handle consists of two sequential pointers: the first to an 
       ERESOURCE object and the second to an RTL_AVL_TABLE object. The shim
       cache handle is used on Windows 8 platforms."""

    def __init__(self, *args, **kwargs):
        # used to store a pointer to the head of the shim cache LRU list; this
        # field is set upon successful validation of the object
        self.shim_cache_head = None
        obj.CType.__init__(self, *args, **kwargs)

    def get_head(self):
        """Return the head of the shim cache LRU list via this handle object"""
        if self.shim_cache_head is None:
            self.is_valid()
        return self.shim_cache_head
    
    def is_valid(self, page_start, page_end):
        """Validates that the object contains a pointer to a valid ERESOURCE
           object followed by a pointer to a valid RTL_AVL_TABLE object; this
           function requires the memory page range of the handle pointer in 
           order to validate the RTL_AVL_TABLE object"""

        if not obj.CType.is_valid(self):
            debug.debug("Invalid SHIM_CACHE_HANDLE object at 0x{0:08x}".format(self.v()))
            return False

        if self.eresource.dereference_as("_ERESOURCE").is_valid():
            rtl_avl_table = self.rtl_avl_table.dereference_as("_RTL_AVL_TABLE")
            if rtl_avl_table.is_valid(page_start, page_end):
                
                offset_shim = rtl_avl_table.v() + rtl_avl_table.size()
                debug.debug("Testing for LRU at 0x{0:08x} (v) 0x{1:08x} (p)".format(offset_shim, self.obj_vm.vtop(offset_shim)))
                shim_cache_head = obj.Object("SHIM_CACHE_ENTRY", offset = offset_shim, vm = self.obj_vm)
                
                if shim_cache_head.is_valid():
                    debug.info("Shimcache found at 0x{0:08x}".format(shim_cache_head))
                    debug.info("\t_RTL_AVL_TABLE:  0x{0:08x} 0x{1:08x}".format(rtl_avl_table, rtl_avl_table.obj_vm.vtop(rtl_avl_table.obj_offset)))
                    debug.info("\tSHIM_CACHE:      0x{0:08x} 0x{1:08x}".format(shim_cache_head, shim_cache_head.obj_vm.vtop(shim_cache_head.obj_offset)))
                    self.shim_cache_head = shim_cache_head
                    return True
                                    
        debug.debug("Invalid SHIM_CACHE_HANDLE candidate at  0x{0:08x} (v) 0x{1:08x} (p)".format(self.v(), self.obj_vm.vtop(self.obj_offset)))
        return False
        
###############################################################################
# Profile Modifications (borrowed from plugins/registry/shimcache.py)
###############################################################################
class ShimCacheEntryTypeXPSP2x86(obj.ProfileModification):
    """A shimcache entry on Windows XP SP2 (x86)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '32bit',
                  'vtype_module': lambda x: x == 'volatility.plugins.overlays.windows.xp_sp2_x86_vtypes',}
    def modification(self, profile):
        profile.vtypes.update(shimcache_xp_x86)
        profile.vtypes.update(shimcache_xp_sp2_x86)

class ShimCacheEntryTypeXPSP3x86(obj.ProfileModification):
    """A shimcache entry on Windows XP SP3 (x86)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '32bit',
                  'vtype_module': lambda x: x == 'volatility.plugins.overlays.windows.xp_sp3_x86_vtypes',}
    def modification(self, profile):
        profile.vtypes.update(shimcache_xp_x86)
        profile.vtypes.update(shimcache_xp_sp3_x86)

class ShimCacheEntryType2003x86(obj.ProfileModification):
    """A shimcache entry on Windows Server 2003 (x86)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_2003_x86)

class ShimCacheEntryTypeVistax86(obj.ProfileModification):
    """A shimcache entry on Windows Vista (x86) and Windows Server 2008 (x86)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_vista_x86)

class ShimCacheEntryTypeWin7x86(obj.ProfileModification):
    """A shimcache entry on Windows 7 (x86) and Windows Server 2008 R2 (x86)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_win7_x86)

class ShimCacheEntryTypeWin8x86(obj.ProfileModification):
    """A shimcache entry on Windows 8, 8.1, 2012, and 2012 R2 (x86)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x in (2,3),
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_win8_x86)
        profile.vtypes.update(shimcache_win8_x86_detail)

class ShimCacheEntryType2003x64(obj.ProfileModification):
    """A shimcache entry on Windows Server 2003 (x64)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5,
                  'minor': lambda x: x == 2,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_2003_x64)
        
class ShimCacheEntryTypeVistax64(obj.ProfileModification):
    """A shimcache entry on Windows Vista (x64) and Windows Server 2008 (x64)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_vista_x64)

class ShimCacheEntryTypeWin7x64(obj.ProfileModification):
    """A shimcache entry on Windows 7 (x64) and Windows Server 2008 R2 (x64)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 1,
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_win7_x64)

class ShimCacheEntryTypeWin8x64(obj.ProfileModification):
    """A shimcache entry on Windows 8, 8.1, 2012, and 2012 R2 (x64)"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x in (2,3),
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_win8_x64)
        profile.vtypes.update(shimcache_win8_x64_detail)

class ShimCachex86(obj.ProfileModification):
    """The shimcache on x86 platforms"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '32bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_objs_x86)

class ShimCachex64(obj.ProfileModification):
    """The shimcache on x64 platforms"""
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'memory_model': lambda x: x == '64bit'}
    def modification(self, profile):
        profile.vtypes.update(shimcache_objs_x64)

class ShimCacheObjectClasses(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        profile.object_classes.update({'_ERESOURCE': _ERESOURCE})
        profile.object_classes.update({'_RTL_AVL_TABLE': _RTL_AVL_TABLE})
        profile.object_classes.update({'SHIM_CACHE_ENTRY' : ShimCacheEntry})
        profile.object_classes.update({'SHIM_CACHE_HANDLE': ShimCacheHandle})

###############################################################################
# Miscellaneous helper function to print bytes at an offset
###############################################################################
def print_bytes(addr_space, offset, num_bytes, bytes_per_line=32):
    for chunk in range(offset, offset + num_bytes, bytes_per_line):
        bytes = addr_space.read(chunk, bytes_per_line)
        if bytes:
            debug.info(' '.join("%02x" % ord(b) for b in bytes))
        else:
            debug.info("Error reading bytes at {0:08x}".format(offset))

###############################################################################
# ShimCacheMem Plugin
###############################################################################
class ShimCacheMem(common.AbstractWindowsCommand):
    """Parses the Application Compatibility Shim Cache stored in kernel memory"""

    # list of NT kernel modules that could contain the shimcache
    NT_KRNL_MODS = ['ntoskrnl.exe', 'ntkrnlpa.exe', 'ntkrnlmp.exe', 'ntkrpamp.exe']

    ###########################################################################
    # 
    ###########################################################################
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("CLEAN_FILE_PATHS", 
                          short_option = 'c', 
                          default = False,
                          help = "Replaces 'SYSVOL' with 'C:\' and strips UNC paths; provided as a convenience for analysts", 
                          action = "store_true")

        config.add_option("PRINT_OFFSETS", 
                          short_option = 'P', 
                          default = False,
                          help = "Print virtual and physical offsets of each shim cache entry (intended for debug/analysis of raw memory images)", 
                          action = "store_true")

        # used to track eresource object sizes depending on platform bitness
        self.eresource_sz = None
        self.eresource_alignment = None

    ###########################################################################
    # 
    ###########################################################################
    def parse_shim_win_xp(self, shim_prcs_space, shim_vad):
        """Parses the shim cache in the provided process address space at the
          provided virtual address."""

        SHIM_MAGIC_HEADER = '\xef\xbe\xad\xde'
        SHIM_NUM_ENTRIES_OFFSET = 0x8
        SHIM_MAX_ENTRIES = 0x60 #96 max entries in XP shim cache
        SHIM_LRU_OFFSET = 0x10
        SHIM_HEADER_SIZE = 0x190
        SHIM_CACHE_ENTRY_SIZE = 0x228
        
        shim_entries = [] #used to store parsed shim cache entries

        #validate the VAD starts with the magic value (0xDEADBEEF)
        data = shim_prcs_space.read(shim_vad.Start, 4)
        if data == SHIM_MAGIC_HEADER:
            debug.info("Shim cache magic header found at 0x{0:08x} (0x{1:08x})".format(shim_vad.Start, shim_prcs_space.vtop(shim_vad.Start)))
        else:
            if data is None:
                debug.error("Unable to read VAD at offset 0x{0:x}. This may indicate a corrupt or partial memory dump.".format(shim_vad.Start))
            else:
                debug.error("Unexpected magic value '{0}' found in VAD. This may indicate a corrupt or partial memory dump.".format(binascii.hexlify(data)))
            return None
            
        #validate that the number of entries doesn't exceed the max value on Windows XP
        num_entries = obj.Object("unsigned int", offset = shim_vad.Start + SHIM_NUM_ENTRIES_OFFSET, vm = shim_prcs_space)
        if num_entries > SHIM_MAX_ENTRIES:
            debug.error("Number of entries found in cache ({0}) exceeds XP maximum ({1}); aborting.".format(num_entries, SHIM_MAX_ENTRIES))
            return None

        #there is a table at SHIM_LRU_OFFSET that maintains the contains indexes
        #used to maintain the order of the shim cache entries; the index table 
        #must be walked sequentially to calculate the offset of the next entry
        #in the shim cache
        cache_idx_ptr = shim_vad.Start + SHIM_LRU_OFFSET
       
        for x in range(0, num_entries):
       
            #fetch the value of the index using the pointer into the index table
            cache_idx_val = obj.Object("unsigned long", offset = cache_idx_ptr, vm = shim_prcs_space)

            #increment the pointer to the next index vlaue
            cache_idx_ptr += 4
            
            #index value cannot exceed the maximum number of entries in a shim cache
            if cache_idx_val > SHIM_MAX_ENTRIES-1:
                debug.warning("Invalid index value ({0}) found in shim cache LRU table at offset 0x{1:x}.".format(cache_idx_val, cache_idx_ptr))
                continue                
            
            #fetch the shim entry at the specified index
            shim_entry_offset = shim_vad.Start + SHIM_HEADER_SIZE + (SHIM_CACHE_ENTRY_SIZE * cache_idx_val)
            shim_entry = obj.Object("SHIM_CACHE_ENTRY", offset = shim_entry_offset, vm = shim_prcs_space)
            if not shim_entry.is_valid():
                debug.warning("Shim entry contains one or more invalid fields:\n{0}".format(str(shim_entry)))
            shim_entries.append(shim_entry)

        return shim_entries

    ###########################################################################
    # 
    ###########################################################################
    def find_shim_win_xp(self, addr_space):
        """Implements the algorithm to search for the shim cache on Windows XP
           (x86). The algorithm consists of the following:

           1) Find the ShimSharedMemory section object, which every XP user
              process has a handle to.
           2) Using the section object, find the process that contains the
              shim cache (always winlogon.exe) and the virtual offset in the 
              process where the shim cache begins
           3) Use the VAD to obtain the corresponding process memory space
           4) Parse the shim cache
        """
        shim_prcs_offset = None #offset of process ERESOURCE object containing 
                                #shim cache (winlogon.exe)
        shim_prcs_vad = None    #virtual address in shim cache process containing 
                                #shim cache
        
        debug.info("Searching for ShimSharedMemory section handle...")
        
        #search all tasks for a section handle named ShimSharedMemory
        for task in taskmods.DllList(self._config).calculate():
            
            debug.debug("\tChecking {0}".format(task.ImageFileName))
            pid = task.UniqueProcessId
            if task.ObjectTable.HandleTableList:
                for handle in task.ObjectTable.handles():
                    if not handle.is_valid():
                        continue

                    #check if the handle is to the ShimSharedMemory section
                    object_type = handle.get_object_type()
                    if object_type == "Section" and str(handle.NameInfo.Name or '') == "ShimSharedMemory":
                        debug.info("\tFound ShimSharedMemory handle in {0} ({1})".format(task.ImageFileName, task.UniqueProcessId))

                        #ShimSharedMemory handle points to a section object
                        shim_section = handle.dereference_as("_SECTION_OBJECT")
                        debug.info("\tShim section object found at (0x{0:08x}) 0x{1:08x}".format(shim_section.obj_offset, shim_section.obj_vm.vtop(shim_section.obj_offset)))
                        debug.debug("\tSectionObject.Segment    (0x{0:08x}) = 0x{1:08x}".format(shim_section.Segment, shim_section.Segment.dereference().obj_offset))
                        
                        #segment field in section object contains additional pointers to shim cache
                        shim_segment = shim_section.Segment.dereference_as("_SEGMENT")
                        debug.info("\tShim segment found at (0x{0:08x}) 0x{1:08x}".format(shim_segment.obj_offset, shim_segment.obj_vm.vtop(shim_segment.obj_offset)))
                        debug.debug("\tShim Process Offset (0x{0:08x}) = 0x{1:08x}".format(shim_segment.u1.obj_offset, shim_segment.u1.v()))
                        debug.debug("\tShim Process VAD (0x{0:08x})    = 0x{1:08x}".format(shim_segment.u2.obj_offset, shim_segment.u2.v()))
                        
                        #u1 is the offset of the EPROCESS object of the process
                        #that contains the shim cache (winlogon.exe on XP); u2
                        #is the virtual address of the cache within that process
                        shim_prcs_offset = shim_segment.u1.v()
                        shim_prcs_vad = shim_segment.u2.v()

                        break

            #check if process and virtual address of shim were found in previous task
            if shim_prcs_offset and shim_prcs_vad:
    
                #find the process using the shim process offset obtained above
                shim_prcs = None
                for proc in tasks.pslist(addr_space):
                    if proc.obj_offset == shim_prcs_offset:
                        shim_prcs = proc
                        debug.info("Process '{0}' ({1}) contains shim cache at virtual address 0x{2:08x}".format(shim_prcs.ImageFileName, shim_prcs.UniqueProcessId, shim_segment.u2.v()))
                        break
                
                if shim_prcs is None:
                    debug.error("Unable to find process at offset 0x{0:08x}. This may indicate a corrupt or partial memory dump.".format(shim_prcs_offset))
                    return None
                
                #process found; find the VAD that correponds to the virtual address offset within the process
                shim_vad, shim_prcs_space = None, None
                for vad, prcs_space in shim_prcs.get_vads():
                    if vad.Start == shim_segment.u2.v():
                        debug.debug("Found VAD at 0x{0:x} - 0x{1:x} in {2} ({3})".format(vad.Start, vad.Start+vad.Length, shim_prcs.ImageFileName, shim_prcs.UniqueProcessId))
                        shim_vad = vad
                        shim_prcs_space = prcs_space

                if shim_vad is None or shim_prcs_space is None:
                    debug.error("Unable to find VAD at 0x{0:x} in process {1} ({2}). This may indicate a corrupt or partial memory dump.".format(shim_prcs_offset, shim_prcs.ImageFileName, shim_prcs.UniqueProcessId))
                    return None
            
                shim_entries = self.parse_shim_win_xp(shim_prcs_space, shim_vad)
                return shim_entries
            else:
                debug.debug("\tNo valid shim section or segment object found in {0} ({1})".format(task.ImageFileName, task.UniqueProcessId))

        return None

    ###########################################################################
    # 
    ###########################################################################
    def find_shim_win_2k3(self, addr_space):
        """Implements the algorithm to search for the shim cache on Windows 2000
           (x64) through Windows 7 / 2008 R2. The algorithm consists of the following:
           
           1) Find the NT kernel module's .data and PAGE sections
           2) Iterate over every 4/8 bytes (depending on OS bitness) in the .data
              section and test for the following:
              a) offset represents a valid RTL_AVL_TABLE object
              b) RTL_AVL_TABLE is preceeded by an ERESOURCE object
              c) RTL_AVL_TABLE is followed by the beginning of the SHIM LRU list
        """
        data_sec_offset, data_sec_size = self.get_module_section_range(addr_space, self.NT_KRNL_MODS, ".data")
        mod_page_offset, mod_page_size = self.get_module_section_range(addr_space, self.NT_KRNL_MODS, "PAGE")

        debug.info("Scanning range 0x{0:08x} - 0x{1:08x}".format(data_sec_offset, data_sec_offset + data_sec_size))

        # pointer to head of shim cache (if found)
        shim_cache_head = None
        
        # get pointer size for OS bitness
        addr_size = addr_space.profile.get_obj_size("address")

        # iterate over NT kernel module's .data section
        for offset in range(data_sec_offset, data_sec_offset + data_sec_size, addr_size):

            # test if current offset is a valid _RTL_AVL_TABLE object; module's page 
            # size is used to validate pointers within the AVL table
            rtl_avl_table = obj.Object("_RTL_AVL_TABLE", offset = offset, vm = addr_space)
            if not rtl_avl_table.is_valid(mod_page_offset, mod_page_offset + mod_page_size):
                continue

            # calculate relative offset of ERESOURCE, which must preceed AVL table
            offset_ersrc_rel = self.eresource_sz + ((offset - self.eresource_sz) % self.eresource_alignment)
            offset_ersrc = offset - offset_ersrc_rel 
    
            # test if calculated offset is a valid _ERESOURCE object
            eresource = obj.Object("_ERESOURCE", offset = offset_ersrc, vm = addr_space)
            if not eresource.is_valid():
                continue

            # calculate offset of shim LRU list that follows AVL table
            offset_shim_list = offset + rtl_avl_table.size()

            debug.debug("Shimcache list candidate found at 0x{0:08x}".format(offset_shim_list))
            shim_cache_head = obj.Object("SHIM_CACHE_ENTRY", offset = offset_shim_list, vm = addr_space)
            
            if not shim_cache_head.is_valid():
                shim_cache_head = None
                continue
            else:
                debug.info("Shimcache found at 0x{0:08x}".format(shim_cache_head))
                debug.debug("\t_ERESOURCE:      0x{0:08x} 0x{1:08x}".format(eresource, eresource.obj_vm.vtop(eresource.obj_offset)))
                debug.debug("\t_RTL_AVL_TABLE:  0x{0:08x} 0x{1:08x}".format(rtl_avl_table, rtl_avl_table.obj_vm.vtop(rtl_avl_table.obj_offset)))
                debug.debug("\tSHIM_CACHE:      0x{0:08x} 0x{1:08x}".format(shim_cache_head, shim_cache_head.obj_vm.vtop(shim_cache_head.obj_offset)))
                break

        return shim_cache_head

    ###########################################################################
    # 
    ###########################################################################
    def find_shim_win_8(self, addr_space, module_list):
        """Implements the algorithm to search for the shim cache on Windows 8
           and 8.1. Returns up to two shim caches. On Windows 8+, there are two
           caches, though only one is relevent to the shim cache. The algorithm
           is as follows:
           
           1) Find the ahcache kernel module's .data and PAGE sections
           2) Iterate over every 4/8 bytes (depending on OS bitness) in the 
              .data section and test for the following:
              a) offset is a pointer to a handle, consisting of two pointers:
                 i) pointer to an RTL_AVL_TABLE object
                 ii) pointer to an ERESOURCE object
                 
              b) RTL_AVL_TABLE is preceeded by an ERESOURCE object
              c) RTL_AVL_TABLE is followed by the beginning of the SHIM LRU list
        """
        data_sec_offset, data_sec_size = self.get_module_section_range(addr_space, module_list, ".data")
        mod_page_offset, mod_page_size = self.get_module_section_range(addr_space, module_list, "PAGE")

        debug.info("Scanning range 0x{0:08x} - 0x{1:08x}".format(data_sec_offset, data_sec_offset + data_sec_size))

        # get pointer size for OS bitness
        addr_size = addr_space.profile.get_obj_size("address")

        # list to store the two expected caches
        shim_cache_list = []
        
        # iterate over ahcache kernel module's .data section in search of *two* SHIM handles
        for offset in range(data_sec_offset, data_sec_offset + data_sec_size, addr_size):
    
            debug.debug("Testing for shim handle at 0x{0:8x} 0x{1:8x}".format(offset, addr_space.vtop(offset)))
            shim_handle_ptr = obj.Object("Pointer", offset = offset, vm = addr_space)
            shim_handle = shim_handle_ptr.dereference_as("SHIM_CACHE_HANDLE")

            # module's page size is used to validate pointers within the AVL table
            if shim_handle.is_valid(mod_page_offset, mod_page_offset + mod_page_size):
                shim_cache_head = shim_handle.get_head()
                debug.info("Shim handle at 0x{0:08x} (0x{1:08x}) points to a valid shim cache at 0x{2:8x}".format(offset, addr_space.vtop(offset), shim_cache_head))
                shim_cache_list.append(shim_cache_head)
                if len(shim_cache_list) == 2:
                    break

        if len(shim_cache_list) != 2:
            debug.warning("Unable to find Windows 8 caches")
            shim_cache_list = [None, None]
            
        return shim_cache_list

    ###########################################################################
    # 
    ###########################################################################
    def get_module_section_range(self, addr_space, module_list, section_name):
        """Locates the size and offset of the specified module section"""

        debug.info("Searching for '{0}' section in the following kernel module(s): {1}".format(section_name, ', '.join(module_list)))

        krnl_mod = None

        for module in modules.lsmod(addr_space):
            if str(module.BaseDllName or '').lower() in module_list:
                krnl_mod = module
                debug.info("Found kernel module '{0}' at offset 0x{1:08x}".format(krnl_mod.BaseDllName, krnl_mod.DllBase))
                break
            else:
                debug.debug("Ignoring module {0}".format(module.BaseDllName))

        if krnl_mod == None:
            debug.error("Unable to locate kernel module(s): {0}".format(', '.join(module_list)))
            return -1,-1

        debug.info("Searching for {0} section...".format(section_name))

        section = None
        
        # code taken from Win32KBase._section_chunks (win32_core.py)
        dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = krnl_mod.DllBase, vm = krnl_mod.obj_vm)
        if dos_header:
            try:
                nt_header = dos_header.get_nt_header()
                            
                for sec in nt_header.get_sections():
                    if str(sec.Name or '').lower() == section_name.lower():
                        section = sec
                        debug.debug("Found {0} section at 0x{1:08x}".format(section_name, section.VirtualAddress))
                        debug.debug("\tModule Base:      0x{0:08x}".format(krnl_mod.DllBase))
                        debug.debug("\tVirtual Address:  0x{0:08x}".format(section.VirtualAddress))
                        debug.debug("\tVirtual Size:     0x{0:08x}".format(section.Misc.VirtualSize))
                        debug.debug("\tPhysical Address: 0x{0:08x}".format(section.obj_vm.vtop(section.obj_offset)))
                        break
                    else:
                        debug.debug("Ignoring section {0} at address {1}".format(sec.Name, sec.VirtualAddress))

            except ValueError:
                ## This catches PE header parsing exceptions 
                pass
        else:
            debug.error("Unable to instantiate DOS header for kernel module")
            return -1,-1

        if section == None:
            debug.error("Unable to locate section in kernel module {0}.".format(krnl_mod.BaseDllName))
            return -1,-1
  
        section_offset = krnl_mod.DllBase + section.VirtualAddress
        section_size = section.Misc.VirtualSize
        debug.info("Found {0} section at 0x{1:08x} with size 0x{2:x}".format(section_name, section.VirtualAddress, section_size))
        
        return section_offset, section_size

    ###########################################################################
    # 
    ###########################################################################
    def calculate(self):
        """Find and dump the shimcache from memory"""

        if self._config.OUTPUT == "csv" and not self._config.OUTPUT_FILE:
            debug.error("You must also specify an output file using --output-file")

        debug.info("Shimcache Memory Dump")

        addr_space = utils.load_as(self._config)

        #plugin supports XPx64, 2003, 2003R2, Vista, 2008, 2008R2, and 7
        os_vsn_maj = addr_space.profile.metadata.get('major', 0)
        os_vsn_min = addr_space.profile.metadata.get('minor', 0)
        
        # get size and alignment of _ERESOURCE object to use during scanning
        self.eresource_sz = addr_space.profile.get_obj_size("_ERESOURCE")

        # it would be more appropriate to define the alignment as an attribute 
        # of the ERESOURCE object based on platform bitness
        memory_model = addr_space.profile.metadata.get('memory_model', '32bit')
        if memory_model == '32bit':
            self.eresource_alignment = 0x10
        else:
            self.eresource_alignment = 0x20
       
        # pointer to the head of the shim cache LRU list
        shim_cache_head = None

        # plugin currently supports XP x86 (5.1) - Windows 8.1/Server 2012 R2 (6.3) 
        if (os_vsn_maj, os_vsn_min) not in [(5,1),(5,2),(6,0),(6,1),(6,2),(6,3),]:
            debug.error("Plugin does not support Windows {0}.{1}. Plugin supports 5.1 (XP) - 6.3 (Windows 8.1 / Server 2012 R2)".format(os_vsn_maj, os_vsn_min))
            return

        ####################################
        # Windows XP x86
        ####################################
        if (os_vsn_maj == 5 and os_vsn_min <= 1):
            shim_cache_list = self.find_shim_win_xp(addr_space)
            if shim_cache_list is None:
                debug.error("XP shim cache not found")
            else:
                for shim_entry in shim_cache_list:
                    yield (shim_entry.get_file_path(), 
                           shim_entry.get_file_size(), 
                           shim_entry.get_last_modified(), 
                           shim_entry.get_last_update(),
                           None,                           #exec flag not present on XP
                           shim_entry.obj_offset, 
                           shim_entry.obj_vm.vtop(shim_entry.obj_offset))
                debug.info("Shimcache parsed with {0:d} entries".format(len(shim_cache_list)))
            return

        ####################################
        #Windows XP x64, 2003/2003R2, Vista/2008, 7/2008 R2
        ####################################
        elif (os_vsn_maj == 5 and os_vsn_min == 2) or (os_vsn_maj == 6 and os_vsn_min <= 1):
            shim_cache_head = self.find_shim_win_2k3(addr_space)

        ####################################
        #Windows 8/2012, 8.1/2012R2
        ####################################
        elif (os_vsn_maj == 6 and os_vsn_min >= 2):
            if os_vsn_min == 2:
                # two sequential caches exist on Windows 8+; on Windows 8 x64, the 
                # first cache contains the shim cache. On Windows 8 x86 and 
                # Windows 8.1 x86/x64, the second cache contains the shim cache
                shim_cache_list = self.find_shim_win_8(addr_space, self.NT_KRNL_MODS)
                if memory_model == '64bit':
                    shim_cache_head = shim_cache_list[0]
                else:
                    shim_cache_head = shim_cache_list[1]

            elif os_vsn_min == 3:
                # On Windows 8.1, the second cache is the relevent shim cache
                _, shim_cache_head = self.find_shim_win_8(addr_space, ["ahcache.sys"])

        # if shim cache was found, iterate through the results
        if shim_cache_head:
            debug.info("Shimcache found at 0x{0:08x}".format(shim_cache_head.obj_offset))

            num_entries = 0
            for shim_entry in shim_cache_head.ListEntry.list_of_type("SHIM_CACHE_ENTRY", "ListEntry"):
                num_entries += 1

                if shim_entry.ListEntry.Flink.Blink != shim_entry.ListEntry.Flink.Blink.dereference().obj_offset:
                    debug.warning("Invalid list entry pointer in shimcache entry {0} at 0x{1:08x} (0x{2:08x}); subsequent entries are likely invalid".format(num_entries, shim_entry.ListEntry, shim_entry.obj_vm.vtop(shim_entry.obj_offset)))
                    debug.warning(shim_entry)

                # last item in the shim cache is empty
                if shim_entry.ListEntry.Flink == shim_cache_head:
                    debug.debug("End of shim cache list")
                    break

                yield (shim_entry.get_file_path(), 
                       shim_entry.get_file_size(), 
                       shim_entry.get_last_modified(), 
                       None,                            #last update only present on XP
                       shim_entry.get_exec_flag(),
                       shim_entry.obj_offset, 
                       shim_entry.obj_vm.vtop(shim_entry.obj_offset))
            debug.info("Shimcache parsed with {0:d} entries".format(num_entries))
        else:
            debug.info("Shimcache not found")

        return

    ###########################################################################
    # 
    ###########################################################################
    def render_csv(self, outfd, data):
        """Renders the ShimCache entries to a CSV file"""
    
        print_header = True
        time_fmt = '%Y-%m-%d %H:%M:%S'

        # include a column that represents the sequence of entries in the LRU list.
        # this gives analyst the ability to sort the list by any column and then 
        # revert back to the original list sequence
        seq = 0

        for file_path, file_size, last_modified, last_update, exec_flag, offset_virtual, offset_physical in data:
            seq += 1

            # clean-up paths; intended as a convenience for analysts
            if self._config.CLEAN_FILE_PATHS:
                file_path = file_path.replace("SYSVOL", "C:").replace("\\??\\","")
            
            #explicit format conversion is required here due to a bug in 
            #WinTimeStamp.__format__ that prevents providing a custom format 
            #specification to WinTimeStamp.format()
            last_modified_str = last_modified.as_datetime().strftime(time_fmt) or ''

            file_size = file_size or ''

            #only set execution flag if a value exists
            exec_flag_str = ''
            if exec_flag is not None:
                exec_flag_str = 'True' if exec_flag == 1 else 'False'

            #last update is only set on Windows XP
            last_update_str = ''
            if last_update is not None:
                last_update_str = last_update.as_datetime().strftime(time_fmt) or ''

            if print_header:
                outfd.write("Order,Last Modified,Last Update,Exec Flag,File Size,File Path\n")
                print_header = False

            outfd.write("{0},{1},{2},{3},{4},{5}\n".format(seq, last_modified_str, last_update_str, exec_flag_str, file_size, file_path))

    ###########################################################################
    # 
    ###########################################################################
    def render_text(self, outfd, data):
        """Renders the ShimCache entries as text"""

        print_header = True
        time_fmt = '%Y-%m-%d %H:%M:%S'

        # include a column that represents the sequence of entries in the LRU list.
        # this gives analyst the ability to sort the list by any column and then 
        # revert back to the original list sequence
        seq = 0

        tbl_hdr  = [("Order", "5"), ("Last Modified", "21"), ("Last Update", "21"), ("Exec", "5"), ("File Size", "10"), ("File Path", ""),]
        row_fmt  = "{0:5} {1:21} {2:21} {3:5} {4:10} {5}\n"

        tbl_hdr_offset = [("Order", "5"), ("Offset (v)", "18"), ("Offset (p)", "10"), ("File Path", ""),]
        row_fmt_offset = "{0:5} 0x{1:010x} 0x{2:08x} {3}\n"
        
        for file_path, file_size, last_modified, last_update, exec_flag, offset_virtual, offset_physical in data:
            seq += 1

            # clean-up paths; intended as a convenience for analysts
            if self._config.CLEAN_FILE_PATHS:
                file_path = file_path.replace("SYSVOL", "C:").replace("\\??\\","")

            if self._config.PRINT_OFFSETS:
                if print_header:
                    self.table_header(outfd, tbl_hdr_offset)
                    print_header = False
                outfd.write(row_fmt_offset.format(seq, offset_virtual, offset_physical, file_path))
                continue

            #explicit format conversion is required here due to a bug in 
            #WinTimeStamp.__format__ that prevents specifying custom time formats 
            last_modified_str = last_modified.as_datetime().strftime(time_fmt) or ''

            #last update is only set on Windows XP
            last_update_str = ''
            if last_update is not None:
                last_update_str = last_update.as_datetime().strftime(time_fmt) or ''
            
            file_size = file_size or ''
            
            #only set execution flag if a value exists
            exec_flag_str = ''
            if exec_flag is not None:
                exec_flag_str = 'True' if exec_flag == 1 else 'False'

            if print_header:
                self.table_header(outfd, tbl_hdr)
                print_header = False

            outfd.write(row_fmt.format(seq, last_modified_str, last_update_str, exec_flag_str, file_size, file_path))
