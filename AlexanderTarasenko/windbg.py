import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.obj as obj
import pykd 

class PykdAddressSpace(addrspace.BaseAddressSpace):

    '''
    Windbg address space
    '''
    order = 10

    def __init__(self, base, config, *args, **kwargs):

         self.as_assert(base == None)
         self.as_assert(config.LOCATION=='windbg')
         self.as_assert(pykd.isKernelDebugging())
         self.dtb = pykd.reg('cr3')
         self.nt = pykd.module('nt')
         config.KDBG = self.nt.KdCopyDataBlock
         self.pageSize = pykd.pageSize()
         self.lowPage = pykd.ptrMWord(self.nt.MmLowestPhysicalPage)
         self.highPage = pykd.ptrMWord(self.nt.MmHighestPhysicalPage)
         self.spaces = [ ( self.lowPage*self.pageSize, (self.highPage -self.lowPage )*self.pageSize) ]

         super(PykdAddressSpace,self).__init__(base,config)

         self.name = "WinDBG Address Space"

    def is_valid_profile(self, profile):

        systemVer = pykd.getSystemVersion()
        minor = 3 if systemVer.buildNumber == 9600 else systemVer.win32Minor #fix for minor version for windows 8.1

        return profile.metadata.get('os', 'Unknown').lower() == 'windows' and \
            profile.metadata.get('memory_model', '32bit') == ( '64bit' if pykd.is64bitSystem() else '32bit' ) and \
            profile.metadata.get('major', 0) == systemVer.win32Major and \
            profile.metadata.get('minor', 0) == minor


    def read(self, offset, length):
        try:
            return pykd.loadChars(offset,length,phyAddr=True)
        except pykd.MemoryException:
            return None

    def zread(self, offset, length):
        try:
            return pykd.loadChars(offset,length,phyAddr=True)
        except pykd.MemoryException:
            return '\x00'*length

    def get_address_range(self):
        return [ self.lowPage*self.pageSize,(self.highPage + 1)*self.pageSize - 1]

    def get_available_addresses(self):

        for space in self.spaces:
            yield space

    def is_valid_address(self, addr):
        try:
            pykd.loadChars(addr,1,phyAddr=True)
            return True
        except pykd.MemoryException:
             return False

