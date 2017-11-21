import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32
import volatility.plugins.dlldump as dlldump
import contrib.plugins.enumfunc as enumfunc
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks
import volatility.plugins.malware.impscan as impscan
import volatility.plugins.handles as handles
import volatility.plugins.netscan as netscan
import volatility.plugins.filescan as filescan
import volatility.debug as debug
import volatility.obj as obj
import pefile
import struct
import pip
import sys
import os

binstallconstruct = False

try:
    import construct
    if construct.__version__ != "2.5.5": binstallconstruct = True
except:
    binstallconstruct = True

if binstallconstruct:
    debug.error("Construct==2.5.5 is not installed, trying to install it")
    pip.main(['install', "construct==2.5.5-reupload"]) 
    debug.error("Construct==2.5.5 has been installed, please relaunch plugin")
    sys.exit(0)

from construct import *

##################################################################################################################

class SymbolizeMod(impscan.ImpScan):

    ##############################################################################################################
    
    def gather_impscan_symbols(self, sections):    
        
        symbols = []
        
        for e in impscan.ImpScan.calculate(self):            
            sect_off = self.rva_to_section_offset(e[0] - self._config.BASE, sections)
            symbols.append((e[0] - self._config.BASE, sect_off[0]+1, sect_off[1], e[3]))
        
        return symbols
        
    ##############################################################################################################
    
    def gather_exports_symbols_values(self):

        symbols_values = []
        addr_space = utils.load_as(self._config)
        
        #############################
        # collect kernel mode exports
        if self._config.PID == None:         
            all_mods = list(modules.lsmod(addr_space))            
            for mod in all_mods:
                if mod.DllBase != self._config.BASE:
                    dllBaseAppended = False
                    for ordinal, func_addr, func_name in mod.exports():
                        if func_addr != None:
                            name = func_name or ordinal or ''
                            if self._config.AGGRESIVE or ("%s" % mod.BaseDllName).lower() in self.kernel_common_mods:
                                if self._config.DLLBASES and not dllBaseAppended: 
                                    symbols_values.append((mod.DllBase, ("dllbase_%s" % mod.BaseDllName).replace(".","_").lower()))
                                    dllBaseAppended = True
                                symbols_values.append((mod.DllBase + func_addr, str(name))) #"%s_%s" % (mod.BaseDllName, name))
        
        ###########################
        # collect user mode exports 
        # for specified process        
        else:
            for prc in tasks.pslist(addr_space):
                if prc.UniqueProcessId == self._config.PID:
                    #addr_space = prc.get_process_address_space()
                    for mod in prc.get_load_modules():
                        if mod.DllBase != self._config.BASE:
                            dllBaseAppended = False
                            for ordinal, func_addr, func_name in mod.exports():                                
                                if func_addr != None:
                                    name = func_name or ordinal or ''
                                    if self._config.AGGRESIVE or ("%s" % mod.BaseDllName).lower() in self.user_common_mods:
                                        if self._config.DLLBASES and not dllBaseAppended: 
                                            symbols_values.append((mod.DllBase, ("dllbase_%s" % mod.BaseDllName).replace(".","_").lower()))
                                            dllBaseAppended = True
                                        symbols_values.append((mod.DllBase + func_addr, str(name))) #"%s_%s" % (mod.BaseDllName, name)))
                    break
        
        return symbols_values
                
    ##############################################################################################################
    
    def cleanStr(self, s):
        sout = ""
        for e in s.lower():
            if (e>='a' and e<='z') or (e>='0' and e<='9'): sout += e
            else: sout += "_"
        return sout
    
    ##############################################################################################################
    
    def gather_handles_values(self):
        
        symbols_values = []
        
        if self._config.PID:
            pid = self._config.PID
            self._config.remove_option("SIZE")
            self._config.remove_option("PID")
            self._config.add_option('PID', short_option = 'p', default = str(pid),
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')            
            
            handls = handles.Handles(self._config)            
            for e in handls.calculate():
                symbols_values.append((e[1].HandleValue, "handle_%s_%s" % (e[2], self.cleanStr(e[3]))))
            
            self._config.remove_option("PID")
            self._config.add_option('PID', short_option = 'p', default = pid,
                          help = 'Process ID (leave off to scan kernel memory)',
                          action = 'store', type = 'int')
        
        return symbols_values
        
    ##############################################################################################################
    
    def rva_to_section_offset(self, rva, sections):
        
        if not sections:
            return None
        for i in range(0, len(sections)):
            if rva >= sections[i].VirtualAddress and rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize:
                return (i, rva - sections[i].VirtualAddress)
        
        return None
        
    ##############################################################################################################
    
    def collect_pe_info(self):
        
        addr_space = utils.load_as(self._config)
        
        if self._config.PID != None:
            for prc in tasks.pslist(addr_space):
                if prc.UniqueProcessId == self._config.PID:
                    addr_space = prc.get_process_address_space()
                    break

        dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = self._config.BASE, vm = addr_space)
        nt_headers = dos_header.get_nt_header()
        sections = list(nt_headers.get_sections())
        sections_data = []
        
        for i in range(0, len(sections)):
            data = addr_space.zread(sections[i].VirtualAddress + self._config.BASE, sections[i].Misc.VirtualSize)
            sections_data.append(data)
        
        return dos_header, nt_headers, sections, sections_data
        
    ##############################################################################################################
    
    def binarySearch(self, alist, item):
        first = 0
        last = len(alist)-1
        found = False
        retval = 0  
        while first<=last and not found:
            midpoint = (first + last)//2
            #some malwares dont call the beginning of the API, they call some instructions after the beginning, i.e.:
            #ADVAPI32!RegDeleteValueW:
            #77daedf1 8bff            mov     edi,edi
            #77daedf3 55              push    ebp
            #77daedf4 8bec            mov     ebp,esp
            #77daedf6 83ec0c          sub     esp,0Ch <- malware executes push ebp, mov ebp, esp in its own code, and then jumps here
            #Por eso no comparamos la direccion dada con la de la lista, sino que aceptamos q sea la de la lista o hasta 10 posiciones mas alante
            #For this reason, we compare the given address with the API address, but we accept:  API_address <= given_address <= API_address + 10
            if alist[midpoint][0] <= item and item < alist[midpoint][0]+10: 
                found = True
                retval = midpoint
            else:
                if item < alist[midpoint][0]:
                    last = midpoint-1
                else:
                    first = midpoint+1    
        return found, retval    
    
    ##############################################################################################################
    
    def unique_symbols(self, symbols):
        
        for i in range(0, len(symbols)):
            renameindex = 1
            for j in range(i+1, len(symbols)):
                if symbols[i][3] == symbols[j][3]:                    
                    newsymbol = (symbols[j][0], symbols[j][1], symbols[j][2], "%s_%d" % (symbols[j][3], renameindex))
                    symbols.pop(j)
                    symbols.insert(j, newsymbol)
                    renameindex += 1
        
        return symbols 
        
    ##############################################################################################################
    
    def symbols_values_to_symbols(self, symbols_values, sections, sections_data):
        
        symbols = []
        
        if not len(symbols_values):return symbols
        symbols_values = sorted(symbols_values, key=lambda symbols_values: symbols_values[0])       
        for isect in range(0, len(sections)):
            if len(sections_data[isect])>=4:
                for j in range(0, len(sections_data[isect])-3):
                    v = struct.unpack("=L", sections_data[isect][j:j+4])[0]
                    isymbol = self.binarySearch(symbols_values, v)
                    if isymbol[0]:
                        symbols.append((sections[isect].VirtualAddress+j, isect+1, j, symbols_values[isymbol[1]][1]))
        
        return symbols

    ##############################################################################################################

    def gather_symbols(self, sections, sections_data):
        
        #symbols_values, it contains values (usually pointers) associated with names. For example, WSAStartup <-> 0x757A3AB2. Once the plugin has collected these 
        #values it will search target PE code and data searching for this values, and it will create a symbol for the address where the value was found. I.e., in
        #the target PE, we find a variable at address 0x443231, containing a pointer to WSAStartup. The plugin will add a symbol for that address with the name 
        #ws2_32_WSAStartup and it will dump this symbol to the dbg file (when we open a dump of the PE or we attach a debugger, we can load this .dbg file to
        #see these symbols). If impscan is used, this option is not necessary, impscan already calculates the offset where these values are stored in the target PE  
        
        #symbols, this array contains the final symbols that will be written to .dbg file        
        
        symbols_impscan = []
        symbols_values_exports = []
        symbols_values_handles = []
        
        ###########################
        # API usage scanning
        if self._config.USE_IMPSCAN:            
            symbols_impscan = self.gather_impscan_symbols(sections)
        else:
            symbols_values_exports = self.gather_exports_symbols_values()

        ###########################
        # Handles scanning
        if self._config.HANDLES:
            symbols_values_handles = self.gather_handles_values()
        
        ###########################
        # Search gathered values in target PE code and data, and generate symbols
        symbols = symbols_impscan + self.symbols_values_to_symbols(symbols_values_exports + symbols_values_handles, sections, sections_data)
        
        return symbols

    ##############################################################################################################

    def __init__(self, config, *args, **kwargs):    
        
        impscan.ImpScan.__init__(self, config, *args, **kwargs)
    
        config.add_option('PID', short_option = 'p', default = None,
                          help = 'Process ID (leave off to scan kernel memory)',
                          action = 'store', type = 'int')
        config.add_option('BASE', short_option = 'b', default = None,
                          help = 'BASE offset in the process address space or kernel space of the module to symbolize',
                          action = 'store', type = 'int')
        config.add_option('USE-IMPSCAN', default = False,
                          help = 'Use impscan for searching APIs being used by the analyzed module',
                          action = 'store_true')
        config.add_option('HANDLES', default = False,
                          help = 'Search handles used by the analyzed module',
                          action = 'store_true')
        config.add_option('DLLBASES', default = False,
                          help = 'Store the baseaddress of modules with exports together with the other symbols values, and search them in the analyzed module to create symbols',
                          action = 'store_true')
        config.add_option('AGGRESIVE', default = False,
                          help = 'Aggresive mode: search for APIs from all modules (instead of APIS from more common modules)',
                          action = 'store_true')
        config.add_option('DESTINATION-FILE', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Destionation .dbg file in which to write symbols')
        self._config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'EPROCESS offset (in hex) in the physical address space',
                          action = 'store', type = 'int')
        self._config.add_option('SIZE', short_option = 's', default = None,
                          help = 'Size of memory to scan',
                          action = 'store', type = 'int')
                          
        self.kernel_common_mods = ["ntoskrnl.exe", "fltmgr.sys", "ndis.sys"]
        self.user_common_mods = ["kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", "wininet.dll", "ntdll.dll", "crypt32.dll", "dnsapi.dll", "psapi.dll", "urlmon.dll", "netapi.dll"]
  
    ##############################################################################################################
    
    def get_target_mod_name(self):
        addr_space = utils.load_as(self._config)
        # kernel mod
        if self._config.PID == None:         
            all_mods = list(modules.lsmod(addr_space))            
            for mod in all_mods:
                if self._config.BASE == mod.DllBase: 
                    return os.path.splitext(str(mod.BaseDllName))[0]
        # user mod
        else:
            for prc in tasks.pslist(addr_space):
                if prc.UniqueProcessId == self._config.PID:
                    print "pid: %d" % prc.UniqueProcessId
                    for mod in prc.get_load_modules():
                        print "mod: %x" % mod.DllBase
                        if self._config.BASE == mod.DllBase: 
                            return os.path.splitext(str(mod.BaseDllName))[0]
                    break     
        return "unknown"
        
    ##############################################################################################################
  
    def calculate(self):     
        
        if self._config.BASE == None:
            debug.error("Please specify a base address (-b)")
            return
            
        if self._config.DESTINATION_FILE == None:
            debug.error("Please specify a destionation file (-D)")
            return
            
        dos_header, nt_headers, sections, sections_data = self.collect_pe_info()
        symbols = self.gather_symbols(sections, sections_data)
        
        if not len(sections):
            debug.error("There were problems recovering target PE")
            return
        
        if not len(symbols):
            debug.error("No symbols were collected")
            return
        
        yield symbols, dos_header, nt_headers, sections, sections_data

    ##############################################################################################################

    def render_text(self, outfd, data):        
        
        for symbols, dos_header, nt_headers, sections, sections_data in data:
        
            symbols = self.unique_symbols(symbols)
            
            for e in symbols:
                print hex(e[0]), hex(e[1]), hex(e[2]), e[3]

            self.create_dbg(self._config.DESTINATION_FILE, symbols, nt_headers, sections, self.get_target_mod_name())
            
    ##############################################################################################################

    def create_dbg(self, destpath, symbols, nt_headers, sections, mod_name):
        
        f = open(destpath, "wb")
        
        IMAGE_SEPARATE_DEBUG_HEADER = Struct("IMAGE_SEPARATE_DEBUG_HEADER",             
            Bytes("Signature", 2), #Const(Bytes("Signature", 2), b"DI"),
            ULInt16("Flags"),
            ULInt16("Machine"),
            ULInt16("Characteristics"),
            ULInt32("TimeDateStamp"),
            ULInt32("CheckSum"),
            ULInt32("ImageBase"),
            ULInt32("SizeOfImage"),
            ULInt32("NumberOfSections"),
            ULInt32("ExportedNamesSize"),
            ULInt32("DebugDirectorySize"),
            ULInt32("SectionAlignment"),
            ULInt32("Reserved1"),
            ULInt32("Reserved2")
        )

        IMAGE_DEBUG_DIRECTORY = Struct("IMAGE_DEBUG_DIRECTORY",
            ULInt32("Characteristics"),
            ULInt32("TimeDateStamp"),
            ULInt16("MajorVersion"),
            ULInt16("MinorVersion"),
            ULInt32("DebugDirectoryType"),
            ULInt32("SizeOfData"),
            ULInt32("AddressOfRawData"),
            ULInt32("PointerToRawData")
            #Pointer(
            #    lambda ctx: ctx.PointerToRawData, String("Data", lambda ctx: ctx.SizeOfData)
            #)
        )
        
        OMFSignature = Struct("OMFSignature",
            Bytes("Signature", 4),
            ULInt32("OMFSignatureSz")
        )        
        
        OMFDirHeader = Struct("OMFDirHeader",
            ULInt16("cbDirHeader"),
            ULInt16("cbDirEntry"),
            ULInt32("cDir"),
            ULInt32("lfoNextDir"),
            ULInt32("flags")
        )

        OMFDirEntry = Struct("OMFDirEntry",
            ULInt16("SubSection"),
            ULInt16("iMod"),
            ULInt32("lfo"),
            ULInt32("cb")
        )
        
        OMFSegDesc = Struct("OMFSegDesc",
            ULInt16("Seg"),
            ULInt16("pad"),
            ULInt32("Off"),
            ULInt32("cbSeg")
        )
        
        OMFModule = Struct("OMFModule",
            ULInt16("ovlNumber"),
            ULInt16("iLib"),
            ULInt16("cSeg"),
            ULInt16("Style")       # debugging style "CV"
            #OMFSegDesc []
            #char Name[]
            )
        
        OMFSymHash = Struct("OMFSymHash",
            ULInt16("symhash"),
            ULInt16("addrhash"),
            ULInt32("cbSymbol"),
            ULInt32("cbHSym"),
            ULInt32("cbHAddr")
            )
        
        OMFSegMapDesc = Struct("OMFSegMapDesc",
            ULInt16("flags"),
            ULInt16("ovl"),
            ULInt16("group"),
            ULInt16("frame"),
            ULInt16("iSegName"),
            ULInt16("iClassName"),
            ULInt32("offset"),
            ULInt32("cbSeg")
            )

        OMFSegMap = Struct("OMFSegMap",
            ULInt16("cSeg"),
            ULInt16("cSegLog")
            #OMFSegMapDesc   rgDesc[0];
            )
            
        IMAGE_SECTION_HEADER = Struct("IMAGE_SECTION_HEADER",
            Bytes("Name", 8),
            ULInt32("Misc_VirtualSize"),
            ULInt32("VirtualAddress"),
            ULInt32("SizeOfRawData"),
            ULInt32("PointerToRawData"),
            ULInt32("PointerToRelocations"),
            ULInt32("PointerToLinenumbers"),
            ULInt16("NumberOfRelocations"),
            ULInt16("NumberOfLinenumbers"),
            ULInt32("Characteristics"))
        
        PUBSYM32 = Struct("PUBSYM32",
            ULInt16("reclen"),
            ULInt16("rectyp"),  #S_PUB32 = 0x0203
            ULInt32("off"),
            ULInt16("seg"),
            ULInt16("typind"))
            #name #Length-prefixed name
        
        sstModule      = 0x120
        sstTypes       = 0x121
        sstPublic      = 0x122
        sstPublicSym   = 0x123
        sstSymbols     = 0x124
        sstAlignSym    = 0x125
        sstSrcLnSeg    = 0x126
        sstSrcModule   = 0x127
        sstLibraries   = 0x128
        sstGlobalSym   = 0x129
        sstGlobalPub   = 0x12a
        sstGlobalTypes = 0x12b
        sstMPC         = 0x12c
        sstSegMap      = 0x12d
        sstSegName     = 0x12e
        sstPreComp     = 0x12f
        sstFileIndex   = 0x133
        sstStaticSym   = 0x134
        
        szAllSymbols = 0
        for e in symbols: szAllSymbols += (PUBSYM32.sizeof() + 1 + len(e[3]))
        szModName = ((len(mod_name)+1)+3) & (~3)
        cvoSstModule = OMFSignature.sizeof() + OMFDirHeader.sizeof() + 3*OMFDirEntry.sizeof()
        szSstModule = OMFModule.sizeof() + len(sections)*OMFSegDesc.sizeof() + szModName
        cvoGlobalPub = cvoSstModule + szSstModule
        gpoSym = OMFSymHash.sizeof() + szAllSymbols 
        cvoSegMap = cvoGlobalPub + gpoSym
        szSegMap = OMFSegMap.sizeof() + len(sections)*OMFSegMapDesc.sizeof()
        szCv = cvoSegMap + szSegMap
        oCv = IMAGE_SEPARATE_DEBUG_HEADER.sizeof() + len(sections)*IMAGE_SECTION_HEADER.sizeof() + 1*IMAGE_DEBUG_DIRECTORY.sizeof()
        
        #write IMAGE_SEPARATE_DEBUG_HEADER
        f.write(IMAGE_SEPARATE_DEBUG_HEADER.build(dict(Signature = b"DI",
                                               Flags = 0, 
                                               Machine = nt_headers.FileHeader.Machine, 
                                               Characteristics = nt_headers.FileHeader.Characteristics, 
                                               TimeDateStamp = nt_headers.FileHeader.TimeDateStamp, 
                                               CheckSum = nt_headers.OptionalHeader.CheckSum,
                                               ImageBase = nt_headers.OptionalHeader.ImageBase, 
                                               SizeOfImage = nt_headers.OptionalHeader.SizeOfImage,
                                               NumberOfSections = len(sections), 
                                               ExportedNamesSize = 0,
                                               DebugDirectorySize = 1*IMAGE_DEBUG_DIRECTORY.sizeof(),
                                               SectionAlignment = nt_headers.OptionalHeader.SectionAlignment,
                                               Reserved1 = 0,
                                               Reserved2 = 0
                                               )))
        #write sections
        for e in sections:
            f.write(IMAGE_SECTION_HEADER.build(dict(Name = e.Name + "\0"*(8-len(e.Name)),
                                            Misc_VirtualSize = e.Misc.VirtualSize,
                                            VirtualAddress = e.VirtualAddress,
                                            SizeOfRawData = e.SizeOfRawData,
                                            PointerToRawData = e.PointerToRawData,
                                            PointerToRelocations = e.PointerToRelocations,
                                            PointerToLinenumbers = e.PointerToLinenumbers,
                                            NumberOfRelocations = e.NumberOfRelocations,
                                            NumberOfLinenumbers = e.NumberOfLinenumbers,
                                            Characteristics = e.Characteristics)))
            
        #write IMAGE_DEBUG_DIRECTORY
        f.write(IMAGE_DEBUG_DIRECTORY.build(dict(Characteristics = 0, 
                                         TimeDateStamp = nt_headers.FileHeader.TimeDateStamp, 
                                         MajorVersion = 0,
                                         MinorVersion = 0,
                                         DebugDirectoryType = 2, #IMAGE_DEBUG_TYPE_CODEVIEW
                                         SizeOfData = szCv,
                                         AddressOfRawData = 0,
                                         PointerToRawData = oCv)))
        
        #write OMFSignature
        f.write(OMFSignature.build(dict(Signature = b"NB09", 
                                        OMFSignatureSz = 8)))
        
        #write misc dirheader
        f.write(OMFDirHeader.build(dict(cbDirHeader = OMFDirHeader.sizeof(),
                                cbDirEntry = OMFDirEntry.sizeof(),
                                cDir = 3,
                                lfoNextDir = 0,
                                flags = 0)))
        
        #write misc direntry[0]: sstModule
        f.write(OMFDirEntry.build(dict(SubSection = sstModule,
                                iMod = 1,
                                lfo = cvoSstModule,
                                cb = szSstModule)))
                
        #write misc direntry[1]: sstGlobalPub
        f.write(OMFDirEntry.build(dict(SubSection = sstGlobalPub,
                                iMod = 0xFFFF,                                
                                lfo = cvoGlobalPub,
                                cb = gpoSym)))
        
        #write misc direntry[2]: sstSegMap
        f.write(OMFDirEntry.build(dict(SubSection = sstSegMap,
                                iMod = 0xFFFF,
                                lfo = cvoSegMap,
                                cb = szSegMap)))


        #write SstModule
        f.write(OMFModule.build(dict(ovlNumber = 0,
                                iLib = 0,
                                cSeg = len(sections),
                                Style = 0x5643))) #CV
          
        #write SstModule - numsecs*OMFSegDesc        
        for i in range (0, len(sections)):
            f.write(OMFSegDesc.build(dict(Seg = i+1,            
                                pad = 0,
                                Off = 0,
                                cbSeg = sections[i].Misc.VirtualSize)))
        
        #write SstModule - modname len
        f.write(struct.pack("B", len(mod_name)))
        
        #add padding bytes to round it up 4        
        ModNamePadding = mod_name        
        while (len(ModNamePadding)+1)%4: ModNamePadding += "\0"
        
        #write SstModule - modname
        f.write(ModNamePadding)
        
        #write header pre-symbols (GlobalPub?)
        f.write("\0\0\0\0")
        f.write(struct.pack("=L", szAllSymbols)) # <- len total sum PUBSYM32
        f.write("\0\0\0\0")
        f.write("\0\0\0\0")

        #write GlobalPub
        #f.write(OMFSymHash.build(dict(cbSymbol = gpoSym - OMFSymHash.sizeof(),
        #                        symhash = 0,
        #                        addrhash = 0,
        #                        cbHSym = 0, #size all symbols
        #                        cbHAddr = 0)))        
        
        #write symbols
        for e in symbols:        
            f.write(PUBSYM32.build(dict(reclen = PUBSYM32.sizeof() + len(e[3]) + 1 - 2,
                                rectyp = 0x0203,
                                off = e[2],
                                seg = e[1],
                                typind = 0)))
            f.write(struct.pack("B", len(e[3])))
            f.write(e[3])

        #write Global - symbols
        #f.seek(oCv + cvoSegMap, os.SEEK_SET)
        
        #write SegMap
        f.write(OMFSegMap.build(dict(cSeg = len(sections), 
                            cSegLog = len(sections))))
        
        #write SegMap - nsec*OMFSegMapDesc
        for i in range(1, len(sections)+1):
            f.write(OMFSegMapDesc.build(dict(flags = 0,
                            ovl = 0,
                            group = 0,
                            frame = i,
                            iSegName = 0xFFFF,
                            iClassName = 0xFFFF,
                            offset = 0,
                            cbSeg = sections[i-1].Misc.VirtualSize)))

##################################################################################################################    





##################################################################################################################    
##################################################################################################################    
##################################################################################################################    
##################################################################################################################
