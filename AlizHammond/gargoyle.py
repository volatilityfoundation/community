import struct
import volatility
import inspect
import importlib
import volatility.plugins.common as common
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
from volatility import utils, obj, win32
from volatility.plugins.malware import malfind
from volatility.plugins.malware.timers import Timers

from unicorn import *
from unicorn.x86_const import *

class timerResult():
    def __init__(self, process, thread, timerRoutine):
        self.thread = thread
        self.process = process
        self.routine = timerRoutine
        self.didROP = "Unknown"
        self.didAdjustPerms = "Unknown"
        self.didJumpToAdjusted = "Unknown"
        self.adjustedAddresses = []
        self.probablePayload = 0
        self.prolog = "Unknown"

        instrStream = process.get_process_address_space().read(timerRoutine, 16)
        if not instrStream:
            print "Process %s '%s': Can't read instruction stream at %s; perhaps it is paged out" % (hex(int(process.obj_offset)), process.ImageFileName, hex(timerRoutine))
        else:
            self.prolog = disAssembleInstr(instrStream, timerRoutine, 5)

def disAssembleInstr(instrStream, instrLocation, opcodeCount):
    toRet = []
    for _, i, _ in malfind.Disassemble(instrStream, instrLocation, True):
        toRet.append(i)
        opcodeCount = opcodeCount - 1
        if opcodeCount == 0:
            break
    return "; ".join(toRet)

# Unicorn doesn't support virtual memory properly (see unicorn bug #947) so there's not really much point setting up
# GDT/etc.

def printUnicornContext(pas, nextIns, unicornEng):
    print "Unicorn context: "
    instrStream = pas.read(nextIns, 20)
    for _, i, _ in malfind.Disassemble(instrStream, nextIns):
        print "\t %s" % i
    print "ESP = %s" % hex(unicornEng.reg_read(UC_X86_REG_ESP))
    print "EAX = %s" % hex(unicornEng.reg_read(UC_X86_REG_EAX))
    print "EBX = %s" % hex(unicornEng.reg_read(UC_X86_REG_EBX))
    print "ECX = %s" % hex(unicornEng.reg_read(UC_X86_REG_ECX))
    print "EDX = %s" % hex(unicornEng.reg_read(UC_X86_REG_EDX))
    print "ESI = %s" % hex(unicornEng.reg_read(UC_X86_REG_ESI))
    print "EDI = %s" % hex(unicornEng.reg_read(UC_X86_REG_EDI))
    print "EFLAGS = %s" % hex(unicornEng.reg_read(UC_X86_REG_EFLAGS))
    print ""

def getWoW64Profile(process):
    """
    Given a 64-bit Windows process, find the 32-bit profile which most closely matches the 64-bit proceesses profile.
    Hopefully, this will be close enough enable us to decode 32-bit objects running under WoW.
    """
    pas = process.get_process_address_space()

    wow64ProfileFull = str(pas.profile.__class__).strip('><\'')[len('class: '):]
    wow64ProfileNameSpace = '.'.join(wow64ProfileFull.split('.')[:-1])
    wow64ProfileName = str(wow64ProfileFull.split('.')[-1:][0].replace('x64', 'x86'))

    module = importlib.import_module(wow64ProfileNameSpace)
    class_ = getattr(module, wow64ProfileName)
    return class_()

def isKernelSpace(process, DllBase):
    if process.get_process_address_space().profile.metadata.get("memory_model") == "32bit":
        # TODO: support 3GB address mode, if it's worth it
        return DllBase < 0x80000000
    else:
        return DllBase < 0x8000000000000000

    # It seems that certain SPs of certain OSs (vista and certain versions of 2003/XP64) use a non-standard
    # APC format when running in WoW64 mode. We will apply this type only if we detect a version of windows
    # which uses it.
WoW64UnusualAPC = {
      '_KAPC_WOW64' : [ 0x58, {
    'Type' : [ 0x0, ['unsigned char']],
    'SpareByte0' : [ 0x1, ['unsigned char']],
    'Size' : [ 0x2, ['unsigned char']],
    'SpareByte1' : [ 0x3, ['unsigned char']],
    'SpareLong0' : [ 0x4, ['unsigned long']],
    'Thread' : [ 0x8, ['pointer64', ['_KTHREAD']]],
    'ApcListEntry' : [ 0x10, ['_LIST_ENTRY']],
    'KernelRoutine' : [ 0x20, ['pointer64', ['void']]],
    'RundownRoutine' : [ 0x28, ['pointer64', ['void']]],
    'unknown' : [ 0x30, ['pointer64', ['void']]],
    'NormalContext' : [ 0x38, ['pointer32', ['void']]],
    'NormalRoutine' : [ 0x3C, ['pointer32', ['void']]],
    'SystemArgument1' : [ 0x40, ['pointer64', ['void']]],
    'SystemArgument2' : [ 0x48, ['pointer64', ['void']]],
    'ApcStateIndex' : [ 0x50, ['unsigned char']],
    'ApcMode' : [ 0x51, ['unsigned char']],
    'Inserted' : [ 0x52, ['unsigned char']],
}]}

class APCVTypes(obj.ProfileModification):
    before = ['WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        if profile.metadata.get("memory_model", "32bit") == "64bit":
            profile.vtypes.update(WoW64UnusualAPC)

class gargoyle(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option("VERBOSE", default=0, action='count',
                          short_option='v', help='Verbose information')
        config.add_option("ALLTIMERS", default = False, action = 'store_true',
                          help = "Do not filter timers by valid EPROCESS")

    def dbgMsg(self, *args):
        if self._config.VERBOSE > 0:
            print " ".join(map(str, args))

    # This is called when Unicorn needs to access some memory that isn't mapped yet.
    # We simply map the memory, copy in its contents from the debuggee, and return.
    # Our main loop will retry. We signal errors by setting self.emulationFaulted.
    def badmemWrapped(self, uc, access, address, size, value, user_data):
        self.dbgMsg("Access to unmapped memory %s" % hex(address))

        if self.pas == None:
            self.dbgMsg("Unable to handle memory mapping with no active process")
            raise MemoryError
        # Unicorn will only successfully map page-aligned addresses, so map the whole page.
        pageSize = 0x1000
        pageBase = address & (~(pageSize-1))
        uc.mem_map(pageBase, pageSize)
        # Read from the debuggee..
        pageCts = self.pas.read(pageBase, pageSize)
        if pageCts == None:
            self.dbgMsg ("Unable to read %s bytes at %s" % (hex(pageSize), hex(pageBase)))
            raise MemoryError
        # And write to Unicorn.
        uc.mem_write(pageBase, pageCts)
        self.dbgMsg( "Mapped %s bytes at base %s" % (hex(pageSize), hex(pageBase)))

        return True

    def badmem(self, uc, access, address, size, value, user_data):
        try:
            return self.badmemWrapped(uc, access, address, size, value, user_data)
        except Exception as e:
            self.emulationFaulted = e
            raise

    def unified_output(self, data):
        return TreeGrid([("Process", str),
                       ("Handler", Address),
                       ("Prolog", str),
                       ("Adjusted page permissions", str),
                       ("Branched to code after altering page permission", str),
                       ("Probable payload", Address)],
                        self.generator(data))

    def generator(self, data):
        for timer in data:
            yield(0, [ str(timer.process.ImageFileName),
                       Address(timer.routine),
                       str(timer.prolog),
                       str(timer.didAdjustPerms),
                       str(timer.didJumpToAdjusted),
                       Address(timer.probablePayload)])

    def calculate(self):
        self.exportCache = {}
        addr_space = utils.load_as(self._config)

        if self._config.ALLTIMERS:
            validProcesses = None
        else:
            validProcesses = []
            for p in win32.tasks.pslist(addr_space):
                validProcesses.append(int(p.obj_offset))

        # Firstly, we must iterate over the timers found by the timers plugin. We can then find the owning process, the
        # associated APC, and the thread. We need the process because we will need to know what process context the APC's
        # NormalRoutine (if any) will run in, in order to do our emulation.
        for timeraddress, _ in Timers(self._config).calculate():
            timer = obj.Object("_ETIMER", offset=timeraddress.obj_offset, vm=timeraddress.obj_vm)
            self.dbgMsg("Timer at %s dpc %s" % (hex(int(timer.obj_offset)), hex(int(timeraddress.Dpc.DeferredRoutine))))
            etimer = timer.cast("_ETIMER")
            # Check for the weird APC format
            version = (addr_space.profile.metadata.get('major', 0),
                       addr_space.profile.metadata.get('minor', 0))
            if addr_space.profile.metadata.get("memory_model") == "64bit" and ((version == (5, 2) ) or (version == (6, 0))):
                apc = obj.Object("_KAPC_WOW64", offset=etimer.TimerApc.obj_offset, vm=etimer.TimerApc.obj_vm)
            else:
                apc = obj.Object("_KAPC"      , offset=etimer.TimerApc.obj_offset, vm=etimer.TimerApc.obj_vm)
            routine = int(apc.NormalRoutine)
            thread = obj.Object("_ETHREAD", offset=int(apc.Thread), vm=addr_space)
            if (thread == None) | (routine == 0):
                # This APC has no user-mode payload.
                continue
            process = thread.owning_process()
            if process == None:
                # This usually happens when a timer is not pointing to a valid thread. I'm not sure why this happens -
                # I guess there's some flag in the timer which states that it isn't valid, or the timer/timer list is
                # # being manipulated when we dump.
                self.dbgMsg('Timer %s : warning: Thread ID %s has no owning process, skipping' % (hex(int(timeraddress.obj_offset)), hex(int(thread.Cid.UniqueThread))))
                continue

            # If this is a WoW64 APC - ie, an APC queued by a 32-bit thread on a 64-bit windows install - then we must
            # 'decode' the NormalRoutine by shifting and negating it.
            # We detect these WoW64-style APCs by comparing the top half of the 64bit address, except bit zero, to  0xffffffff. I'm not
            # sure if this is reliable, but it seems to work.
            if (((routine >> 32) | 0x01) == 0xffffffff):
                routine32bit = (-(routine >> 2)) & 0xffffffff
                self.dbgMsg("WoW64-style APC routine decoded %s to %s" % (hex(routine), hex(routine32bit)))
                routine = routine32bit

            if (validProcesses != None) and (not process in validProcesses):
                continue

            for result in self.examine(addr_space, process, thread, routine, apc, timer):
                yield result

    def getWoW64Modules(self, process):
        pas = process.get_process_address_space()

        # Get a pointer to the 32-bit PEB, which is stored as part of the _EWOW64PROCESS. This is of type nt!_PEB32.
        peb32 = process.Peb32
        ldr = int(peb32.Ldr)

        # Since this PEB is 32bit, we must use definitions from the 32bit version of windows which corresponds to this
        # build.
        profile32 = getWoW64Profile(process)
        pas32 = pas
        pas32.profile = profile32
        pebLdrData = obj.Object("_PEB_LDR_DATA", offset=ldr, vm=pas32)
        modules = pebLdrData.InMemoryOrderModuleList.cast("_LIST_ENTRY").list_of_type("_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks")
        return modules

    def findExport(self, process, addr_space, moduleName, exportName):
         # mind the case! 'WoW' vs 'Wow'.
         if hasattr(process.m, 'Wow64Process'):
             wow64Process = process.Wow64Process
         elif hasattr(process, 'WoW64Process'):
             wow64Process = process.WoW64Process
         else:
             wow64Process = None

         isWoW64 = False
         if wow64Process != None and wow64Process.v() != 0:
             isWoW64 = True
         if isWoW64:
            # WoW64 processes are treated specially, since we must get 32bit modules via the 32bit PEB.
            pas = process.get_process_address_space()
            if pas == None:
                # Probably not a real EPROCESS.
                return None
            modList = self.getWoW64Modules(process)
         else:
            # Not a WoW64 process, so just get the modules normally.
            modList = process.get_mem_modules()

         exp = self.findExportInModuleList(modList, moduleName, exportName, process, isWoW64)
         if exp == None:
             print "Unable to find export %s!%s in process %s" % (moduleName, exportName, process.ImageFileName)
         return exp

    def findExportInModuleList(self, moduleList, moduleName, exportName, process, isWoW64):
        moduleNameLowercase = moduleName.lower()
        exportNameLowercase = exportName.lower()

        for m in moduleList:
            dllName = str(m.BaseDllName).lower()
            if dllName == moduleNameLowercase:
                # Cache per-process (since a module may appear in a different process at a different base). For kernel modules
                # there's no need to be per-process, so don't bother.
                if isKernelSpace(process, m.DllBase):
                    cacheKey = "%s!%s (kernel)" % (moduleNameLowercase, exportNameLowercase)
                else:
                    cacheKey = "%s!%s %s (wow64 %s)" % (moduleNameLowercase, exportNameLowercase, hex(m.DllBase), isWoW64)
                if cacheKey in self.exportCache.keys():
                    return self.exportCache[cacheKey]

                for _, expAddress, expName in m.exports():
                    if str(expName).lower() == exportNameLowercase:
                        toReturn = m.DllBase + expAddress
                        self.dbgMsg("Found %s ! %s at %s (%s)" % (m.BaseDllName, expName, hex(toReturn), hex(m.DllBase)))
                        self.exportCache[cacheKey] = toReturn
                        return toReturn

        return None

    def examine(self, addr_space, process, thread, routine, apc, timer):
        # We will now emulate through the instruction stream, starting at the APC handler, and see if anything fishy
        # goes on. Specifically, we will see if the APC calls VirtualProtect. If it does, we will see if it also
        # tries to jump to the newly-VirtualProtect'ed memory - a sure sign of Gargoyle-ness.
        VirtualProtect   = self.findExport(process, addr_space, "KERNEL32.DLL", "VirtualProtect")
        VirtualProtectEx = self.findExport(process, addr_space, "KERNEL32.DLL", "VirtualProtectEx")
        # We'll need to set the process address space so that our badmem callback can use it later on.
        self.pas = process.get_process_address_space()
        self.emulationFaulted = None

        result = timerResult(process, thread, routine)
        self.dbgMsg("Timer %s APC %s routine %s in process %s ('%s') thread %s" % (hex(int(timer.obj_offset)), hex(int(apc.obj_offset)), hex(routine), hex(int(process.obj_offset)), process.ImageFileName, hex(thread.StartAddress)))

        unicornEng = Uc(UC_ARCH_X86, UC_MODE_32)
        # Populate the context from which to start emulating.
        # We use an arbitrary ESP, with a magic value to signify that the APC handler has returned.
        initialStackBase = 0x00000000f0000000
        unicornEng.mem_map(initialStackBase, 2 * 1024 * 1024)
        unicornEng.mem_write(initialStackBase + 0x100 + 0, "\xbe\xba\xde\xc0")
        # We push the argument which the APC handler is given
        unicornEng.mem_write(initialStackBase + 0x100 + 4, apc.NormalContext.obj_vm.read(apc.NormalContext.obj_offset, 4))
        unicornEng.reg_write(UC_X86_REG_ESP, initialStackBase + 0x100)

        # Set up our handlers, which will map memory on-demand from the debuggee
        unicornEng.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.badmem)
        unicornEng.hook_add(UC_HOOK_MEM_WRITE_INVALID, self.badmem)
        unicornEng.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.badmem)

        # There's not really much point mapping the GDT, since Unicorn doesn't properly support paging.
        # See Unicorn's bug #947, "(x86) Emulated CPU is not translating virtual memory addresses".

        # Now, lets emulate some instructions! We won't get many, because Unicorn can't emulate a lot of things (like
        # segment-prefixed instructions, as used by wow64) but we'll get enough to detect most ROP chains.
        instrEmulated = 0
        nextIns = routine
        memoryRange = None
        while instrEmulated < 10000:

            if self._config.VERBOSE > 0:
                print "Before instruction %d at %s:" % (instrEmulated, hex(nextIns))
                print "CS:IP = %s:%s SS:SP = %s:%s" % (
                    hex(unicornEng.reg_read(UC_X86_REG_CS)), hex(unicornEng.reg_read(UC_X86_REG_EIP)),
                    hex(unicornEng.reg_read(UC_X86_REG_SS)), hex(unicornEng.reg_read(UC_X86_REG_ESP)))

                instrStream = self.pas.read(nextIns, 15)
                for _, i, _ in malfind.Disassemble(instrStream, nextIns):
                    print "\t%s\t%s" % (hex(nextIns), i)
                    break

            # Attempt to emulate a single instruction
            try:
                unicornEng.emu_start(nextIns, nextIns + 0x10, count = 1)
            except unicorn.UcError as e1:
                break
            if self.emulationFaulted != None:
                break

            # Great, we emulated an instruction. Move on to the next instruction.
            nextIns = unicornEng.reg_read(UC_X86_REG_EIP)
            instrEmulated = instrEmulated + 1

            # If we're now at our magic address, then our APC has completed executing entirely. That's all, folks.
            if nextIns == 0xc0debabe:
                break

            # Now we can check for some suspicious circumstance.
            esp = unicornEng.reg_read(UC_X86_REG_ESP)
            if esp == int(apc.NormalContext):
                result.didROP = "True"
                self.dbgMsg("APC has performed stack pivot; new stack is its context pointer")
                if VirtualProtect == None:
                    # If we didn't find VirtualProtect, we can't go any further. I guess a stack pivot is a pretty big
                    # red flag anyway.
                    break
            if VirtualProtectEx != None:
                if nextIns == VirtualProtectEx:
                    result.didAdjustPerms = "True"

                    # Read the arguments to VirtualProtect, and the return address, from the stack
                    returnAddress = struct.unpack("I", unicornEng.mem_read(esp - 0, 4))[0]
                    memoryRange = struct.unpack("I", unicornEng.mem_read(esp + 8, 4))[0]

                    result.adjustedAddresses.append(memoryRange)
                    self.dbgMsg("VirtualProtectEx: Timer routine is adjusting memory permissions of range %s" % hex(memoryRange))
                    # Set the return address to whatever VirtualProtect would've returned to
                    nextIns = returnAddress
                    unicornEng.reg_write(UC_X86_REG_EIP, returnAddress)
                    # Pop five args plus the return address off the (32bit) stack
                    unicornEng.reg_write(UC_X86_REG_ESP, esp + (6*4))
                if VirtualProtect != None:
                    if nextIns == VirtualProtect:
                        result.didAdjustPerms = "True"

                        # Read the arguments to VirtualProtect, and the return address, from the stack
                        returnAddress = struct.unpack("I", unicornEng.mem_read(esp - 0, 4))[0]
                        memoryRange = struct.unpack("I", unicornEng.mem_read(esp + 4, 4))[0]

                        result.adjustedAddresses.append(memoryRange)
                        self.dbgMsg("VirtualProtect: Timer routine is adjusting memory permissions of range %s" % hex(memoryRange))
                        # Set the return address to whatever VirtualProtect would've returned to
                        nextIns = returnAddress
                        unicornEng.reg_write(UC_X86_REG_EIP, returnAddress)
                        # Pop four args plus the return address off the (32bit) stack
                        unicornEng.reg_write(UC_X86_REG_ESP, esp + (5 * 4))
                if nextIns in result.adjustedAddresses:
                    result.didJumpToAdjusted = "True"
                    result.probablePayload = nextIns
                    self.dbgMsg( "Timer routine is jumping to newly-executable code at %s!" % hex(memoryRange))
                    break
        yield result
