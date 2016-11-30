import sys, pydoc, struct
import volatility.utils as utils
import volatility.registry as registry
import volatility.obj as obj
import volatility.win32.modules as modules
import volatility.win32.tasks as tasks
import volatility.plugins.ssdt as ssdt
import volatility.plugins.taskmods as taskmods
import volatility.plugins.modscan as modscan
import volatility.plugins.malware.malfind as malfind
import volatility.debug as debug
import volatility.plugins.malware.threads as threads

enumerated_processes = {}
kernel_modules = {}

class CallstackItem():
    """ a class that describes an item retreived from the callstack"""
    def __init__(self, ret_address, frame_address):
        self.ret_address = ret_address
        self.frame_address = frame_address
        self.owning_module_name = None
        self.owning_module_address = None
        self.function = None
        self.comment = ""

class ThreadModule():
    """ a class that describes a loaded module"""
    def __init__(self, ldr_object):
        self.ldr_object = ldr_object
        self.functions = None

class ModuleFunction():
    """ a class that describes an exported function"""
    def __init__(self, name, address):
        self.name = name
        self.address = address

class ThreadCallstack():
    """ a class that describes a threads callstack"""
    def __init__(self, thread):
        self.callstack = []
        self.eip = False
        self.bit32 = True
        self.thread = thread
        self.mal_pattern = []
        
    def add_callstack_item(self, item):
        # adds a CallstackItem to the threads list
        self.callstack.append(item)
        return True
    
    def set_bits(self, s):
        if s == "32":
            self.bits32 = True
        elif s == "64":
            self.bits32 = False

def parse_callstack(thread, bits32, config):
    # extract the threads callstack by walking saved frames
    
    ##     ---------- 0x00001234                                               
    ##  /--|  ebp   |        	 
    ##  |  ----------                                                                                                 
    ##  |  |ret_addr|        	 
    ##  |  ----------                                                 
    ##  |  |  data  |        	 
    ##  |  ----------   	 
    ##  |  |  data  |        	 
    ##  |  ----------                                                    
    ##  \->|  ebp   |-----\     	 
    ##     ----------     |                                                                                             
    ##     |ret_addr|     |    	 
    ##     ----------     |                                              
    ##     |  data  |     |   	 
    ##     ----------     | 
    ##	   |  data  |     |   	 
    ##     ----------     |                                               
    ##     |  ebp   |<----/   	 
    ##     ----------                                                                                                  
    ##     |ret_addr|        	 
    ##     ---------- 0x0000125c

    # for each ebp that is retreived the function saves the
    # data at [ebp+4] which is the return address and continues
    # to the next ebp.

    # this function does not work for 64bit since building frames on the stack by pushing
    # rbp is not a must in the _fastcall 
    
    thread_callstack = ThreadCallstack(thread)
    trapframe = thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")
    current_ebp = 0
    call_address = 0
    ip_added = False
    
    if bits32:
        pointer_size = 4
        unpack_size = "I"
    else:
        pointer_size = 8
        unpack_size = "Q"
    
    if trapframe:
        address_space = thread.owning_process().get_process_address_space()
        if bits32:
            thread_callstack.set_bits("32")
            current_ebp = trapframe.Ebp
            thread_callstack.add_callstack_item(CallstackItem(trapframe.Eip, trapframe.Eip))
            thread_callstack.eip = True
            
            
            while current_ebp:
                if address_space.is_valid_address(current_ebp) and address_space.is_valid_address(current_ebp + pointer_size):
                    call_address = struct.unpack(unpack_size, address_space.zread(current_ebp + pointer_size, pointer_size))[0]
                    current_ebp = struct.unpack(unpack_size, address_space.zread(current_ebp, pointer_size))[0]
                        
                    if len(thread_callstack.callstack) > 1:
                        if current_ebp == thread_callstack.callstack[-1].frame_address:
                            break
                    if call_address:
                        thread_callstack.add_callstack_item(CallstackItem(call_address, current_ebp))
                else:
                    call_address = None
                    current_ebp = None
            thread_callstack.callstack = parse_callstack_items_address(thread, thread_callstack.callstack, config)
        else:
            
            thread_callstack.set_bits("64")
            current_ebp = trapframe.Rbp
            thread_callstack.add_callstack_item(CallstackItem(trapframe.Rip, trapframe.Rip))
            thread_callstack.eip = True

            while current_ebp:
                if address_space.is_valid_address(current_ebp) and address_space.is_valid_address(current_ebp + pointer_size):
                    call_address = struct.unpack(unpack_size, address_space.zread(current_ebp + pointer_size, pointer_size))[0]
                    current_ebp = struct.unpack(unpack_size, address_space.zread(current_ebp, pointer_size))[0]
                        
                    if len(thread_callstack.callstack) > 1:
                        if current_ebp == thread_callstack.callstack[-1].frame_address:
                            break
                    if call_address:
                        thread_callstack.callstack.add_callstack_item(CallstackItem(call_address, current_ebp))
                else:
                    call_address = None
                    current_ebp = None
            thread_callstack.callstack = parse_callstack_items_address(thread, thread_callstack.callstack, config)
        
    return thread_callstack

def parse_callstack_items_address(thread, callstack, config):
    # for each callstack item eg. 0x7f801234 figure out in
    # which module and function the address resides
    
    modules = get_thread_modules(thread, config)

    for item in callstack:
        current_module = None
        current_function = None
        
        for mod in modules:

            if mod.ldr_object.DllBase < item.ret_address:
                if item.ret_address > mod.ldr_object.DllBase and item.ret_address < (mod.ldr_object.DllBase + mod.ldr_object.SizeOfImage):
                    current_module = mod
            else:
                break
        
        if current_module:
            item.owning_module_name = current_module.ldr_object.BaseDllName
            item.owning_module_address = current_module.ldr_object.DllBase
            
            for function in current_module.functions:
                if function.address < item.ret_address:
                    current_function = function
                else:
                    break
        else:
            item.owning_module_name = "Unknown"
            item.owning_module_address = 0

        if current_function:
            item.function = current_function
        else:
            item.function = ModuleFunction("Unknown", item.ret_address)
    return callstack

def get_module_exports(thread, mod):
    # retreive exports from module
    
    functions = []
    if mod:
        for _, f, n in mod.exports():
            if n:
                functions.append(ModuleFunction(str(n), mod.DllBase + f))
            else:
                functions.append(ModuleFunction("Unknown", mod.DllBase + f))
    return functions
       
def get_thread_modules(thread, config):
    # get the loaded modules of the process containing the thread
    # this function also pays respect to already gathered modules
    # for increased performance
    
    global kernel_modules
    global enumerated_processes

    thread_modules = []
    user_modules = []
    
    addr_space = utils.load_as(config)
    system_range = tasks.get_kdbg(addr_space).MmSystemRangeStart.dereference_as("Pointer")

    if len(kernel_modules) == 0:
        for mod in modules.lsmod(addr_space):
            if mod:
                thread_modules.append(ThreadModule(mod))
                thread_modules[-1].functions = get_module_exports(thread, thread_modules[-1].ldr_object)
                thread_modules[-1].functions = sorted(thread_modules[-1].functions, key = lambda item: item.address)                    
        thread_modules = sorted(thread_modules, key = lambda item: item.ldr_object.DllBase)
        kernel_modules = thread_modules
    else:
        pass

    owning_process = thread.owning_process() 
    if not owning_process.is_valid(): 
        owner = None
    else:
        try:
            user_modules = enumerated_processes[owning_process.obj_offset]
        except KeyError:
            for mod in owning_process.get_load_modules():
                if mod:
                    user_modules.append(ThreadModule(mod))
                    user_modules[-1].functions = get_module_exports(thread, user_modules[-1].ldr_object)
                    user_modules[-1].functions = sorted(user_modules[-1].functions, key = lambda item: item.address) 
            user_modules = sorted(user_modules, key = lambda item: item.ldr_object.DllBase)
            enumerated_processes[owning_process.obj_offset] = user_modules
            
    thread_modules = user_modules + kernel_modules
    return thread_modules


class Callstacks(taskmods.DllList):
    """ this is the plugin class for callstacks """
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        self.pidlist = None
        if self._config.PID is not None:
            try:
                self.pidlist = map(int, self._config.PID.split(','))
            except ValueError:
                return
        
        self.bits32 = None

    def calculate(self):
        thread_start_module = None
        thread_start_function = None
        # Checks that subclass AbstractThreadCheck
        checks = registry.get_plugin_classes(threads.AbstractThreadCheck)

        addr_space = utils.load_as(self._config)

        # Are we on x86 or x64. Save this for render_text 
        self.bits32 = addr_space.profile.metadata.\
            get("memory_model", "32bit") == "32bit"

        seen_threads = dict()

        # Gather threads by list traversal of active/linked processes 
        for task in taskmods.DllList(self._config).calculate():
            for thread in task.ThreadListHead.\
                    list_of_type("_ETHREAD", "ThreadListEntry"):
                seen_threads[thread.obj_vm.vtop(thread.obj_offset)] = (False, thread)

        # Now scan for threads and save any that haven't been seen
        for thread in modscan.ThrdScan(self._config).calculate():
            if not seen_threads.has_key(thread.obj_offset):
                seen_threads[thread.obj_offset] = (True, thread)

        # Keep a record of processes whose DLLs we've already enumerated
        process_dll_info = {}
        
        for _offset, (found_by_scanner, thread) in seen_threads.items():
            if self.pidlist:
                if not thread.attached_process().UniqueProcessId in self.pidlist:
                    continue
            thread_callstack = parse_callstack(thread, self.bits32, self._config)
            
            yield thread, addr_space, \
                        thread_start_function, thread_callstack

    def render_text(self, outfd, data):
        for thread, addr_space, \
                     thread_start_function, thread_callstack in data:

            s = "\n------\n\n"

            s += "ETHREAD: {0:#010x} Pid: {1} Tid: {2}\n".format(
                thread.obj_offset,
                thread.Cid.UniqueProcess, thread.Cid.UniqueThread)

            s += "Owning Process: {0}\n".format(
                thread.owning_process().ImageFileName)

            s += "Attached Process: {0}\n".format(
                thread.attached_process().ImageFileName)

            s += "Thread Flags: {0}\n".format(str(thread.CrossThreadFlags))

            


            if len(thread_callstack.callstack) > 0:

                s += "\nCallstack:\n"
                if thread_callstack.eip:
                    s += "\t{0:<8} {3:<8}   {1:<8}   {2}\n".format("No.", "RetAddr", "Function", "Ebp")
                    s += "\t{0:<8} 0x{5:08x} 0x{1:08x} {2}!{3}+0x{4:<8x}\n".format("[eip]", thread_callstack.callstack[0].function.address,
                                                thread_callstack.callstack[0].owning_module_name, thread_callstack.callstack[0].function.name,
                                                thread_callstack.callstack[0].ret_address - thread_callstack.callstack[0].function.address, 0)
                    thread_callstack.callstack.remove(thread_callstack.callstack[0])

                i = 0
                for item in thread_callstack.callstack:
                    s += "\t{0:<8} 0x{5:08x} 0x{1:08x} {2}!{3}+0x{4:<8x}\n".format("[" + str(i) + "]", item.function.address,
                                                                item.owning_module_name, item.function.name,
                                                                item.ret_address - item.function.address, item.frame_address)
                    i += 1
            else:
                s += "Couldn't acquire threads _KTRAP_FRAME\n"

            outfd.write("{0}\n".format(s))

