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
import callstacks

# pattern names for the plugins output
pattern_name_dll_injection = "Dll injection"
pattern_name_dynamic_code_execution = "Thread executing from dynamically allocated memory"

class MalthfindRule(object):
    """Base class for malthfind rules"""
    def __init__(self, thread_callstack):
        self.thread_callstack = thread_callstack

    def check(self):
        pass
    """Return True or False from this method"""

class MalthfindRuleDllInjection(MalthfindRule):
    """Detect dll injection by scanning the call stack"""

    # the purpose of this check is to find injected dlls using the vanilla
    # dll injection technique of using CreateRemoteThread and starting
    # the thread at LoadLibraryA/W, passing the dlls path as a parameter.

    # this check will scan the callstack and check if the function
    # ntdll.dll!LdrLoadDll is in the first 8 functions called.
    
    def check(self):
        scanback_amount = 8
        callstack_size = len(self.thread_callstack.callstack)
        scanned_amount = 0

        tagged = False
        while scanned_amount != scanback_amount and scanned_amount < callstack_size:
            index = (scanned_amount + 1) * (-1)
            
            if (self.thread_callstack.callstack[index].owning_module_name != "Unknown" or\
               self.thread_callstack.callstack[index].owning_module_name != "-") and\
               self.thread_callstack.callstack[index].function.name != "Unknown":
                if str(self.thread_callstack.callstack[index].owning_module_name).lower() == "ntdll.dll" and self.thread_callstack.callstack[index].function.name.lower() == "ldrloaddll":
                    self.thread_callstack.callstack[index].comment += pattern_name_dll_injection
                    tagged = True
            scanned_amount += 1

        if tagged:
            self.thread_callstack.mal_pattern.append(pattern_name_dll_injection)
        return self.thread_callstack

class MalthfindRuleDynamicallyAllocatedExecutionAddress(MalthfindRule):
    """Detect threads running in dynamically allocated memory"""

    # the purpose of this check is to find injected threads

    # check for code running in dynamically allocated pages
    # we treat pages not mapped to any file object as 'dynamically allocated pages'
    # any thread having a return address in such a page will be flagged
    # by this check.
    
    def check(self):
        address_space = self.thread_callstack.thread.attached_process().get_process_address_space()
        tagged = False
        for item in self.thread_callstack.callstack:
            if address_space.is_valid_address(item.ret_address):
                comment = ""
                if item.owning_module_name != "Unknown" and item.owning_module_name != "-":
                    for vad in self.thread_callstack.thread.attached_process().VadRoot.traverse():
                        if item.ret_address > vad.Start and item.ret_address < vad.End:
                            file_object_name = None
                            file_object = None
                            if vad != None:           
                                try:
                                    control_area = vad.ControlArea
                                    if vad.VadFlags.PrivateMemory != 1 and control_area:                
                                        if control_area:        
                                            file_object = vad.FileObject
                                            if file_object != None and file_object.FileName:
                                                file_object_name = str(file_object.FileName)
                                                if file_object_name.lower().find(item.owning_module_name.lower()) != -1:
                                                    break
                                                else:
                                                    comment += pattern_name_dynamic_code_execution
                                                    tagged = True
                                        else:
                                            comment += pattern_name_dynamic_code_execution
                                            tagged = True
                                except AttributeError:
                                    pass
                            break
                        else:
                            continue
                else:
                    comment += pattern_name_dynamic_code_execution
                    tagged = True
                item.comment += comment
        if tagged:
                self.thread_callstack.mal_pattern.append(pattern_name_dynamic_code_execution)
        return self.thread_callstack

class Malthfind(callstacks.Callstacks):
    "Find malicious threads by analyzing their callstack"

    def __init__(self, config, *args, **kwargs):
        callstacks.Callstacks.__init__(self, config, *args, **kwargs)
        self.bits32 = None

    def calculate(self):
        # retreive callstacks using the Callstacks plugin
        for thread, addr_space, thread_start_function, thread_callstack\
            in callstacks.Callstacks.calculate(self):
            yield thread, addr_space, thread_start_function, thread_callstack

    def render_text(self, outfd, data):
        checks = registry.get_plugin_classes(MalthfindRule)
        
        for thread, addr_space, thread_start_function, thread_callstack in data:
            has_comment = False
            
            
            s = "\n------\n\n"

            s += "ETHREAD: {0:#010x} Pid: {1} Tid: {2}\n".format(
                thread.obj_offset,
                thread.Cid.UniqueProcess, thread.Cid.UniqueThread)

            s += "Owning Process: {0}\n".format(
                thread.owning_process().ImageFileName)

            s += "Attached Process: {0}\n".format(
                thread.attached_process().ImageFileName)

            s += "Thread Flags: {0}\n".format(str(thread.CrossThreadFlags))

            # get all currently implemented rules
            # and run them against the threads callstack
            for cls_name, cls in checks.items():
                thread_callstack = cls(thread_callstack).check()

            if len(thread_callstack.mal_pattern) > 0:
                if len(thread_callstack.callstack) > 0:

                    s += "Malicious patterns detected: "
                    first_pattern = True
                    for pattern in thread_callstack.mal_pattern:
                        if first_pattern:
                            s += pattern
                            first_pattern = False
                        else:
                            s += ", " + pattern
                    s += "\nCallstack:\n"
                    if thread_callstack.eip:
                        s += "\t{0:<8} {3:<8}   {1:<8}   {2}\n".format("No.", "RetAddr", "Function", "Ebp")
                        s += "\t{0:<8} 0x{5:08x} 0x{1:08x} {2}!{3}+0x{4:<8x}\n".format("[eip]", thread_callstack.callstack[0].function.address,
                                                    thread_callstack.callstack[0].owning_module_name, thread_callstack.callstack[0].function.name,
                                                    thread_callstack.callstack[0].ret_address - thread_callstack.callstack[0].function.address,
                                                                                                 0)
                        thread_callstack.callstack.remove(thread_callstack.callstack[0])

                    i = 0
                    for item in thread_callstack.callstack:
                        s += "\t{0:<8} 0x{5:08x} 0x{1:08x} {2}!{3}+0x{4:<8x}\n".format("[" + str(i) + "]", item.function.address,
                                                                    item.owning_module_name, item.function.name,
                                                                    item.ret_address - item.function.address, item.frame_address)
                        i += 1
                        if item.comment != "":
                            has_comment = True
                            
                else:
                    s += "Couldn't acquire threads _KTRAP_FRAME\n"

                if has_comment:
                    outfd.write("{0}\n".format(s))


