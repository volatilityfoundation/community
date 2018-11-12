# Author: KSL group
# Email: ksl.taskforce@gmail.com
# Description:
# Threadmap plugin helps you map the process's threads'
# entry points in memory. This is done by extracting Win32StartAddress
# from the _ETHREAD and try to match it to a vad or kernel space.
# By using kernel objects to check the entry point we can
# detect any user mode memory manipulation and unattended
# kernel manipulations as well.
#
# The plugin will output suspicious threads and processes that match our rules:
#
# [*] Any process that doesn't have at least one thread that points
# to the process's mapped image file will be considered
# suspicious (Process Hollowing attacks can be found this way).
# A suspended thread that points to the process's image
# file doesn't count as mapped thread.
#
# [*] Any thread that points to an exe file that is not the
# process's image file will be considered suspicious
#
# [*] Any thread that is mapped to a vad without a file object
# will be considered suspicious. Most cases of injected code
# allocate memory by creating a vad that is not mapped to an image file
# (Good for finding code injection and process hollowing).
#
# [*] Any thread is mapped to a vad with a file object, but the type
# of the file isn't IMAGE_FILE. When initializing a process or loading
# a dll "in the natural way" the windows system maps a vad with the right
# flags. Attackers who attempt to mimic that action by loading an PE file
# as a mapped object using windows API wouldn't be able to map it as
# an IMAGE_FILE.
#
# [*] Suspicious JMP or CALLS withing the first 12 bytes (3-4 orders)
# that send the thread to another vad will be considered suspicious.
# Using a JMP and CALL are used in process hollowing and code injection
# when an attacker sends the running thread to his allocated memory
# (Good for finding code injection and process hollowing).

import re
import os
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.malfind as malfind
from volatility.plugins.taskmods import PSList
from volatility.plugins.modules import Modules

# Try to import distorm3 for disassembly
try:
    import distorm3
except ImportError:
    debug.warning("distorm3 isn't found. "
                  "Disassemble functions will be carried by malfind")
    has_distorm = False
else:
    has_distorm = True

VAD_OBJECT              = 0
VAD_ADDRSPACE           = 1
IMAGE_FILE_TYPE         = 2
WAIT                    = 5
SUSPEND                 = 5
SUSPENDED_THREAD        = "PS_CROSS_THREAD_FLAGS_DEADTHREAD"

# Process messages, add here for your custom rules
PROCESS_MESSAGES        = {"Points to Process Image":
                               "Good thread points to an image file",
                           "No Image File":
                               "No thread is pointing to process's image file",
                           "Thread Suspended":
                               "Mapped thread is suspended"}

# Suspicious threads messages, add here for your custom rules
THREAD_THREATS          = {"Thread Without File Object":
                               "\tThread points to a vad without a file object",
                           "Different EXE": "\tFound a thread that points to another .exe file",
                           "PE that isn't Image File":
                               "\tFound a thread that points to a PE "
                               "file that is not mapped as IMAGE_FILE",
                           "Suspicious JMP":
                               "\tFound a suspicious JMP/CALL in thread"}

class ThreadFindings(object):
    def __init__(self, thread_object):
        self.reason = []
        self.struct = thread_object
        self.mapped_to_kernel = False
        self.mapped_to_vad = False
        self.no_location = False
        self.jmp_data = []
        self.file_object_name = ''
        self.module_start_address = 0
        self.entry_point = thread_object.Win32StartAddress

    def add_location_in_kernel(self, module_name, module_start_address):
        """
        :param module_name: The module's file name in mapped kernel
        :param module_start_address: Start address of module in kernel
        :return: None
        Thread is mapped to a kernel module.
        Add the file object in kernel, the start address
        """
        self.mapped_to_kernel = True
        self.file_object_name = module_name
        self.module_start_address = module_start_address

    def _get_vad_file_object(self, vad_object):
        """
        :param vad_object: _MMVAD object
        :return: A string of the mapped file object name
        Try to get the full name of the mapped file to vad
        """
        try:
            file_name = vad_object.FileObject.FileName.v()
        except AttributeError:
            return ''
        else:
            return file_name

    def add_location_in_vad(self, vad_object):
        """
        :param vad_object: __MMVAD object
        :return: None
        Thread is mapped to a vad
        Add the vad object itself to thread's info conclusions
        and try to get the file's object full name
        """
        self.mapped_to_vad = True
        self.vad_object = vad_object
        self.file_object_name = self._get_vad_file_object(vad_object)

    def disassemble(self, address_space, entry_point):
        """
        :param address_space: process's address space object
        :param entry_point: Start address
        :return: A string of the disassembled code
        Disassemble the 64 bytes of code by giving the process's
        address space and the start address
        """
        entry_point = int(entry_point)
        content = address_space.read(entry_point, 64)

        # Check if we could have read from memory, might be paged
        if content:
            disassemble_code = "\t"
            disassemble_code += ("{0}\n\n".format("\n\t".join(
                ["{0:#010x}  {1:<48}  {2}".format(entry_point + o, h, ''.join(c))
                 for o, h, c in utils.Hexdump(content)])))
            disassemble_code += "\t"

            # Rather disassemble with distrom3 than malfind
            if has_distorm:
                # Get OS profile
                mode = address_space.profile.metadata.get('memory_model')

                if mode == '64bit':
                    mode = distorm3.Decode64Bits

                else:
                    mode = distorm3.Decode32Bits

                disassemble_code += "\n\t".join(["{0:#010x} {1:<16} {2}".format(o, h, i) \
                                              for o, _size, i, h in \
                                              distorm3.DecodeGenerator(entry_point, content, mode)])

            else:
                disassemble_code += "\n\t".join(
                    ["{0:#010x} {1:<16} {2}".format(o, h, i)
                     for o, i, h in malfind.Disassemble(content, entry_point)])

            disassemble_code += "\n"

        else:
            disassemble_code = "\t** Couldn't read memory\n"

        return disassemble_code

    def parse_vad(self, vad_object):
        """
        :param vad_object: _MMVAD Object
        :return: A string of information about the vad
        Extract relevant information about the vad
        for the final output in render_text
        """
        vad = vad_object
        vad_start = vad.Start
        vad_end = vad.End
        vad_size = vad_end - vad_start
        vad_protection = vadinfo.PROTECT_FLAGS.get(
            vad.VadFlags.Protection.v())
        vad_tag = vad.Tag
        file_name = self._get_vad_file_object(vad_object)
        file_name = file_name if file_name else "''"

        output =    "\tVad Base Address: {0:#x}\n"\
                    "\tVad End Address: {1:#x}\n"\
                    "\tVad Size: {2:#x}\n"\
                    "\tVad Tag: {3}\n"\
                    "\tVad Protection: {4}\n"\
                    "\tVad Mapped File: {5}\n\n".format(vad_start,
                                                 vad_end,
                                                 vad_size,
                                                 vad_tag,
                                                 vad_protection,
                                                 file_name)

        return output

class threadmap(vadinfo.VADDump):
    """
    Relate a thread's properties with its respective vad's properties
    to attempt to detect irregularities
    """
    
    def __init__(self, config, *args, **kwargs):
        vadinfo.VADDump.__init__(self, config, *args, **kwargs)
        config.remove_option("BASE")
        self.kernel_modules = {}
        self.proc_vads = []

    def check_for_jmp(self, thread, proc, addr_space):
        """
        :param thread: _ETHREAD Object
        :param proc: _EPROCESS Object
        :param addr_space: Process's address space object
        :return: None, JMP/CALL is determined if thread.jmp_data exists
        Try to detect if there is a suspicious JMP or CALL in the
        first 12 bytes of the thread's entry point
        JMP/CALL that points to the same vad are considered to be
        legitimate. When we detect a JMP/CALL to another allocated
        memory in a new vad we might suspect someone tampered
        and injected malicious code.
        """

        vad = thread.vad_object
        content = addr_space.read(thread.entry_point, 12)

        # Can't read thread's entry point from memory, might be paged
        if not content:
            return False

        # disassemble with distorm3, more accurate
        if has_distorm:

            # Get OS profile
            mode = addr_space.profile.metadata.get('memory_model')

            if mode == '64bit':
                mode = distorm3.Decode64Bits

            else:
                mode = distorm3.Decode32Bits

            disassemble_data = "\n".join(["{0:<#8x} {1:<32} {2}".format(o, h, i) \
                                          for o, _size, i, h in \
                                          distorm3.DecodeGenerator(int(thread.entry_point),content, mode)])

        else:

            disassemble_data = "\n".join(
            ["{0:#010x} {1:<16} {2}".format(o, h, i)
            for o, i, h in malfind.Disassemble(content, int(thread.entry_point))])

        # First check - if there is a jmp to an address
        jmp_list_to_addr = re.findall("\s*(?:call|jmp)\s*(0x[0-9a-f]+)\s*\n\s*",
                                      disassemble_data, re.I)

        # Second check - if there is a move and then jmp or call to the register
        jmp_list_to_register = re.findall("(0x[0-9a-f]+)\n0x[0-9a-f]+\s*[0-9a-f]+\s*(?:call|jmp)\s*[a-z]+\n",
                                          disassemble_data, re.I)

        jmp_list = jmp_list_to_addr + jmp_list_to_register

        # Check if we found a jmp
        if jmp_list:

            # Pass on every jmp
            for address in jmp_list:

                if not address:
                    continue

                address = int(address, 16)

                # Check if the address is in the vad
                if vad.Start <= address <= vad.End:
                    continue

                # Suspicious jump outside the vad range
                else:

                    in_vad_range = self.check_where_in_vad(address)

                    # Found a matching vad for the JMP address
                    if in_vad_range:
                        vad, vad_addr_space = in_vad_range
                        thread.jmp_data.append(("vad", vad, address))

                    # Found a suspicious JMP, but didn't find a matching vad in process memory checking kernel
                    else:

                        in_kernel_space = self.check_where_in_kernel(address)

                        if in_kernel_space:
                            module_name, module_start = in_kernel_space
                            thread.jmp_data.append(("kernel",
                                                    (module_name, module_start),
                                                    address))

                        else:
                            thread.jmp_data.append(("Couldn't find location", '', address))

    def get_kernel_modules(self):
        """
        :return: a dictionary of all the loaded modules in kernel space
        Get all loaded kernel modules to check if there are threads
        that point there.
        """

        kernel_modules = {}

        # Get the name, start and end address of each kernel module
        for module in Modules(self._config).calculate():
            kernel_modules[module.FullDllName.v()] = {"Start_Address": module.DllBase,
                                                      "End_Address": module.DllBase \
                                                       + module.SizeOfImage}
        return kernel_modules

    def get_vad_for_process(self, task):
        """
        :param task: _EPROCESS structure of the process
        :return: a list of all vad objects for a given process
        """

        proc_vad_range = []

        for vad, addr_space in task.get_vads():
            proc_vad_range.append((vad, addr_space))

        return proc_vad_range

    def get_threads_for_process(self, task):
        """
        :param task: _EPROCESS structure of the process
        :return: a generator of threads from
                 the linked list - _ETHREAD Object
        """

        for thread in task.ThreadListHead.list_of_type("_ETHREAD",
                                                       "ThreadListEntry"):
            yield thread

    def check_where_in_vad(self, thread_entry_point):
        """
        :param thread_entry_point: thread's entry point
               from Win32StartAddress attribute
        :return: a tuple of the _MMVAD object and its address space
        Check where the thread's entry point is located within the
        process's vads
        """

        for vad, addr_space in self.proc_vads:

            # Check if the thread's function is within the vad range 
            if vad.Start <= thread_entry_point <= vad.End:

                return (vad, addr_space)

        return ()

    def check_where_in_kernel(self, thread_entry_point):
        """
        :param thread_entry_point: thread's entry point
               from Win32StartAddress attribute
        :return: a tuple of the module's mapped file name and the
                 start address
        Check if the thread's function is pointed to one the
        kernel modules
        """

        for module in self.kernel_modules.keys():

            start_address = self.kernel_modules[module]["Start_Address"]
            end_address = self.kernel_modules[module]["End_Address"]

            # Check if the thread points to this module range 
            if start_address <= thread_entry_point <= end_address:

                return module, start_address

        return ()

    def get_proc_name(self, proc, address_space):
        """
        :param proc: _EPROCESS object
        :param address_space: Process's address space object
        :return: The process's loaded image file name
        Extract the process's loaded image file name from
        the _EPROCESS structure
        """
        name = address_space.read(proc.SeAuditProcessCreationInfo.ImageFileName.Name.Buffer,
                                  proc.SeAuditProcessCreationInfo.ImageFileName.Name.Length).replace("\x00", '')

        return name if name else ''

    def calculate(self):

        # Get kernel modules
        self.kernel_modules = self.get_kernel_modules()

        # Get processes
        ps = PSList(self._config)
        psdata = ps.calculate()

        for proc in psdata:

            proc_addr_space = proc.get_process_address_space()
            thread_points_to_proc_image = False
            suspicious_thread_in_process = False
            threads_for_process = []
            proc_name = self.get_proc_name(proc, proc_addr_space)
            threats_in_proc = []

            # Skip terminated processes when verbose is off
            if proc.ProcessDelete.v() != 0 and proc.ProcessExiting != 0 \
                and not self._config.verbose:
                continue

            # Get vads for process
            self.proc_vads = self.get_vad_for_process(proc)

            # Check every thread from given process
            for thread in self.get_threads_for_process(proc):

                # Create a new thread
                thread = ThreadFindings(thread)
                thread_entry_point = thread.struct.Win32StartAddress

                in_vad_range = self.check_where_in_vad(thread_entry_point)

                # Check if the thread points to a kernel module
                if not in_vad_range:

                    at_kernel_module = self.check_where_in_kernel(thread_entry_point)

                    # Thread is not at kernel space
                    if at_kernel_module:
                        module_name, module_start_addr = at_kernel_module
                        thread.add_location_in_kernel(module_name, module_start_addr)
                        threads_for_process.append(thread)
                    else:
                        print "Process", proc.UniqueProcessId, proc.ImageFileName, "Thread", hex(thread_entry_point)
                        thread.no_location = True
                        threads_for_process.append(thread)

                else:

                    vad, vad_addr_space = in_vad_range
                    thread.add_location_in_vad(vad)

                    # Found a thread is mapped to vad without a file object
                    if not thread.file_object_name:
                        thread.reason.append(THREAD_THREATS["Thread Without File Object"])
                        suspicious_thread_in_process = True

                        # Add reason only once
                        if THREAD_THREATS["Thread Without File Object"] \
                                not in threats_in_proc:
                            threats_in_proc.append(THREAD_THREATS["Thread Without File Object"])

                    else:

                        # Found a thread that is pointing to the vad that contains
                        # the process's legitimate image file
                        if thread.file_object_name in proc_name:
                            thread_points_to_proc_image = PROCESS_MESSAGES["Points to Process Image"]

                            wait_reason = int(thread.struct.Tcb.WaitReason)
                            state = int(thread.struct.Tcb.State)

                            # Check if the file object thread is suspended
                            if state == WAIT and wait_reason == SUSPEND:
                                thread_points_to_proc_image = PROCESS_MESSAGES["Thread Suspended"]

                        else:

                            # Found a thread is mapped to a vad that contains an
                            # exe file object that is different from the loaded process's image file
                            if thread.file_object_name.split(".")[-1].lower() == "exe":
                                thread.reason.append(THREAD_THREATS["Different EXE"])
                                suspicious_thread_in_process = True

                                # Add reason only once
                                if THREAD_THREATS["Different EXE"] not in threats_in_proc:
                                    threats_in_proc.append(THREAD_THREATS["Different EXE"])

                        # Check if the vad is mapped to an image file
                        if vad.u.VadFlags.VadType.v() != IMAGE_FILE_TYPE:
                            suspicious_thread_in_process = True

                            # Add the reason only once
                            if THREAD_THREATS["PE that isn't Image File"] not in threats_in_proc:
                                threats_in_proc.append(THREAD_THREATS["PE that isn't Image File"])

                    # Check for suspicious jumps only for threads that are not in kernel mode
                    if thread.mapped_to_vad:

                        self.check_for_jmp(thread, proc, proc_addr_space)

                        # A suspicious JMP/CALL is found within the thread
                        if thread.jmp_data:
                            suspicious_thread_in_process = True

                            # Add suspicious jump/call message to process only once
                            if THREAD_THREATS["Suspicious JMP"] not in threats_in_proc:
                                threats_in_proc.append(THREAD_THREATS["Suspicious JMP"])

                            thread.reason.append(THREAD_THREATS["Suspicious JMP"])

                    threads_for_process.append(thread)

            yield (proc, threads_for_process,
                   thread_points_to_proc_image,
                   suspicious_thread_in_process)

    def render_text(self, outfd, data):

        outfd.write("\n\nThread Map Information:\n\n")
        verbose = self._config.verbose
        dump_dir = self._config.DUMP_DIR

        # Check if -D (dump dir) is passed and directory exists
        if dump_dir and not os.path.isdir(dump_dir):
            debug.error("'{}' was not found".format(dump_dir))

        for proc, thread_info, thread_points_to_proc_image, \
            suspicious_thread_in_process in data:

            # A legitimate process won't be printed unless verbose is passed
            if not verbose and not suspicious_thread_in_process \
                    and thread_points_to_proc_image == PROCESS_MESSAGES["Points to Process Image"]:
                continue

            proc_pid = proc.UniqueProcessId
            proc_ppid = proc.InheritedFromUniqueProcessId
            proc_name = proc.ImageFileName
            address_space = proc.get_process_address_space()

            # Skip printing out system process if not verbosed
            if proc_pid == 4 and not verbose:
                continue

            outfd.write("Process: {} PID: {} PPID: {}\n\n".format(proc_name,
                                                                proc_pid,
                                                                proc_ppid))

            if not thread_points_to_proc_image:
                outfd.write("** {}\n".format(PROCESS_MESSAGES["No Image File"]))

            elif thread_points_to_proc_image == PROCESS_MESSAGES["Thread Suspended"]:
                outfd.write("** {}\n".format(PROCESS_MESSAGES["Thread Suspended"]))

            if suspicious_thread_in_process:
                outfd.write("** Found suspicious threads in process\n")

            outfd.write("\n")

            for thread in thread_info:

                thread_id = thread.struct.Cid.UniqueThread.v()

                # Print threads if they are suspected, verbose is enabled, or none
                # of the threads point to process's image file
                if verbose or thread.reason or not thread_points_to_proc_image:

                    # Check if the thread is terminated
                    if thread.struct.Terminated != 0:
                        outfd.write("Thread : {} (IS "\
                                            "Terminated)\n\n".format(thread_id))
                    else:
                        outfd.write("Thread ID: {} (ACTIVE)\n\n".format(thread_id))

                    # Print out the thread's findings if there are some
                    if thread.reason:
                        outfd.write("Reason:\n {}\n\n".format('\n'.join(thread.reason)))

                    # Couldn't find a valid location for thread
                    if thread.no_location:
                        outfd.write("Couldn't obtain thread's location in memory, "
                                    "Might be unmapped\n")

                    # Print out thread's mapped kernel space information
                    elif thread.mapped_to_kernel:
                        outfd.write("Kernel space info:\n")
                        outfd.write("\tThread Entry Point: {0:#x}\n".format(thread.entry_point))
                        outfd.write("\tMapped to kernel at: {0:#x}\n".format(thread.module_start_address))
                        outfd.write("\tModule name: {}\n\n".format(thread.file_object_name))
                        outfd.write(thread.disassemble(address_space, thread.entry_point))

                    # Print out thread's mapped vad information
                    elif thread.mapped_to_vad:
                        outfd.write("Vad Info:\n")
                        outfd.write("\tThread Entry Point: {0:#x}\n".format(thread.entry_point))
                        outfd.write(thread.parse_vad(thread.vad_object))
                        outfd.write(thread.disassemble(address_space, thread.entry_point))

                        # Dump the vad data
                        if dump_dir:
                            filename = "Process.{0}.Thread.{1}.entrypoint.{2:#x}.dmp".format(proc_pid,
                                                                                             thread_id,
                                                                                             thread.entry_point)
                            full_path = os.path.join(dump_dir, filename)
                            self.dump_vad(full_path, thread.vad_object, address_space)

                        # Print out thread's vad information from found JMP/CALL address
                        if thread.jmp_data:
                            for type_of_memory, memory_object, jmp_address in thread.jmp_data:

                                if type_of_memory == "vad":
                                    outfd.write("\n\tSuspicious JMP/CALL to: {0:#x}\n".format(jmp_address))
                                    outfd.write(thread.parse_vad(memory_object))
                                    outfd.write(thread.disassemble(address_space, jmp_address))

                                    # Dump suspicious JMP/CALL vad data
                                    if dump_dir:
                                        filename = "Process.{0}.Thread.{1}.JMP_or_CALL_address.{2:#x}.dmp".format(proc_pid,
                                                                                                                  thread_id,
                                                                                                                  jmp_address)
                                        full_path = os.path.join(dump_dir, filename)
                                        self.dump_vad(full_path, memory_object, address_space)

                                elif type_of_memory == "kernel":
                                    module_name, module_start_address = memory_object
                                    outfd.write("\n\tSuspicious JMP/CALL to: {0:#x}\n".format(jmp_address))
                                    outfd.write("\tMapped to kernel at: {0:#x}\n".format(module_start_address))
                                    outfd.write("\tModule name: {}\n\n".format(module_name))
                                    outfd.write(thread.disassemble(address_space, jmp_address))

                                else:
                                    outfd.write("\n\n\tSuspicious JMP/CALL to: {0:#x}\n".format(jmp_address))
                                    outfd.write("\n\t** Couldn't read memory\n")

                    outfd.write("----------------------------------------------------------------------\n\n")

            outfd.write("----------------------------------------------------------------------\n\n")
