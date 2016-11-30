# Author: Monnappa K A
# Email : monnappa22@gmail.com
# Twitter: @monnappa22
# Description: Volatility plugin to detect different types of Process Hollowing 

import os
import volatility.obj as obj
import volatility.utils as utils
from volatility.plugins.taskmods import PSList
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.malfind as malfind
from volatility.renderers.basic import Address,Hex


hollow_types = dict(enumerate(["Invalid EXE Memory Protection and Process Path Discrepancy",
                             "No VAD Entry For Process Executable",
                             "Process Base Address and Memory Protection Discrepancy"]))

class HollowFind(vadinfo.VADDump):
    """Detects different types of Process Hollowing"""
    
    def __init__(self, config, *args, **kwargs):
        vadinfo.VADDump.__init__(self, config, *args, **kwargs)
        config.remove_option("BASE") 
    
    def update_proc_peb_info(self, psdata):
        self.proc_peb_info = {}
        # Builds a dictionary of process executable information from PEB
        for proc in psdata:
            pid = int(proc.UniqueProcessId)
            self.proc_peb_info[pid] = [proc, 
                                       pid, 
                                       proc.ImageFileName, 
                                       int(proc.InheritedFromUniqueProcessId),
                                       str(proc.CreateTime)]
            if proc.Peb: 
                # gets process information for the process executable from PEB and updates the dictionary 
                mods = proc.get_load_modules()
                for mod in mods:
                    ext = os.path.splitext(str(mod.FullDllName))[1].lower()
                    if (ext == ".exe"):
                        proc_cmd_line = proc.Peb.ProcessParameters.CommandLine
                        proc_image_baseaddr = proc.Peb.ImageBaseAddress
                        mod_baseaddr = mod.DllBase
                        mod_size = mod.SizeOfImage
                        mod_basename = mod.BaseDllName
                        mod_fullname = mod.FullDllName
                        break
                        
                self.proc_peb_info[pid].extend([str(proc_cmd_line), 
                                                Address(proc_image_baseaddr), 
                                                Address(mod_baseaddr), 
                                                Hex(mod_size), 
                                                str(mod_basename),
                                                str(mod_fullname or "")])
                        
            else:
                self.proc_peb_info[pid].extend(["No PEB", Address(0), Address(0), Hex(0), "No PEB", "No PEB"])
                
                
    def update_proc_vad_info(self, proc_peb_info):
        """Builds a dictionary of process executable information from VAD"""
        self.proc_vad_info = {}
        for pid in proc_peb_info:
            self.proc_vad_info[pid] = []
            proc = proc_peb_info[pid][0]
            
            if proc.Peb:
                # gets process information for the process executable from VAD and updates the dictionary
                for vad, addr_space in proc.get_vads(vad_filter = proc._mapped_file_filter):
                    ext = ""
                    vad_found = False
                    if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = addr_space).e_magic != 0x5A4D:
                        continue
                    
                    if str(vad.FileObject.FileName or ''):
                        ext = os.path.splitext(str(vad.FileObject.FileName))[1].lower()
                    
                    if (ext == ".exe") or (vad.Start == proc.Peb.ImageBaseAddress):
                        vad_filename =  vad.FileObject.FileName
                        vad_baseaddr = vad.Start
                        vad_size = vad.End - vad.Start
                        vad_protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v())
                        vad_tag = vad.Tag
                        self.proc_vad_info[pid].extend([str(vad_filename or ''), 
                                                        Address(vad_baseaddr),
                                                        Hex(vad_size), 
                                                        str(vad_protection or ''), 
                                                        str(vad_tag or '')])
                        vad_found = True
                        break
                
                if vad_found == False:
                    self.proc_vad_info[pid].extend(["NA", Address(0), Hex(0), "NA", "NA"])
                          
            else:
                self.proc_vad_info[pid].extend(["No VAD", Address(0), Hex(0), "No VAD", "No VAD"])
    
    def get_proc_peb_info(self):
        return self.proc_peb_info
    
    def get_proc_vad_info(self):
        return self.proc_vad_info
    
    def detect_proc_hollow(self):
        """Detects hollowed processes and returns dictionary with pid as the key and type of process hollowing as value"""
        proc_peb_info = self.get_proc_peb_info()
        proc_vad_info = self.get_proc_vad_info()
        hol_type = None
        self.hollowed_procs = {}
        for pid in proc_peb_info:
            (proc, pid, proc_name, ppid, create_time, proc_cmd_line, proc_image_baseaddr, mod_baseaddr, 
             mod_size, mod_basename, mod_fullname) = proc_peb_info[pid] 
            (vad_filename, vad_baseaddr, vad_size, vad_protection, vad_tag) = proc_vad_info[pid]
            
            if vad_protection == "PAGE_EXECUTE_READWRITE":
                hol_type = 0
                self.hollowed_procs[pid] = hol_type
                
            elif vad_protection == "NA":
                hol_type = 1
                self.hollowed_procs[pid] = hol_type
            
            elif (vad_protection == "PAGE_EXECUTE_WRITECOPY") and (vad_baseaddr != proc_image_baseaddr):
                hol_type = 2
                self.hollowed_procs[pid] = hol_type
        return self.hollowed_procs
    
    
    def update_parent_proc_info(self, proc_peb_info):
        """Builds a dictionary containing parent process information for all the processes"""
        self.parent_proc_info = {}
        for pid in proc_peb_info:
            self.parent_proc_info[pid] = []
            if pid == 4:
                self.parent_proc_info[pid].extend(["", 0])
            else: 
                ppid = int(proc_peb_info[pid][3])
                if ppid in proc_peb_info:
                    ppname = str(proc_peb_info[ppid][2])
                else:
                    ppname = "NA"
                    
                self.parent_proc_info[pid].extend([ppname, ppid])                 
    
    def get_parent_proc_info(self):
        return self.parent_proc_info
    
    def get_similar_procs(self, procid):
        """Given a process id returns a list containing information of similar processes"""
        self.similar_procs = []
        proc_peb_info = self.get_proc_peb_info()
        parent_proc_info = self.get_parent_proc_info()
        pname = proc_peb_info[procid][2]
        create_time = proc_peb_info[procid][4]
        ppname, ppid = parent_proc_info[procid]
        self.similar_procs.append([pname, procid, ppname, ppid, create_time])
        
        for pid in proc_peb_info:
            if pid == procid:
                continue
            if pname == proc_peb_info[pid][2]:
                proc_name = proc_peb_info[pid][2]
                creation_time = proc_peb_info[pid][4]
                parent_name, parent_id = parent_proc_info[pid]
                self.similar_procs.append([proc_name, pid, parent_name, parent_id, creation_time])
        return self.similar_procs
    
                     
    def calculate(self):
        if self._config.PID:
            filter_pid = self._config.PID
            # This is so that when -p option is given it can still enumerate all processes to determine similar processes
            self._config.PID = None
        else:
            filter_pid = None
        ps = PSList(self._config)
        psdata = ps.calculate()
        self.update_proc_peb_info(psdata)
        proc_peb_info = self.get_proc_peb_info()
        self.update_parent_proc_info(proc_peb_info)
        parent_proc_info = self.get_parent_proc_info()
        self.update_proc_vad_info(proc_peb_info)
        hol_procs = self.detect_proc_hollow()
        proc_vad_info = self.get_proc_vad_info()  
        if hol_procs:
            for (hol_pid, hol_type) in hol_procs.items():
                similar_procs = self.get_similar_procs(hol_pid)
                if not filter_pid:
                    yield (proc_peb_info[hol_pid], 
                           proc_vad_info[hol_pid],
                           hol_pid, hol_type,
                           similar_procs,
                           parent_proc_info[hol_pid] )
                else:
                    for p in filter_pid.split(','):
                        fil_pid = int(p)
                        if int(fil_pid) == hol_pid:
                            yield (proc_peb_info[hol_pid],
                                   proc_vad_info[hol_pid],
                                   hol_pid, hol_type,
                                   similar_procs,
                                   parent_proc_info[hol_pid])
    
    def render_text(self, outfd, data):
        for (hol_proc_peb_info, hol_proc_vad_info, hol_pid, hol_type, similar_procs, parent_proc_info) in data:
            (proc, pid, proc_name, ppid, create_time, proc_cmd_line, proc_image_baseaddr, mod_baseaddr, 
             mod_size, mod_basename, mod_fullname) = hol_proc_peb_info
            (vad_filename, vad_baseaddr, vad_size, vad_protection, vad_tag) = hol_proc_vad_info
            (parent_name, parent_id) = parent_proc_info
            
            outfd.write("Hollowed Process Information:\n")
            outfd.write("\tProcess: {0} PID: {1}\n".format(proc_name, hol_pid))
            outfd.write("\tParent Process: {0} PPID: {1}\n".format(parent_name, ppid))
            outfd.write("\tCreation Time: {0}\n".format(create_time))
            outfd.write("\tProcess Base Name(PEB): {0}\n".format(mod_basename))
            outfd.write("\tCommand Line(PEB): {0}\n".format(proc_cmd_line))
            outfd.write("\tHollow Type: {0}\n".format(hollow_types[hol_type]))
            outfd.write("\n")
            outfd.write( "VAD and PEB Comparison:\n")
            outfd.write( "\tBase Address(VAD): {0:#x}\n".format(vad_baseaddr))
            outfd.write( "\tProcess Path(VAD): {0}\n".format(vad_filename))
            outfd.write( "\tVad Protection: {0}\n".format(vad_protection))
            outfd.write( "\tVad Tag: {0}\n".format(vad_tag))
            outfd.write("\n")
            
            if hol_type == 0:
                addr_space = proc.get_process_address_space()
                dos_header = obj.Object("_IMAGE_DOS_HEADER", offset=proc_image_baseaddr, vm=addr_space)
                nt_header = dos_header.get_nt_header()
                optional_header = obj.Object("_IMAGE_OPTIONAL_HEADER", offset=nt_header.obj_offset+0x18, vm=addr_space)
                ep_addr = proc_image_baseaddr + optional_header.AddressOfEntryPoint
                content = addr_space.read(ep_addr, 64)
                outfd.write("\tBase Address(PEB): {0:#x}\n".format(proc_image_baseaddr))
                outfd.write("\tProcess Path(PEB): {0}\n" .format(mod_fullname))
                outfd.write("\tMemory Protection: {0}\n".format(vad_protection))
                outfd.write("\tMemory Tag: {0}\n".format(vad_tag))
                outfd.write("\n")
                outfd.write("Disassembly(Entry Point):\n")
                if content != None:
                    outfd.write("\n".join(["\t{0:#010x} {1:<16} {2}".format(o, h, i) 
                     for o, i, h in malfind.Disassemble(content, ep_addr)
                    ]))
                else:
                    outfd.write("\tNo Disassembly: Memory Unreadable at {0:#010x}\n".format(ep_addr))
                    
                outfd.write("\n\n")
            
            if (hol_type == 1) or (hol_type == 2):
                for vad, addr_space in proc.get_vads():
                    if vad.Start == proc_image_baseaddr:
                        content = addr_space.read(vad.Start, 64)
                        outfd.write("\tBase Address(PEB): {0:#x}\n".format(proc_image_baseaddr))
                        outfd.write("\tProcess Path(PEB): {0}\n" .format(mod_fullname))
                        outfd.write("\tMemory Protection: {0}\n".format(str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v()) or  "")))
                        outfd.write("\tMemory Tag: {0}\n".format(str(vad.Tag or "")))
                        outfd.write("\n")
                        if content != None:
                            outfd.write("".join(["{0:#010x}  {1:<48}  {2}\n".format(vad.Start + o, h, ''.join(c))
                                       for o, h, c in utils.Hexdump(content)]))
                        else:
                            outfd.write("\tNo Hexdump: Memory Unreadable at {0:#010x}\n".format(vad.Start))
                        outfd.write("\n")
                        
            outfd.write("Similar Processes:\n")
            for similar_proc in similar_procs:
                (process_name, process_id, parent_name, parent_id, creation_time) = similar_proc
                outfd.write("\t{0}({1}) Parent:{2}({3}) Start:{4}\n".format(process_name,
                                                                            process_id,
                                                                            parent_name,
                                                                            parent_id,
                                                                            creation_time))
            outfd.write("\n")
            
            outfd.write("Suspicious Memory Regions:\n")
            for vad, addr_space in proc.get_vads():
                content = addr_space.read(vad.Start, 64)
                if content == None:
                    continue
                vad_prot = str(vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v()))
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = addr_space).e_magic != 0x5A4D:
                    flag = "No PE/Possibly Code"
                    if (vad_prot == "PAGE_EXECUTE_READWRITE"):
                        sus_addr = vad.Start
                        outfd.write("\t{0:#x}({1})  Protection: {2}  Tag: {3}\n".format(vad.Start,
                                                                                        flag,
                                                                                        vad_prot,
                                                                                        str(vad.Tag or "")))
                        if self._config.DUMP_DIR:
                            filename = os.path.join(self._config.DUMP_DIR,"process.{0}.{1:#x}.dmp".format(hol_pid, sus_addr))
                            self.dump_vad(filename, vad, addr_space)
                    
                    elif (vad_prot == "PAGE_EXECUTE_WRITECOPY"):
                        sus_addr = vad.Start
                        outfd.write("\t{0:#x}({1})  Protection: {2}  Tag: {3}\n".format(sus_addr,
                                                                                        flag,
                                                                                        vad_prot,
                                                                                        str(vad.Tag or "")))
                        if self._config.DUMP_DIR:
                            filename = os.path.join(self._config.DUMP_DIR,"process.{0}.{1:#x}.dmp".format(hol_pid, 
                                                                                                          sus_addr))
                            self.dump_vad(filename, vad, addr_space)
                        
                else:
                    if vad_prot == "PAGE_EXECUTE_READWRITE":
                        flag = "PE Found"
                        sus_addr = vad.Start
                        outfd.write("\t{0:#x}({1})  Protection: {2}  Tag: {3}\n".format(sus_addr,
                                                                                        flag,
                                                                                        vad_prot,
                                                                                        str(vad.Tag or "")))
                        if self._config.DUMP_DIR:
                            filename = os.path.join(self._config.DUMP_DIR,"process.{0}.{1:#x}.dmp".format(hol_pid, 
                                                                                                          sus_addr))
                            self.dump_vad(filename, vad, addr_space)
                    
                    elif (vad_prot == "PAGE_EXECUTE_WRITECOPY") and (not bool(vad.FileObject)):
                        flag = "PE - No Mapped File"
                        sus_addr = vad.Start
                        outfd.write("\t{0:#x}({1})  Protection: {2}  Tag: {3}\n".format(sus_addr,
                                                                                        flag,
                                                                                        vad_prot,
                                                                                        str(vad.Tag or "")))
                        if self._config.DUMP_DIR:
                            filename = os.path.join(self._config.DUMP_DIR,"process.{0}.{1:#x}.dmp".format(hol_pid, 
                                                                                                          sus_addr))
                            self.dump_vad(filename, vad, addr_space)
                        
            outfd.write("---------------------------------------------------\n\n")



