import os
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.win32.modules as modulesf
import volatility.plugins.taskmods as taskmods
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.overlays.windows.windows as windows
import volatility.constants as constants
import volatility.plugins.malware.malfind as malfind




class Malfofind(vadinfo.VADDump):
    "Find indications of process hollowing/RunPE injections"

    def __init__(self, config, *args, **kwargs):
        vadinfo.VADDump.__init__(self, config, *args, **kwargs)
        config.remove_option("BASE")
        config.remove_option("PID")
        config.remove_option("NAME")

    def generate_output(self, outfd, vad, task, file_object_name, peb_image_path_name):
        # this function will output data for a given VAD passed to it
        
        content = None
        
        outfd.write("Process: {0} Pid: {1} Ppid: {2}\n".format(
        task.ImageFileName, task.UniqueProcessId, task.InheritedFromUniqueProcessId))

        outfd.write("Address: {0:#x} Protection: {1}\n".format(
            vad.Start, vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), "")))
        
        if peb_image_path_name != None:
            outfd.write("Initially mapped file object: {0}\n".format(peb_image_path_name))
        else:
            outfd.write("Initially mapped file object: {0}\n".format("None"))

        if file_object_name != None:
            outfd.write("Currently mapped file object: {0}\n".format(file_object_name))
        else:
            outfd.write("Currently mapped file object: {0}\n".format("None"))
    

        address_space = task.get_process_address_space()
        content = address_space.zread(vad.Start, 64)

        if content:
            outfd.write("{0}\n".format("\n".join(
                ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c))
                for o, h, c in utils.Hexdump(content)
                ])))

            outfd.write("\n")
            outfd.write("\n".join(
                ["{0:#010x} {1:<16} {2}".format(o, h, i)
                for o, i, h in malfind.Disassemble(content, vad.Start)
                ]))
        
        outfd.write("\n\n")

        # dump vad incase -D was specified
        if self._config.DUMP_DIR:
            filename = os.path.join(self._config.DUMP_DIR,
                "process.{0:#x}.{1:#x}.dmp".format(
                task.obj_offset, vad.Start))
            self.dump_vad(filename, vad, address_space)
        
    def render_text(self, outfd, data):

        # check if supplied path is a directory
        if self._config.DUMP_DIR and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for task in data:
            peb_image_path_name = None
            peb_image_base = None

            # check if peb is available
            if task.Peb != None:
                if task.Peb.ProcessParameters != None and task.Peb.ProcessParameters.ImagePathName:
                    #grab image base and image path name from peb
                    peb_image_path_name = str(task.Peb.ProcessParameters.ImagePathName)
                    peb_image_base = task.Peb.ImageBaseAddress

            # iterate over vads, for each vad check if there is a mapped file object,
            # check if PEB LDR module objects are mapped with the same name and same
            # base address as the the VAD specifies, if not we consider it and indictaion
            # of process hollowing and send the vads details to self.generate_output()
            
            for vad in task.VadRoot.traverse():
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
                    except AttributeError:
                        pass
                    if peb_image_base != None:
                        if vad.Start == peb_image_base:
                            if peb_image_path_name != None:
                                if file_object_name == None:
                                    self.generate_output(outfd, vad, task, file_object_name, peb_image_path_name)

                                else:
                                    peb_image_path_name = peb_image_path_name.lower()
                                    if peb_image_path_name.startswith(r"\systemroot"):
                                        peb_image_path_name = peb_image_path_name.replace("\\systemroot", "\\windows")
                                    if peb_image_path_name.find(file_object_name.lower()) == -1 or peb_image_path_name.find(str(task.ImageFileName).lower()) == -1:
                                        self.generate_output(outfd, vad, task, file_object_name, peb_image_path_name)
                                    else:
                                        continue

