# findevilmem
__author__ = "Tyler Halfpop"
__version__ = "0.1"
__license__ = "MIT"

import os
import sys

import volatility.debug as debug
import volatility.conf as conf
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods

import findevilinfo

class findEvilMem(taskmods.MemDump):
    """Find potential known bad in memory
    """

    def __init__(self, config, *args, **kwargs):
        taskmods.MemDump.__init__(self, config, *args, **kwargs)
        self._config.DUMP_DIR = os.getcwd() + os.sep + "dump_tmp"
        if not os.path.exists(self._config.DUMP_DIR):
            os.mkdir(self._config.DUMP_DIR)
            print "Creating Dump Dir {}".format(str(self._config.DUMP_DIR))
        else:
            print "Dump Dir Already Exists {}".format(str(self._config.DUMP_DIR))

    def render_text(self, outfd, data):
        """ Dump process memory and check for bad
        https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/taskmods.py
        """

        # Compile Yara Rules if configured
        if findevilinfo.YARA_RULES_DIR != "INSERT_YARA_RULES_DIR_HERE":
            outfd.write("Compiling Yara Rules\n")
            ys = findevilinfo.YaraClass()
        
        # render_text from taskmods
        for pid, task, pagedata in data:
            task_space = task.get_process_address_space()
            output_file = os.path.join(self._config.DUMP_DIR, str(pid) + ".dmp")
            outfd.write("Writing {0} [{1:6}] to {2}.dmp\n".format(task.ImageFileName, pid, str(pid)))
            f = open(output_file, 'wb')
            if pagedata:
                for p in pagedata:
                    data = task_space.read(p[0], p[1])
                    if data == None:
                        if self._config.verbose:
                            outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} Size: 0x{1:x}\n".format(p[0], p[1]))
                    else:
                        f.write(data)
                findevilinfo.carve(output_file)
            else:
                outfd.write("Unable to read pages for task.\n")
            f.close()
        
        self.table_header(outfd,
                          [("Name", "20"),
                           ("Hash", "64"),
                           ("Verdict", "10"),
                           ("Signed", "8"),
                           ("Entropy", "12"),
                           ("Yara", ""),])
        
        # Walk dump_tmp dir get hash, signed, entropy, vt verdict, yara
        try:
            for root, directories, files in os.walk(self._config.DUMP_DIR):
                for file in files:
                    dumped_file = os.path.join(root,file)
                    file_hash = findevilinfo.get_hash(dumped_file)
                    signed = findevilinfo.check_signed(dumped_file)
                    entropy = findevilinfo.get_entropy(dumped_file)

                    if findevilinfo.VT_API_KEY == "INSERT_VT_API_KEY_HERE":
                        verdict = "NO_API_KEY"
                    else:
                        verdict = findevilinfo.get_VT_verdict(file_hash)
                    
                    if findevilinfo.YARA_RULES_DIR == "INSERT_YARA_RULES_DIR_HERE":
                        yara_hits = "NO_YARA_RULES_DIR"
                    else:
                        yara_hits = ys.scan(dumped_file)

                    self.table_row(outfd,
                                file,
                                file_hash,
                                verdict,
                                signed,
                                entropy,
                                yara_hits)

        except Exception as e:
            print "Exception: {}".format(e)
