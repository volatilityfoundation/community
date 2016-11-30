# findevilproc
__author__ = "Tyler Halfpop"
__version__ = "0.1"
__license__ = "MIT"

import os
import sys

import volatility.debug as debug
import volatility.conf as conf
import volatility.utils as utils
import volatility.plugins.procdump as procdump
import volatility.plugins.taskmods as taskmods

import findevilinfo

class findEvilProc(procdump.ProcDump):
    """ Find potential known bad processes
    """

    def __init__(self, config, *args, **kwargs):
        procdump.ProcDump.__init__(self, config, *args, **kwargs)
        self._config.DUMP_DIR = os.getcwd() + os.sep + "dump_tmp"
        if not os.path.exists(self._config.DUMP_DIR):
            os.mkdir(self._config.DUMP_DIR)
            print "Creating Dump Dir {}".format(str(self._config.DUMP_DIR))
        else:
            print "Dump Dir Already Exists {}".format(str(self._config.DUMP_DIR))

    def render_text(self, outfd, data):
        """ Dump processes and check for known bad
        https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/procdump.py
        """

        # Compile Yara Rules if configured
        if findevilinfo.YARA_RULES_DIR != "INSERT_YARA_RULES_DIR_HERE":
            ys = findevilinfo.YaraClass()
        
         # render_text from procdump
        self.table_header(outfd,
                          [("Name", "20"),
                           ("Result", "25"),
                           ("Hash", "64"),
                           ("Verdict", "10"),
                           ("Signed", "8"),
                           ("Entropy", "12"),
                           ("Yara", ""),])
        
        for task in data:
            task_space = task.get_process_address_space()
            if task_space == None:
                result = "Error: Cannot acquire process AS"
            elif task.Peb == None:
                # we must use m() here, because any other attempt to 
                # reference task.Peb will try to instantiate the _PEB
                result = "Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(task.m('Peb'))
            elif task_space.vtop(task.Peb.ImageBaseAddress) == None:
                result = "Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(task.Peb.ImageBaseAddress)
            else:
                dump_file = "executable." + str(task.UniqueProcessId) + ".exe"
                result = self.dump_pe(task_space,
                                task.Peb.ImageBaseAddress,
                                dump_file)
                
                # Full path of dumped file, get hash, VT, signed, entropy, yara
                dumped_file = "{}{}{}".format(self._config.DUMP_DIR, os.sep, dump_file)
                
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
                            task.ImageFileName,
                            result,
                            file_hash,
                            verdict,
                            signed,
                            entropy,
                            yara_hits)
