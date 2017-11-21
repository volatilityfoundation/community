# pylint: disable=E0401,C0111,C0103,C0412,E0602
'''
    File name: procfhash.py
    Author: Inaki Abadia
    Date created: 2/1/2017
    Date last modified: 9/11/2017
    Python Version: 2.7
'''

import tempfile
import os
import sys
import shutil
import string
import multiprocessing.pool
from functools import partial
import pefile
from subprocess import check_output, CalledProcessError


import volatility.plugins.common as common
import volatility.addrspace as addrspace
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.plugins.procdump as procdump
from volatility.plugins.taskmods import MemDump
import volatility.conf as conf
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.text import TextRenderer

import enumtypes as enum
import _exceptions as exc
import algorithms as algh

MAX_CONCURRENT_THREADS = 100


class ProcessFuzzyHash(common.AbstractWindowsCommand):
    """ProcessFuzzyHash

        Options:
          -P: Process PID(s). Will hash given processes PIDs.
                (E.g. -P 252 | -P 252,452,2852)
          -E: Process Name. Will hash process that match given string.
                (E.g. -N svchost.exe | -N winlogon.exe,explorer.exe )
          -N: Process Name. Will hash processes that contain given string in the name.
                (E.g. -N svchost | -N winlogon,explorer )
          -A: Algorithm to use. Aviable: ssdeep, sdhash, tlsh, dcfldd. Default: ssdeep
                (E.g. -A ssdeep | -A SSDeep | -A SSDEEP,sdHash,TLSH,dcfldd)
          -S: Section to hash. 
               Full process: "full"
               Full PE: "pe"
               PE section: "<pe-section>"
               PE header: "pe:<header>", "pe:header" for full header
               PE section header: "<pe-section>:header"
                (E.g. -S .text | -S .data,.rsrc | -S pe,.text:header | -S pe:NT_HEADERS | -S full)
          -s: Hash strins instead of binary data.

          -c: Compare given hash against generated hashes.
                (E.g. -c '3:elHLlltXluBGqMLWvl:6HRlOBVrl')
          -C: Compare given hashes' file against generated hashes.
                (E.g. -C /tmp/hashfile.txt | -C hashfile.txt)
          -H: Human readable values (Create Time)

          -M: Multithreaded processing. If included, one thread will be used per calculated hash.

          -V: Keep hashed data on disk. Defaults to False.

          -t: Tmp folder. If none given a random folder at /tmp will be used.

          --output-file=<file>: Plugin output will be writen to given file.

          --output=<format>: Output formatting. [text, dot, html, json, sqlite, quick, xlsx]

        Note:
          - If -P and -N provided, -N will be ignored.
          - If -N and -E provided, -E will be ignored.
          - Full process (-S full) and full PE/PE section cannot be hsahed at the same time.
          - Supported PE header names (pefile): DOS_HEADER, NT_HEADERS, FILE_HEADER, 
                                                OPTIONAL_HEADER, RICH_HEADER, HEADER
          - Hashes' file given with -C must contain one hash per line.
          - If -c and -C given, the comparation will be between them. No new hashes will be generated.
          - Params -c and -C can be given multiple times (E.g. vol.py (...) -c <hash1> -c <hash2>)"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PROC-PID', short_option = 'P', default = None, help = 'Process PID', 
            action = 'store', type = 'str')
        self._config.add_option('PROC-NAME', short_option = 'N', default = None, help = 'Contained process name', 
            action = 'store', type = 'str')
        self._config.add_option('PROC-NAME-MATCH', short_option = 'E', default = None, help = 'Exact process name', 
            action = 'store', type = 'str')
        self._config.add_option('ALGORITHM', short_option = 'A', default = "ssdeep", help = 'Hash algorithm', 
            action = 'store', type = 'str')
        self._config.add_option('SECTION', short_option = 'S', default = None, help = 'PE section to hash', 
            action = 'store', type = 'str')
        self._config.add_option('COMPARE-HASH', short_option = 'c', default = None, help = 'Compare to given hash', 
            action = 'append', type = 'str')
        self._config.add_option('COMPARE-FILE', short_option = 'C', default = None, help = "Compare to hashes' file", 
            action = 'append', type = 'str')
        self._config.add_option('MULTITHREAD', short_option = 'M', default = False, help = 'Use multithreaded processing', 
            action = 'store_true')
        self._config.add_option('HUMAN-READABLE', short_option = 'H', default = False, help = 'Show human readable values', 
            action = 'store_true')
        self._config.add_option('STRINGS', short_option = 's', default = False, help = 'Hash strings contained in binary data', 
            action = 'store_true')
        self._config.add_option('NON-VOLATILE', short_option = 'V', default = False, help = 'Save hashed data on disk', 
            action = 'store_true')
        self._config.add_option('TMP-FOLDER', short_option = 't', default = None, help = 'Temp folder to be used', 
            action = 'store', type = 'str')

    def calculate(self):
        # Initial defines and checks
        self.addr_space = utils.load_as(self._config)

        # Hash, hash and compare or compare
        if self._config.COMPARE_FILE and self._config.COMPARE_HASH:
            return self.calculate_compare()
        else:
            return self.calculate_hash(True if self._config.COMPARE_FILE 
                                                      or self._config.COMPARE_HASH 
                                                   else None)

    def calculate_hash(self, compare):
        # ProcDump or MemDump
        # If no section specified, raise exception
        if not self._config.SECTION:
            raise exc.NoSection()
        sections_list = self._config.SECTION.split(',')
        if len(sections_list) > 1 and 'full' in sections_list:
            raise exc.FullProcessAndPE(self._config.SECTION)
        dumpmem = True if self._config.SECTION and self._config.SECTION == 'full' else False
        # ProcDump plugin configuration
        dump_conf = self.build_dump_conf()
        dump_dir = dump_conf.DUMP_DIR
        # Redirect procdump otuput to devnull
        stdout_bk = sys.stdout
        sys.stdout = open(os.devnull, 'w')
        # Run ProcDump or MemDump and delete
        p = MemDump(dump_conf) if dumpmem else procdump.ProcDump(dump_conf)
        p.execute()
        del p
        # Restore sys.stdout
        sys.stdout = stdout_bk

        # Build Fprint list
        fprint_list = []
        if self._config.MULTITHREAD:
            # Multithread!
            pool = multiprocessing.pool.ThreadPool(processes=MAX_CONCURRENT_THREADS)
            pdump_list = []
            for task in tasks.pslist(self.addr_space):
                dumpfilename = resolve_dump_path(dump_conf.DUMP_DIR, task.UniqueProcessId, dumpmem)
                if check_file(dumpfilename):
                    # Read dump file, proc name and build PDump obj
                    if dumpmem:
                        dmp_file = open(dumpfilename)
                    else:
                        dmp_file = pefile.PE(dumpfilename, fast_load=True)
                    proc_name = task.ImageFileName
                    pdump = PDump(dmp_file, 
                                  task.UniqueProcessId, 
                                  str(task.CreateTime if self._config.HUMAN_READABLE else task.CreateTime.as_windows_timestamp()), 
                                  proc_name, 
                                  self._config.PROFILE,
                                  not dumpmem,
                                  self._config.STRINGS,
                                  dump_dir if self._config.NON_VOLATILE else None,
                                  dumpfilename)

                    pdump_list.append(pdump)
            algh_list = self._config.ALGORITHM.split(",")
            for a in algh_list:
                for s in sections_list:
                    func = partial(HashEngine().digest_data,
                                algh.get_alghconfig_instance(enum.Algorithm().resolve(a)),
                                s)
                    fprint_list += pool.map(func, pdump_list, chunksize=1)
        else:
            for task in tasks.pslist(self.addr_space):
                # Check if procdump didn't dump a file or filtered by name/pids
                dumpfilename = resolve_dump_path(dump_conf.DUMP_DIR, task.UniqueProcessId, dumpmem)
                if check_file(dumpfilename):
                    # Read executable file, proc name and build PDump obj
                    if dumpmem:
                        dmp_file = open(dumpfilename)
                    else:
                        dmp_file = pefile.PE(dumpfilename, fast_load=True)
                    proc_name = task.ImageFileName
                    pdump = PDump(dmp_file, 
                                  task.UniqueProcessId,
                                  task.CreateTime if self._config.HUMAN_READABLE else task.CreateTime.as_windows_timestamp(), 
                                  proc_name,
                                  self._config.PROFILE,
                                  not dumpmem,
                                  self._config.STRINGS,
                                  dump_dir if self._config.NON_VOLATILE else None,
                                  dumpfilename)

                    # Append frpint ot FPrint list
                    algh_list = self._config.ALGORITHM.split(",")

                    for a in algh_list:
                        for s in sections_list:
                            fprint_list.append(
                                HashEngine().digest_data(algh.get_alghconfig_instance(
                                                            enum.Algorithm().resolve(a)),
                                                        s,
                                                        pdump))
        # Delete files generated by procdump
        if self._config.NON_VOLATILE:
            debug.info('Hashed data stored in: ' + dump_dir)
        else:
            shutil.rmtree(dump_dir)
        # Remove None occurences (bad sections)
        fprint_list = filter(lambda v: v != None, fprint_list)
        if compare:
            return self.compare_fprint_list(fprint_list)
        else:
            return fprint_list

    def compare_fprint_list(self, flist):
        # Get hash list from FPrint list
        hash_team_1 = []
        hash_team_2 = []
        for f in flist:
            hash_team_2.append(f.fingerprint)
        # Get second hash list
        if self._config.COMPARE_FILE:
            # -C
            hash_team_1 = self.build_hash_team(self._config.COMPARE_FILE)
        elif self._config.COMPARE_HASH:
            # -c
            hash_team_1 = self._config.COMPARE_HASH
        # Match teams
        match_results = []
        for h1 in hash_team_1:
            for h2 in hash_team_2:
                match_results.append(HashEngine().compare_hashes(h1, h2, self._config.ALGORITHM))
        return match_results

    def calculate_compare(self):
        # Build individual hashes' and files' teams
        hash_team_1 = self._config.COMPARE_HASH
        hash_team_2 = self.build_hash_team(self._config.COMPARE_FILE)

        # Match teams (compare 1v1)
        match_results = []
        for h1 in hash_team_1:
            for h2 in hash_team_2:
                match_results.append(HashEngine().compare_hashes(h1, h2, self._config.ALGORITHM))
        return match_results

    def build_hash_team(self, hash_files_list):
        '''Build Hash list from hash file list'''
        hash_file_list = []
        for hfile in hash_files_list:
            hash_file_list += self.hash_file_to_list(hfile)
        return hash_file_list

    def hash_file_to_list(self, hfile):
        hash_list = []
        try:
            with open(hfile, "r") as f:
                for line in f:
                    hash_list.append(line.rstrip())
        except IOError:
            debug.error("IO error with file " + hfile + " occurred. Please specify a valid file.")
        return hash_list

    def generator(self, data):
        if self._config.COMPARE_HASH or self._config.COMPARE_FILE:
            for match in data:
                yield(0, [
                    str(match.hash_a),
                    str(match.hash_b),
                    str(match.algorithm),
                    str(match.score)
                ])
        else:
            for proc in data:
                yield(0, [
                    str(proc.process_name),
                    str(proc.process_pid),
                    str(proc.create_time),
                    str(proc.section),
                    str(proc.algorithm),
                    str(proc.fingerprint)
                ])

    def unified_output(self, data):
        tree = ''
        if self._config.COMPARE_HASH or self._config.COMPARE_FILE:
            tree = [
                ("Hash A", str),
                ("Hash B", str),
                ("Algorithm", str),
                ("Score", str)
                ]
        else:
            tree = [
                ("Name", str),
                ("PID", str),
                ("Create Time", str),
                ("Section", str),
                ("Algorithm", str),
                ("Hash", str)
                ]
        return TreeGrid(tree, self.generator(data))

    def render_text(self, outfd, data):
        # Overriding this function is a hack to override the default max_width.
        self._render(outfd, TextRenderer(self.text_cell_renderers, max_width = sys.maxint, sort_column = self.text_sort_column,
                                         config = self._config), data)

    def build_dump_conf(self):
        # Create conf obj
        procdump_conf = conf.ConfObject()

        # TMP Folder
        tmp_folder = tempfile.mkdtemp() if not self._config.TMP_FOLDER else self._config.TMP_FOLDER

        # Define conf
        procdump_conf.readonly = {}
        procdump_conf.PROFILE = self._config.PROFILE
        procdump_conf.LOCATION = self._config.LOCATION
        procdump_conf.DUMP_DIR = tmp_folder
        procdump_conf.MEMORY = True
        # Single, multiple or all PIDs (all PIDs == No PID specified)
        if self._config.PROC_PID:
            procdump_conf.PID = self._config.PROC_PID
        elif self._config.PROC_NAME or self._config.PROC_NAME_MATCH:
            procdump_conf.PID = self.build_pids()

        # Safety check
        if not os.path.exists(procdump_conf.DUMP_DIR): os.mkdir(procdump_conf.DUMP_DIR)

        # Remove outputfile conf
        procdump_conf.OUTPUT = 'text'
        procdump_conf.OUTPUT_FILE = None

        return procdump_conf

    def build_pids(self):
        if self._config.PROC_NAME:
            # PROC_NAME
            name_list = self._config.PROC_NAME.split(",")
            pid_list = []
            for name in name_list:
                for task in tasks.pslist(self.addr_space):
                    if name in str(task.ImageFileName):
                        pid_list.append(task.UniqueProcessId)
    
            pids = ','.join(map(str, pid_list))
        else:
            # PROC_NAME_MATCH
            name_list = self._config.PROC_NAME_MATCH.split(",")
            pid_list = []
            for name in name_list:
                for task in tasks.pslist(self.addr_space):
                    if name == str(task.ImageFileName):
                        pid_list.append(task.UniqueProcessId)
        
            pids = ','.join(map(str, pid_list))

        if pids == '':
            debug.error("No process matches given name. Please specify a valid name or PID.")
        return pids

class HashEngine(object):
    """HashEngine"""

    def digest_data(self, alghconfig, section, pdump):
        get_data = True if not section or section in {'full', 'pe'} else False
        hash_data = pdump.get_data() if get_data else pdump.get_section(section)
        if not hash_data:
            # Bad section or something
            return None
        if alghconfig.algh == enum.Algorithm.SDHash:
            hash_string = algh.SDHashAlgorithm().hash(hash_data, alghconfig)
        elif alghconfig.algh == enum.Algorithm.TLSH:
            hash_string = algh.TLSHAlgorithm().hash(hash_data, alghconfig)
        elif alghconfig.algh == enum.Algorithm.SSDeep:
            hash_string = algh.SSDeepAlgorithm().hash(hash_data, alghconfig)
        elif alghconfig.algh == enum.Algorithm.dcfldd:
            hash_string = algh.DcflddAlgorithm().hash(hash_data, alghconfig)
        else:
            raise exc.InvalidAlgorithm(alghconfig.algh)

        return Fprint(pdump.pPID,
                      pdump.pCreateTime,
                      pdump.pName,
                      section if section else "pe",
                      hash_string,
                      enum.Algorithm().name(alghconfig.algh),
                      alghconfig)

    def compare_hashes(self, h1, h2, algorithm):
        return Match(h1,
                     h2,
                     algorithm, 
                     algh.get_algh_instance(
                         enum.Algorithm().resolve(
                             algorithm)).compare(h1, h2))


class Fprint(object):
    """Fprint"""

    def __init__(self, pid, createtime, name, section, fprint, algh, config):
        self.process_name = name
        self.process_pid = pid
        self.create_time = createtime
        self.section = section
        self.fingerprint = fprint
        self.algorithm = algh
        self.algorithm_config = config

class PDump(object):
    """PDump"""

    def __init__(self, file, pid, createtime, name, profile, pe, strgs, mirror, filename):
        self.pDump = file
        self.pPID = pid
        self.pCreateTime = createtime
        self.pName = name
        self.pProfile = profile
        self.isPE = pe
        self.strings = strgs
        self.mirror = mirror
        self.filename = filename

    def isPE(self):
        return self.isPE

    def get_profile(self):
        return self.pProfile

    def set_profile(self, profile):
        self.pProfile = profile

    def get_header(self, header_sect):
        ret = None
        # pe:nt_header
        header = header_sect.split(':')[1].upper()
        # Full header func is in lowercase
        if header == 'HEADER':
            # Mind if self.strings
            ret = self.strings_str(self.pDump.header) if self.strings else self.pDump.header
        else:
            try:
                # Mind if self.strings
                ret =  self.strings_str(self.pDump.__getattribute__(header).__pack__()) if self.strings else self.pDump.__getattribute__(header).__pack__()
            except AttributeError:
                raise exc.InvalidPEHeader(header)
        
        # Dump data to disk
        if self.mirror: self.dump_hashed_data(ret, header)

        return ret


    def get_section(self, sect):
        ret = None
        if self.isPE:
            if sect.split(':')[0] == 'pe':
                # PE Header
                ret = self.strings_str(self.get_header(sect)) if self.strings else self.get_header(sect)
            else:
                # PE Section
                split = sect.split(':')
                if len(split) > 1 and split[1] == 'header':
                    # Section header
                    for section in self.pDump.sections:
                        if split[0] == section.Name.translate(None, '\x00'):
                            ret = self.strings_str(section.__pack__()) if self.strings else section.__pack__()
                    if not ret:
                        debug.warning('Unknown section: {!s} for {!s}. Please specify a valid section.'.format(sect, self.pName))
                else:
                    # Section content
                    for section in self.pDump.sections:
                        if sect == section.Name.translate(None, '\x00'):
                            ret = self.strings_str(section.get_data()) if self.strings else section.get_data()
                    if not ret:
                        debug.warning('Unknown section: {!s} for {!s}. Please specify a valid section.'.format(sect, self.pName))
        else:
            raise exc.NoPE(self.pName)

        # Dump data to disk
        if self.mirror: self.dump_hashed_data(ret, sect)

        return ret

    def get_data(self):
        ret = None
        if self.isPE:
            proc = open(self.filename, 'r').read()

            ret = self.strings_str(proc) if self.strings else proc
        else:
            # Special case, use unix strings (much faster)
            if self.strings:
                pdump_strings = check_output(['strings', self.pDump.name])
                ret = pdump_strings
            else:
                self.pDump.seek(0)
                ret = self.pDump.read()

        return ret

    def dump_hashed_data(self, hashdata, sect):
        # Dump to-be-hashed data (mirror to disk)
        dump_name = self.mirror + "/{!s}-{!s}-{!s}.dmp".format(self.pName, str(self.pPID), sect)
        if not os.path.isfile(dump_name) and hashdata:
            # Maybe already dumped on previous algh
            f = open(dump_name, 'w')
            f.write(hashdata)
    
    def strings_str(self, data):
        strings_list = self.get_strings(data)
        res = ""
        for s in strings_list:
            res += s + '\n'
        return res
        
    def get_strings(self, data, min=4):
        result = ""
        for c in data:
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

class Match(object):

    def __init__(self, ha, hb, algh, scr):
        self.hash_a = ha
        self.hash_b = hb
        self.algorithm = algh
        self.score = scr

#################
# AUX FUNCTIONS #
#################
def resolve_dump_path(location, pid, dumpmem):
    if dumpmem:
        return str(location) + "/" + str(pid) + ".dmp"
    else:
        return str(location) + "/" + "executable." + str(pid) + ".exe"

def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except IOError:
        print "File " + path + " doesn't exist"

def check_file(path):
    return os.path.exists(path)
