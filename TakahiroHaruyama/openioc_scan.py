# openioc_scan Volatility plugin
# based on ioc_writer (https://github.com/mandiant/ioc_writer) and pyioc (https://github.com/jeffbryner/pyioc)
# Copyright (c) 2014 Takahiro Haruyama (@cci_forensics)
# http://takahiroharuyama.github.io/

import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.constants as constants
import volatility.commands as commands

import volatility.plugins.common as common
import volatility.plugins.netscan as netscan
import volatility.plugins.overlays.windows.tcpip_vtypes as tcpip_vtypes
import volatility.plugins.registry.hivelist as hivelist
import volatility.plugins.registry.shimcache as shimcache
import volatility.plugins.taskmods as taskmods
import volatility.plugins.modules as modules
import volatility.plugins.modscan as modscan
import volatility.plugins.filescan as filescan
import volatility.plugins.privileges as privileges
import volatility.plugins.ssdt as ssdt
import volatility.plugins.mftparser as mftparser
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware.impscan as impscan
import volatility.plugins.malware.psxview as psxview
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.malware.apihooks as apihooks
import volatility.plugins.malware.devicetree as devicetree
import volatility.plugins.malware.callbacks as callbacks
import volatility.plugins.malware.timers as timers

import volatility.win32 as win32
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.win32.tasks as tasks

import glob, os, re, sqlite3, urllib, socket, time
from lxml import etree as et
from ioc_writer import ioc_api
import colorama
colorama.init()

g_version = '2015/02/24'
g_cache_path = ''
g_detail_on = False
g_color_term = colorama.Fore.MAGENTA
g_color_detail = colorama.Fore.CYAN
g_sus_path_p = re.compile(r'\\ProgramData|\\\$Recycle\.Bin|\\Windows\\Temp|\\Users\\All Users|\\Users\\Default|\\Users\\Public|\\Users\\.*\\AppData', re.IGNORECASE)
READ_BLOCKSIZE = 1024 * 1024 * 10
SCORE_THRESHOLD = 100

# copied from netscan
AF_INET = 2
AF_INET6 = 0x17
inaddr_any = utils.inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = utils.inet_ntop(socket.AF_INET6, '\0' * 16)

if constants.VERSION < 2.4:
    # copied from malfind
    class MalwareObjectClases(obj.ProfileModification):
        before = ['WindowsObjectClasses']
        conditions = {'os': lambda x: x == 'windows'}
        def modification(self, profile):
            profile.object_classes.update({
                '_EPROCESS': malfind.MalwareEPROCESS,
            })

# copied from apihooks
# hook modes
HOOK_MODE_USER = 1
HOOK_MODE_KERNEL = 2
# hook types
HOOKTYPE_IAT = 4
HOOKTYPE_EAT = 8
HOOKTYPE_INLINE = 16
HOOKTYPE_NT_SYSCALL = 32
HOOKTYPE_CODEPAGE_KERNEL = 64
HOOKTYPE_IDT = 128
HOOKTYPE_IRP = 256
HOOKTYPE_WINSOCK = 512
# names for hook types
hook_type_strings = apihooks.hook_type_strings
WINSOCK_TABLE = apihooks.WINSOCK_TABLE

# copied from devicetree
MAJOR_FUNCTIONS = devicetree.MAJOR_FUNCTIONS

# copied from privileges
PRIVILEGE_INFO = privileges.PRIVILEGE_INFO

class Timer(object):
    def __init__(self, verbose=False):
        self.verbose = verbose

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs
        if self.verbose:
            print 'elapsed time: %f ms' % self.msecs

class ItemUtil:
    def is_condition_bool(self, condition):
        supported_conditions = ['is', 'contains']
        if condition in supported_conditions:
            return True
        else:
            return False

    def is_condition_string(self, condition):
        supported_conditions = ['is', 'contains', 'matches', 'starts-with', 'ends-with']
        if condition in supported_conditions:
            return True
        else:
            return False

    def is_condition_integer(self, condition):
        supported_conditions = ['is', 'greater-than', 'less-than']
        if condition in supported_conditions:
            return True
        else:
            return False

    def make_regex(self, content, preserve_case):
        if preserve_case == 'true':
            pattern = re.compile(content, re.DOTALL)
        else:
            pattern = re.compile(content, re.DOTALL | re.IGNORECASE)
        return pattern

    def check_string(self, target, content, condition, preserve_case):
        #out = colorama.Style.BRIGHT + g_color_detail + target + colorama.Fore.RESET + colorama.Style.RESET_ALL
        out = g_color_detail + target + colorama.Fore.RESET
        if condition == 'matches':
            pattern = self.make_regex(content, preserve_case)
            if pattern.search(target) is not None:
                if g_detail_on:
                    print('matched IOC term detail: {0}'.format(out))
                return True
        else:
            if preserve_case == 'false':
                target = target.lower()
                content = content.lower()
            if condition == 'is':
                if target == content:
                    if g_detail_on:
                        print('matched IOC term detail: {0}'.format(out))
                    return True
            elif condition == 'contains':
                if target.find(content) != -1:
                    if g_detail_on:
                        print('matched IOC term detail: {0}'.format(out))
                    return True
            elif condition == 'starts-with':
                if target.startswith(content):
                    if g_detail_on:
                        print('matched IOC term detail: {0}'.format(out))
                    return True
            elif condition == 'ends-with':
                if target.endswith(content):
                    if g_detail_on:
                        print('matched IOC term detail: {0}'.format(out))
                    return True
        return False

    def check_strings(self, target_list, content, condition, preserve_case):
        result = False
        for target in target_list:
            if self.check_string(target, content, condition, preserve_case):
                #return True
                result = True
        #return False
        return result

    def extract_unicode(self, data):
        pat = re.compile(ur'(?:[\x20-\x7E][\x00]){4,}')
        return list(set([w.decode('utf-16le') for w in pat.findall(data)]))

    def extract_ascii(self, data):
        pat = re.compile(r'(?:[\x20-\x7E]){4,}')
        return list(set([w.decode('ascii') for w in pat.findall(data)]))

    def check_integer(self, target, content, condition, preserve_case):
        if condition == 'is':
            if target == content:
                return True
        elif condition == 'greater-than':
            if target > content:
                return True
        elif condition == 'less-than':
            if target < content:
                return True
        return False

    def check_integers(self, target_list, content, condition, preserve_case):
        for target in target_list:
            if self.check_integer(target, content, condition, preserve_case):
                return True
        return False

    def fetchall_from_db(self, cur, table, column):
        debug.debug("{0} already done. Results reused".format(table))
        sql = "select {0} from {1}".format(column, table)
        cur.execute(sql)
        return [record[0] for record in cur.fetchall()]

    def fetchone_from_db(self, cur, table, column):
        debug.debug("{0} already done. Results reused".format(table))
        sql = "select {0} from {1}".format(column, table)
        cur.execute(sql)
        return cur.fetchone()[0]

class ProcessItem(impscan.ImpScan, netscan.Netscan, malfind.Malfind, apihooks.ApiHooks):
    def __init__(self, process, cur, _config):
        self.process = process
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.forwarded_imports = { # copied from impscan
            "RtlGetLastWin32Error" : "kernel32.dll!GetLastError",
            "RtlSetLastWin32Error" : "kernel32.dll!SetLastError",
            "RtlRestoreLastWin32Error" : "kernel32.dll!SetLastError",
            "RtlAllocateHeap" : "kernel32.dll!HeapAlloc",
            "RtlReAllocateHeap" : "kernel32.dll!HeapReAlloc",
            "RtlFreeHeap" : "kernel32.dll!HeapFree",
            "RtlEnterCriticalSection" : "kernel32.dll!EnterCriticalSection",
            "RtlLeaveCriticalSection" : "kernel32.dll!LeaveCriticalSection",
            "RtlDeleteCriticalSection" : "kernel32.dll!DeleteCriticalSection",
            "RtlZeroMemory" : "kernel32.dll!ZeroMemory",
            "RtlSizeHeap" : "kernel32.dll!HeapSize",
            "RtlUnwind" : "kernel32.dll!RtlUnwind",
            }
        self.util = ItemUtil()
        self.compiled_rules = self.compile()

    def read_without_zero_page(self, vad, address_space):
        PAGE_SIZE = 0x1000
        all_zero_page = "\x00" * PAGE_SIZE

        offset = 0
        data = ''
        while offset < vad.Length:
            next_addr = vad.Start + offset
            if address_space.is_valid_address(next_addr):
                page = address_space.read(next_addr, PAGE_SIZE)
                if page != all_zero_page:
                    data += page
            offset += PAGE_SIZE
        return data

    def check_done(self, item):
        sql = "select {0} from done where pid = ?".format(item)
        self.cur.execute(sql, (self.process.UniqueProcessId.v(),))
        return self.cur.fetchone()

    def update_done(self, item):
        sql = "update done set {0} = ? where pid = ?".format(item)
        self.cur.execute(sql, (True, self.process.UniqueProcessId.v()))

    def update_all_done(self, item):
        sql = "update done set {0} = ?".format(item)
        self.cur.execute(sql, (True, ))

    def fetchall_from_db_by_pid(self, table, column):
        debug.debug("{0} already done. Results reused (pid={1})".format(table, self.process.UniqueProcessId))
        sql = "select {0} from {1} where pid = ?".format(column, table)
        self.cur.execute(sql, (self.process.UniqueProcessId.v(),))
        records = self.cur.fetchall()
        if records is None:
            return []
        return [record[0] for record in records]

    def fetchone_from_db_by_pid(self, table, column):
        debug.debug("{0} already done. Results reused (pid={1})".format(table, self.process.UniqueProcessId))
        sql = "select {0} from {1} where pid = ?".format(column, table)
        self.cur.execute(sql, (self.process.UniqueProcessId.v(),))
        record = self.cur.fetchone()
        if record is None: # for cmdLine
            return ''
        return record[0]

    def detect_code_injections(self):
        injected = []
        debug.info("[time-consuming task] detecting code injections...(pid={0})".format(self.process.UniqueProcessId))
        for vad, address_space in self.process.get_vads(vad_filter = self.process._injection_filter):
            if self._is_vad_empty(vad, address_space):
                continue
            self.cur.execute("insert into injected values (?, ?, ?)", (self.process.UniqueProcessId.v(), vad.Start, vad.Length))
            injected.append([vad.Start, vad.Length])
        self.update_done('injected')
        return injected

    def SectionList_MemorySection_Injected(self, content, condition, preserve_case):
        if not self.util.is_condition_bool(condition):
            debug.error('{0} condition is not supported in ProcessItem/SectionList/MemorySection/Injected'.format(condition))
            return False

        (done,) = self.check_done('injected')
        if int(done):
            counts = self.fetchone_from_db_by_pid('injected', 'count(*)')
        else:
            counts = len(self.detect_code_injections())

        if (counts > 0 and content.lower() == 'true') or (counts == 0 and content.lower() == 'false'):
            return True
        else:
            return False

    def SectionList_MemorySection_InjectedHexPattern(self, content, condition, preserve_case):
        if condition != 'matches':
            debug.error('{0} condition is not supported in ProcessItem/SectionList/MemorySection/InjectedHexPattern'.format(condition))
            return False

        (done,) = self.check_done('injected')
        if int(done):
            starts = self.fetchall_from_db_by_pid('injected', 'start')
        else:
            starts = [start for (start, size) in self.detect_code_injections()]

        pattern = self.util.make_regex(content, preserve_case)
        addr_space = self.process.get_process_address_space()
        for start in starts:
            content = addr_space.zread(start, 256)
            if pattern.search(content) is not None:
                return True
        return False

    def extract_strings(self):
        debug.info("[time-consuming task] extracting strings from VADs (pid={0})".format(self.process.UniqueProcessId))
        strings = []

        for vad, address_space in self.process.get_vads(skip_max_commit = True):
            data = self.read_without_zero_page(vad, address_space)
            if len(data) == 0:
                continue
            elif len(data) > READ_BLOCKSIZE:
                debug.debug('data size in VAD is more than READ_BLOCKSIZE (pid{0})'.format(self.process.UniqueProcessId))
            extracted = list(set(self.util.extract_unicode(data) + self.util.extract_ascii(data)))
            strings.extend(extracted)

        records = ((self.process.UniqueProcessId.v(), string) for string in strings)
        self.cur.executemany("insert or ignore into strings values (?, ?)", records)
        self.update_done('strings')
        return strings

    def check_and_extract_strings(self, content, condition, preserve_case):
        (done,) = self.check_done('strings')
        if int(done):
            strings = self.fetchall_from_db_by_pid('strings', 'string')
        else:
            strings = self.extract_strings()
        return self.util.check_strings(strings, content, condition, preserve_case)

    def StringList_string(self, content, condition, preserve_case):
        '''
        condition: is/contains/matches(regex)/starts-with/ends-with
        preserve_case: true/false
        '''
        result = False

        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/StringList/string'.format(condition))
            return False

        result = self.check_and_extract_strings(content, condition, preserve_case)
        if result == False and condition == 'matches': # for searching binary sequences
            pattern = self.util.make_regex(content, preserve_case)
            (done,) = self.check_done('vaddump')
            if int(done):
                debug.debug("vaddump already done. Results reused (pid={0})".format(self.process.UniqueProcessId))
                f = open(os.path.join(g_cache_path, 'vaddump_pid' + str(self.process.UniqueProcessId)) + '.bin', 'rb')

                i = 0
                overlap = 1024
                self.cur.execute("select size from vaddump where pid = ?", (self.process.UniqueProcessId.v(),))
                maxlen = self.cur.fetchone()[0]
                while i < maxlen:
                    to_read = min(READ_BLOCKSIZE + overlap, maxlen - i)
                    f.seek(i)
                    data = f.read(to_read)
                    if data:
                        if pattern.search(data) is not None:
                            return True
                    i += READ_BLOCKSIZE
                return False

            debug.info("[time-consuming task] dumping VADs for regex search... (pid={0})".format(self.process.UniqueProcessId))
            f = open(os.path.join(g_cache_path, 'vaddump_pid' + str(self.process.UniqueProcessId)) + '.bin', 'wb')
            size = 0
            for vad, address_space in self.process.get_vads(skip_max_commit = True):
                data = self.read_without_zero_page(vad, address_space)
                if len(data) == 0:
                    continue
                elif len(data) > READ_BLOCKSIZE:
                    debug.debug('data size in VAD is more than READ_BLOCKSIZE (pid{0})'.format(self.process.UniqueProcessId))
                if pattern.search(data) is not None:
                    result = True
                f.write(data)
                size += len(data)
            f.flush()
            f.close()
            self.cur.execute("insert into vaddump values (?, ?)", (self.process.UniqueProcessId.v(), size))
            self.update_done('vaddump')

        return result

    # based on impscan (overrided)
    def _vicinity_scan(self, addr_space, calls_imported, apis, base_address, data_len, forward, injected):

        sortedlist = calls_imported.keys()
        sortedlist.sort()

        debug.debug('_vicinity_scan: base={0:x}'.format(base_address))
        if not sortedlist:
            debug.debug('sortedlist:None')
            return

        size_of_address = addr_space.profile.get_obj_size("address")

        if forward:
            start_addr = sortedlist[0]
        else:
            start_addr = sortedlist[len(sortedlist) - 1]

        if injected:
            # searching dynamically generated IAT
            threshold = 0x400
            if not forward:
                start_addr += 0x1000
        else:
            threshold = 5
        i = 0

        while threshold and i < 0x2000:
            if forward:
                next_addr = start_addr + (i * size_of_address)
            else:
                next_addr = start_addr - (i * size_of_address)

            debug.debug('next_addr {0:x} (threshold={1})'.format(next_addr, threshold))
            call_dest = obj.Object("address", offset = next_addr,
                            vm = addr_space).v()

            #if (not call_dest or call_dest < base_address or call_dest > base_address + data_len): <- original code miss the entries
            if (not call_dest or (call_dest > base_address and call_dest < base_address + data_len)):
                debug.debug('continued {0:x}:{1:x}'.format(next_addr, call_dest))
                threshold -= 1
                i += 1
                continue

            if call_dest in apis and call_dest not in calls_imported:
                debug.debug('found {0:x}:{1:x}'.format(next_addr, call_dest))
                calls_imported[next_addr] = call_dest
                if injected:
                    threshold = 0x400
                else:
                    threshold = 5
            else:
                threshold -= 1

            i += 1

    # based on impscan
    def SectionList_MemorySection_PEInfo_ImportedModules_Module_ImportedFunctions_string(self, content, condition, preserve_case):
        result = False

        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/SectionList/MemorySection/PEInfo/ImportedModules/Module/ImportedFunctions/string'.format(condition))
            return False

        (done,) = self.check_done('impfunc')
        if int(done):
            imp_funcs = self.fetchall_from_db_by_pid('impfunc', 'func_name')
            return self.util.check_strings(imp_funcs, content, condition, preserve_case)

        debug.info("[time-consuming task] extracting imported functions...(pid={0})".format(self.process.UniqueProcessId))
        if self.process._vol_vm == self.flat_space:
            debug.warning('This process (pid={0}) seems to be dead. Skipping extraction of imported functions..'.format(self.process.UniqueProcessId))
            self.update_done('impfunc')
            return False

        scan_list = []
        all_mods = list(self.process.get_load_modules())
        if all_mods is not None and len(all_mods) > 0:
            # add the process image region
            scan_list.append((all_mods[0].DllBase, all_mods[0].SizeOfImage, False)) # start, size, injected

        # add suspicious DLL regions based on ldrmodules
        p = re.compile(r'')
        for vad, address_space in self.process.get_vads(vad_filter = self.process._mapped_file_filter):
            if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = address_space).e_magic != 0x5A4D:
                continue
            path = str(vad.FileObject.FileName or 'none').lower()
            if g_sus_path_p.search(path) is not None:
                entry = (vad.Start, vad.Length, False)
                if entry not in scan_list: # exclude exe
                    debug.info('add suspicious dll to scan_list: {0}'.format(path))
                    scan_list.append(entry)

        # add injected memory regions
        (done,) = self.check_done('injected')
        if int(done):
            self.cur.execute("select start, size from injected where pid = ?", (self.process.UniqueProcessId.v(),))
            records = self.cur.fetchall()
            if records is not None:
                scan_list.extend([(start, size, True) for start, size in records])
        else:
            scan_list.extend([(start, size, True) for start, size in self.detect_code_injections()])

        debug.debug(scan_list)
        for base_address, size_to_read, injected in scan_list:
            addr_space = self.process.get_process_address_space()
            if not addr_space:
                debug.warning("SectionList_MemorySection_PEInfo_ImportedModules_Module_ImportedFunctions_string: Cannot acquire process AS")
                return False
            data = addr_space.zread(base_address, size_to_read)
            apis = self.enum_apis(all_mods)
            calls_imported = dict(
                    (iat, call)
                    for (_, iat, call) in self.call_scan(addr_space, base_address, data)
                    if call in apis
                    )
            if injected:
                self._vicinity_scan(addr_space, calls_imported, apis, base_address, len(data), True, True)
                self._vicinity_scan(addr_space, calls_imported, apis, base_address, len(data), False, True)
            else:
                self._vicinity_scan(addr_space, calls_imported, apis, base_address, len(data), True, False)
                self._vicinity_scan(addr_space, calls_imported, apis, base_address, len(data), False, False)
            for iat, call in sorted(calls_imported.items()):
                mod_name, func_name = self._original_import(str(apis[call][0].BaseDllName or ''), apis[call][1])
                self.cur.execute("insert into impfunc values (?, ?, ?, ?, ?)", (self.process.UniqueProcessId.v(), iat, call, mod_name, func_name))
                if func_name == '':
                    continue
                if self.util.check_string(func_name, content, condition, preserve_case):
                    result = True

        self.update_done('impfunc')
        return result

    def name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/name'.format(condition))
            return False
        return self.util.check_string(str(self.process.ImageFileName), content, condition, preserve_case)

    def ParentProcessName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/name'.format(condition))
            return False
        if str(self.process.ImageFileName) == "System":
            return self.util.check_string('none', content, condition, preserve_case)
        self.cur.execute("select offset from hidden where pid = ?", (self.process.InheritedFromUniqueProcessId.v(),))
        res = self.cur.fetchone()
        if res is None:
            return False
        pprocess = obj.Object("_EPROCESS", offset = res[0], vm = self.flat_space)
        return self.util.check_string(str(pprocess.ImageFileName), content, condition, preserve_case)

    def cmdLine(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/cmdLine'.format(condition))
            return False
        path = self.fetchone_from_db_by_pid('hidden', 'cmdLine')
        return self.util.check_string(path, content, condition, preserve_case)

    # based on malfind
    def extract_dllpaths(self, is_path=False, is_hidden=False):
        debug.info("[time-consuming task] extracting dllpaths from VADs... (pid={0})".format(self.process.UniqueProcessId))

        inloadorder = dict((mod.DllBase.v(), mod)
                            for mod in self.process.get_load_modules())
        ininitorder = dict((mod.DllBase.v(), mod)
                            for mod in self.process.get_init_modules())
        inmemorder = dict((mod.DllBase.v(), mod)
                            for mod in self.process.get_mem_modules())

        mapped_files = {}
        for vad, address_space in self.process.get_vads(vad_filter = self.process._mapped_file_filter):
            if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = address_space).e_magic != 0x5A4D:
                continue
            mapped_files[int(vad.Start)] = str(vad.FileObject.FileName or '')

        records = []
        for base in mapped_files.keys():
            load_mod = inloadorder.get(base, None)
            init_mod = ininitorder.get(base, None)
            mem_mod = inmemorder.get(base, None)
            result = (load_mod == None) and (init_mod == None) and (mem_mod == None)
            records.append((self.process.UniqueProcessId.v(), mapped_files[base], result))

        self.cur.executemany("insert or ignore into dllpath values (?, ?, ?)", records)
        self.update_done('dllpath')
        if is_path:
            return [record[1] for record in records]
        elif is_hidden:
            return [record[2] for record in records]

    def DllPath(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/DllPath'.format(condition))
            return False

        (done,) = self.check_done('dllpath')
        if int(done):
            dllpaths = self.fetchall_from_db_by_pid('dllpath', 'path')
        else:
            dllpaths = self.extract_dllpaths(is_path=True)
        return self.util.check_strings(dllpaths, content, condition, preserve_case)

    def DllHidden(self, content, condition, preserve_case):
        if not self.util.is_condition_bool(condition):
            debug.error('{0} condition is not supported in ProcessItem/DllHidden'.format(condition))
            return False

        (done,) = self.check_done('dllpath')
        if int(done):
            hiddens = self.fetchall_from_db_by_pid('dllpath', 'hidden')
        else:
            hiddens = self.extract_dllpaths(is_hidden=True)

        if (True in hiddens and content.lower() == 'true') or (False not in hiddens and content.lower() == 'false'):
            if g_detail_on:
                sql = "select path from dllpath where pid = ? and hidden = ?"
                self.cur.execute(sql, (self.process.UniqueProcessId.v(), content.lower() == 'true'))
                records = self.cur.fetchall()
                for (path,) in records:
                    out = g_color_detail + str(path) + colorama.Fore.RESET
                    print('matched IOC term detail: {0}'.format(out))
            return True
        else:
            return False

    # based on handles
    def extract_handles(self, is_name=False, is_type=False):
        debug.info("[time-consuming task] extracting handle information... (pid={0})".format(self.process.UniqueProcessId))

        pid = self.process.UniqueProcessId
        handle_list = []
        if self.process.ObjectTable.HandleTableList:
            for handle in self.process.ObjectTable.handles():

                if not handle.is_valid():
                    continue

                name = ""
                object_type = handle.get_object_type()
                if object_type == "File":
                    file_obj = handle.dereference_as("_FILE_OBJECT")
                    name = str(file_obj.file_name_with_device())
                elif object_type == "Key":
                    key_obj = handle.dereference_as("_CM_KEY_BODY")
                    name = key_obj.full_key_name()
                elif object_type == "Process":
                    proc_obj = handle.dereference_as("_EPROCESS")
                    name = "{0}({1})".format(proc_obj.ImageFileName, proc_obj.UniqueProcessId)
                elif object_type == "Thread":
                    thrd_obj = handle.dereference_as("_ETHREAD")
                    name = "TID {0} PID {1}".format(thrd_obj.Cid.UniqueThread, thrd_obj.Cid.UniqueProcess)
                elif handle.NameInfo.Name == None:
                    name = ''
                else:
                    name = str(handle.NameInfo.Name)

                handle_list.append((int(pid), object_type, name))

            records = list(set(handle_list))
            for record in records:
                #print record
                pid, object_type, name = record
                #self.cur.execute("insert or ignore into handles values (?, ?, ?)", (pid, object_type, name.decode('utf8')))
                self.cur.execute("insert or ignore into handles values (?, ?, ?)", (pid, object_type, unicode(name))) # all executemany should be explicitly converted to unicode?
            #self.cur.executemany("insert or ignore into handles values (?, ?, ?)", records)

            self.update_done('handles')
            if is_name:
                return [record[2] for record in records]
            elif is_type:
                return [record[1] for record in records]

        self.update_done('handles')
        return None

    def HandleList_Handle_Name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/HandleList/Handle/Name'.format(condition))
            return False

        (done,) = self.check_done('handles')
        if int(done):
            names = self.fetchall_from_db_by_pid('handles', 'name')
        else:
            names = self.extract_handles(is_name=True)
            if names is None:
                debug.warning('cannot get handles (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(names, content, condition, preserve_case)

    def HandleList_Handle_Type(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/HandleList/Handle/Type'.format(condition))
            return False

        (done,) = self.check_done('handles')
        if int(done):
            types = self.fetchall_from_db_by_pid('handles', 'type')
        else:
            types = self.extract_handles(is_type=True)
            if types is None:
                debug.warning('cannot get handles (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(types, content, condition, preserve_case)

    def extract_netinfo(self, is_protocol=False, is_laddr=False, is_lport=False, is_raddr=False, is_rport=False, is_state=False):
        debug.info("[time-consuming task] extracting network information...")

        net_list = []
        # addef for default values (AbstractScanCommand)
        self._config.VIRTUAL = False
        self._config.SHOW_UNALLOCATED = False
        self._config.START = None
        self._config.LENGTH = None

        for net_object, proto, laddr, lport, raddr, rport, state in netscan.Netscan.calculate(self):
            if proto.find("UDP") == -1:
                net_list.append((net_object.Owner.UniqueProcessId.v(), proto, str(laddr), int(lport), str(raddr), int(rport), str(state)))
            else:
                net_list.append((net_object.Owner.UniqueProcessId.v(), proto, str(laddr), int(lport), str(raddr), 0, str(state))) # changed rport (from "*" to 0) in UDP entry

        records = list(set(net_list))
        self.cur.executemany("insert or ignore into netinfo values (?, ?, ?, ?, ?, ?, ?)", records)

        self.update_all_done('netinfo')
        if is_protocol:
            return [record[1] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_laddr:
            return [record[2] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_lport:
            return [record[3] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_raddr:
            return [record[4] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_rport:
            return [record[5] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_state:
            return [record[6] for record in records if self.process.UniqueProcessId.v() == record[0]]

        return None

    def PortList_PortItem_localPort(self, content, condition, preserve_case):
        if not self.util.is_condition_integer(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/localPort'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            lports = self.fetchall_from_db_by_pid('netinfo', 'lport')
        else:
            lports = self.extract_netinfo(is_lport=True)
            if lports is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_integers(lports, content, condition, preserve_case)

    def PortList_PortItem_remotePort(self, content, condition, preserve_case):
        if not self.util.is_condition_integer(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/localPort'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            rports = self.fetchall_from_db_by_pid('netinfo', 'rport')
        else:
            rports = self.extract_netinfo(is_rport=True)
            if rports is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_integers(rports, content, condition, preserve_case)

    def PortList_PortItem_localIP(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/localIP'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            laddrs = self.fetchall_from_db_by_pid('netinfo', 'laddr')
        else:
            laddrs = self.extract_netinfo(is_laddr=True)
            if laddrs is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(laddrs, content, condition, preserve_case)

    def PortList_PortItem_remoteIP(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/remoteIP'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            raddrs = self.fetchall_from_db_by_pid('netinfo', 'raddr')
        else:
            raddrs = self.extract_netinfo(is_raddr=True)
            if raddrs is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(raddrs, content, condition, preserve_case)

    def hidden(self, content, condition, preserve_case):
        if not self.util.is_condition_bool(condition):
            debug.error('{0} condition is not supported in ProcessItem/hidden'.format(condition))
            return False

        result = self.fetchone_from_db_by_pid('hidden', 'result')
        if (result and content.lower() == 'true') or ((not result) and content.lower() == 'false'):
            return True
        else:
            return False

    # based on apihooks
    def extract_hooked_APIs(self, is_API=False, is_hookingMod=False):
        debug.info("[time-consuming task] extracting hooked APIs... (pid={0})".format(self.process.UniqueProcessId))

        process_space = self.process.get_process_address_space()
        if not process_space:
            return []

        module_group = apihooks.ModuleGroup(self.process.get_load_modules())

        records = []
        for dll in module_group.mods:
            if not process_space.is_valid_address(dll.DllBase):
                continue
            for hook in self.get_hooks(HOOK_MODE_USER, process_space, dll, module_group):
                if self.whitelist(hook.hook_mode | hook.hook_type, self.process.ImageFileName.v(), hook.VictimModule, hook.HookModule, hook.Function):
                    continue
                records.append((self.process.UniqueProcessId.v(), hook.Mode, hook.Type, str(dll.BaseDllName or ''), hook.Function, hook.HookModule))
        self.cur.executemany("insert or ignore into api_hooked values (?, ?, ?, ?, ?, ?)", records)
        self.update_done('api_hooked')
        if is_API:
            return [record[4] for record in records]
        elif is_hookingMod:
            return [record[5] for record in records]

    def Hooked_API_FunctionName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/Hooked/API/FunctionName'.format(condition))
            return False

        (done,) = self.check_done('api_hooked')
        if int(done):
            hooked_funcs = self.fetchall_from_db_by_pid('api_hooked', 'hooked_func')
        else:
            hooked_funcs = self.extract_hooked_APIs(is_API=True)
        return self.util.check_strings(hooked_funcs, content, condition, preserve_case)

    def Hooked_API_HookingModuleName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/Hooked/API/HookingModuleName'.format(condition))
            return False

        (done,) = self.check_done('api_hooked')
        if int(done):
            hooking_mods = self.fetchall_from_db_by_pid('api_hooked', 'hooking_module')
        else:
            hooking_mods = self.extract_hooked_APIs(is_hookingMod=True)
        return self.util.check_strings(hooking_mods, content, condition, preserve_case)

    # based on privileges
    def extract_privileges(self):
        debug.info("[time-consuming task] extracting enabled privilege information... (pid={0})".format(self.process.UniqueProcessId))
        records = []

        for value, present, enabled, default in self.process.get_token().privileges():
            try:
                name, desc = PRIVILEGE_INFO[int(value)]
            except KeyError:
                continue

            if enabled:
                records.append((self.process.UniqueProcessId.v(), name))

        self.cur.executemany("insert or ignore into privs values (?, ?)", records)
        self.update_done('privs')
        return [record[1] for record in records]

    def EnabledPrivilege_Name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/EnabledPrivilege/Name'.format(condition))
            return False

        (done,) = self.check_done('privs')
        if int(done):
            privs = self.fetchall_from_db_by_pid('privs', 'priv')
        else:
            privs = self.extract_privileges()
        return self.util.check_strings(privs, content, condition, preserve_case)

class RegistryItem(hivelist.HiveList, shimcache.ShimCache):
    def __init__(self, cur, _config):
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()
        self.reg_path_list = []

    def get_path(self, keypath, key):
        if key.Name != None:
            self.reg_path_list.append('{0}'.format(keypath + "\\" + key.Name))
        for k in rawreg.subkeys(key):
            self.get_path(keypath + "\\" + key.Name, k)
        for v in rawreg.values(key):
            if key.Name != None:
                self.reg_path_list.append('{0}'.format(keypath + "\\" + key.Name + "\\" + v.Name))

    def Path(self, content, condition, preserve_case):
        debug.error('RegistryItem/Path is currently disabled because it takes toooo long time :-(')
        return False
        '''
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in RegistryItem/Path'.format(condition))
            return False

        paths = []
        count = self.util.fetchone_from_db(self.cur, "regpath", "count(*)")
        if count > 0:
            paths = self.util.fetchall_from_db(self.cur, "regpath", "path")
        else:
            debug.info("[time-consuming task] extracting registry key/value paths...")
            debug.warning('Please redefine using process handle name instead of this term because it will take too long time :-(')
            hive_offsets = []
            for hive in hivelist.HiveList.calculate(self):
                if hive.Hive.Signature == 0xbee0bee0 and hive.obj_offset not in hive_offsets:
                    hive_offsets.append(hive.obj_offset)
                    h = hivemod.HiveAddressSpace(self.kernel_space, self._config, hive.obj_offset)
                    #key = rawreg.open_key(rawreg.get_root(h), 'software\\microsoft\\windows\\currentversion\\run'.split('\\')) # <- for test
                    #if key:
                    #    self.get_path('', key)
                    self.get_path('', rawreg.get_root(h))
            paths = list(set(self.reg_path_list))
            self.cur.executemany("insert or ignore into regpath values (?)", [(path, ) for path in paths])
        return self.util.check_strings(paths, content, condition, preserve_case)
        '''

    def ShimCache_ExecutablePath(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in RegistryItem/ShimCache/ExecutablePath'.format(condition))
            return False

        paths = []
        records = []
        count = self.util.fetchone_from_db(self.cur, "shimcache", "count(*)")
        if count > 0:
            paths = self.util.fetchall_from_db(self.cur, "shimcache", "path")
        else:
            debug.info("[time-consuming task] extracting shimcache registry information...")
            for path, modified, updated in shimcache.ShimCache.calculate(self):
                path_str ='{0}'.format(path)
                records.append((path_str, modified.v()))
            if len(records) == 0:
                records.append(('dummy', 'dummy')) # insert dummy for done
            self.cur.executemany("insert or ignore into shimcache values (?, ?)", records)
            paths = [record[0] for record in records]
        return self.util.check_strings(paths, content, condition, preserve_case)

class ServiceItem(svcscan.SvcScan):
    def __init__(self, cur, _config):
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()

    def extract_services(self, is_service_name=False, is_display_name=False, is_bin_path=False):
        debug.info("[time-consuming task] extracting service information...")

        records = []
        for rec in svcscan.SvcScan.calculate(self):
            service_name = '{0}'.format(rec.ServiceName.dereference())
            display_name = '{0}'.format(rec.DisplayName.dereference())
            bin_path = '{0}'.format(rec.Binary)
            records.append((service_name, display_name, bin_path))
        self.cur.executemany("insert or ignore into service values (?, ?, ?)", records)

        if is_service_name:
            return [record[0] for record in records]
        elif is_display_name:
            return [record[1] for record in records]
        elif is_bin_path:
            return [record[2] for record in records]

    def name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ServiceItem/name'.format(condition))
            return False

        count = self.util.fetchone_from_db(self.cur, "service", "count(*)")
        if count > 0:
            service_names = self.util.fetchall_from_db(self.cur, "service", "service_name")
        else:
            service_names = self.extract_services(is_service_name=True)
            if service_names is None:
                debug.error('cannot get service information')
        return self.util.check_strings(service_names, content, condition, preserve_case)

    def descriptiveName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ServiceItem/descriptiveName'.format(condition))
            return False

        count = self.util.fetchone_from_db(self.cur, "service", "count(*)")
        if count > 0:
            display_names = self.util.fetchall_from_db(self.cur, "service", "display_name")
        else:
            display_names = self.extract_services(is_display_name=True)
            if display_names is None:
                debug.error('cannot get service information')
        return self.util.check_strings(display_names, content, condition, preserve_case)

    def cmdLine(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ServiceItem/cmdLine'.format(condition))
            return False

        count = self.util.fetchone_from_db(self.cur, "service", "count(*)")
        if count > 0:
            cmdlines = self.util.fetchall_from_db(self.cur, "service", "bin_path")
        else:
            cmdlines = self.extract_services(is_bin_path=True)
            if cmdlines is None:
                debug.error('cannot get service information')
        return self.util.check_strings(cmdlines, content, condition, preserve_case)

#class DriverItem(modules.Modules, modules.UnloadedModules, modscan.ModScan, impscan.ImpScan):
class DriverItem(impscan.ImpScan, devicetree.DriverIrp, callbacks.Callbacks, timers.Timers):
    def __init__(self, kmod, cur, _config):
        self.kmod = kmod
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()
        self.forwarded_imports = { # copied from impscan
            "RtlGetLastWin32Error" : "kernel32.dll!GetLastError",
            "RtlSetLastWin32Error" : "kernel32.dll!SetLastError",
            "RtlRestoreLastWin32Error" : "kernel32.dll!SetLastError",
            "RtlAllocateHeap" : "kernel32.dll!HeapAlloc",
            "RtlReAllocateHeap" : "kernel32.dll!HeapReAlloc",
            "RtlFreeHeap" : "kernel32.dll!HeapFree",
            "RtlEnterCriticalSection" : "kernel32.dll!EnterCriticalSection",
            "RtlLeaveCriticalSection" : "kernel32.dll!LeaveCriticalSection",
            "RtlDeleteCriticalSection" : "kernel32.dll!DeleteCriticalSection",
            "RtlZeroMemory" : "kernel32.dll!ZeroMemory",
            "RtlSizeHeap" : "kernel32.dll!HeapSize",
            "RtlUnwind" : "kernel32.dll!RtlUnwind",
            }

    def fetchall_from_db_by_base(self, table, column):
        name = str(self.kmod.BaseDllName  or '')
        base_addr = self.kmod.DllBase
        debug.debug("fetchall: {0} already done. Results reused (name={1}, base=0x{2:x})".format(table, name, base_addr))
        sql = "select {0} from {1} where base = ?".format(column, table)
        #self.cur.execute(sql, (base_addr.v(),))
        self.cur.execute(sql, (str(base_addr.v()),)) # for unsigned long ("OverflowError: Python int too large to convert to SQLite INTEGER")
        return [record[0] for record in self.cur.fetchall()]

    def fetchone_from_db_by_base(self, table, column):
        name = str(self.kmod.BaseDllName  or '')
        base_addr = self.kmod.DllBase
        debug.debug("fetchone: {0} from {1} (name={2}, base=0x{3:x})".format(column, table, name, base_addr))
        sql = "select {0} from {1} where base = ?".format(column, table)
        #self.cur.execute(sql, (base_addr.v(),))
        self.cur.execute(sql, (str(base_addr.v()),))
        return self.cur.fetchone()[0]

    def DriverName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in DriverItem/DriverName'.format(condition))
            return False
        return self.util.check_string(str(self.kmod.BaseDllName  or ''), content, condition, preserve_case)

    def get_data(self):
        base_address = self.kmod.DllBase
        size_to_read = self.kmod.SizeOfImage
        data = ""
        mod_filepath = os.path.join(g_cache_path, 'kmod_0x{0:x}'.format(self.kmod.DllBase)) + '.sys'

        if os.path.exists(mod_filepath):
            with open(mod_filepath, 'rb') as f:
                data = f.read()
        else:
            if not size_to_read:
                pefile = obj.Object("_IMAGE_DOS_HEADER",
                                    offset = base_address,
                                    vm = self.kernel_space)
                try:
                    nt_header = pefile.get_nt_header()
                    size_to_read = nt_header.OptionalHeader.SizeOfImage
                except ValueError:
                    pass
                if not size_to_read:
                    debug.warning('cannot get size info (kernel module name={0} base=0x{1:x})'.format(str(self.kmod.BaseDllName  or ''), self.kmod.DllBase))

            procs = list(tasks.pslist(self.kernel_space))
            kernel_space = tasks.find_space(self.kernel_space, procs, base_address) # for some GUI drivers (e.g., win32k.sys)
            if not kernel_space:
                debug.warning('Cannot read supplied address (kernel module name={0} base=0x{1:x})'.format(str(self.kmod.BaseDllName  or ''), self.kmod.DllBase))
            else:
                data = kernel_space.zread(base_address, size_to_read)
            with open(mod_filepath, 'wb') as f:
                f.write(data)

        return base_address, size_to_read, data

    # based on impscan
    def PEInfo_ImportedModules_Module_ImportedFunctions_string(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in DriverItem/PEInfo/ImportedModules/Module/ImportedFunctions/string'.format(condition))
            return False

        imp_funcs = []
        count = self.fetchone_from_db_by_base("kernel_mods_impfunc", "count(*)")
        if count > 0:
            imp_funcs = self.fetchall_from_db_by_base("kernel_mods_impfunc", "func_name")
        else:
            debug.info("[time-consuming task] extracting import functions... (kernel module name={0} base=0x{1:x})".format(str(self.kmod.BaseDllName  or ''), self.kmod.DllBase))
            records = []

            all_mods = list(win32.modules.lsmod(self.kernel_space))
            base_address, size_to_read, data = self.get_data()

            if data != '':
                apis = self.enum_apis(all_mods)
                procs = list(tasks.pslist(self.kernel_space))
                addr_space = tasks.find_space(self.kernel_space, procs, base_address) # for some GUI drivers (e.g., win32k.sys)

                calls_imported = dict(
                        (iat, call)
                        for (_, iat, call) in self.call_scan(addr_space, base_address, data)
                        if call in apis
                        )
                self._vicinity_scan(addr_space,
                        calls_imported, apis, base_address, len(data),
                        forward = True)
                self._vicinity_scan(addr_space,
                        calls_imported, apis, base_address, len(data),
                        forward = False)

                for iat, call in sorted(calls_imported.items()):
                    mod_name, func_name = self._original_import(str(apis[call][0].BaseDllName or ''), apis[call][1])
                    #records.append((self.kmod.DllBase.v(), iat, call, mod_name, func_name))
                    records.append((str(self.kmod.DllBase.v()), str(iat), str(call), mod_name, func_name))
                    imp_funcs.append(func_name)

            if len(records) == 0:
                debug.info('inserting marker "done"... (kernel module name={0} base=0x{1:x})'.format(str(self.kmod.BaseDllName  or ''), self.kmod.DllBase))
                records.append((str(self.kmod.DllBase.v()), 0, 0, 'marker_done', 'marker_done'))
            self.cur.executemany("insert or ignore into kernel_mods_impfunc values (?, ?, ?, ?, ?)", records)

        return self.util.check_strings(imp_funcs, content, condition, preserve_case)

    def StringList_string(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in DriverItem/StringList/string'.format(condition))
            return False

        count = self.fetchone_from_db_by_base("kernel_mods_strings", "count(*)")
        strings = []
        records = []
        if count > 0:
            strings = self.fetchall_from_db_by_base("kernel_mods_strings", "string")
        else:
            debug.info("[time-consuming task] extracting strings... (kernel module name={0} base=0x{1:x})".format(str(self.kmod.BaseDllName  or ''), self.kmod.DllBase))
            base_address, size_to_read, data = self.get_data()
            if data != '':
                strings = list(set(self.util.extract_unicode(data) + self.util.extract_ascii(data)))
                records = [(str(self.kmod.DllBase.v()), string) for string in strings]
            if len(records) == 0:
                debug.info('inserting marker "done"... (kernel module name={0} base=0x{1:x})'.format(str(self.kmod.BaseDllName  or ''), self.kmod.DllBase))
                records.append((str(self.kmod.DllBase.v()), 'marker_done'))
            self.cur.executemany("insert or ignore into kernel_mods_strings values (?, ?)", records)

        result = self.util.check_strings(strings, content, condition, preserve_case)
        if result == False and condition == 'matches': # for searching binary sequences
            pattern = self.util.make_regex(content, preserve_case)
            base_address, size_to_read, data = self.get_data()
            if data != '' and pattern.search(data) is not None:
                result = True

        return result

    # based on devicetree.py
    def extract_IRP_info(self):
        debug.info("[time-consuming task] extracting hooking module names in IRP array...")

        records = []
        # added for default option values (AbstractScanCommand)
        self._config.VIRTUAL = False
        self._config.SHOW_UNALLOCATED = False
        self._config.START = None
        self._config.LENGTH = None

        mods = dict((self.kernel_space.address_mask(mod.DllBase), mod) for mod in win32.modules.lsmod(self.kernel_space))
        mod_addrs = sorted(mods.keys())

        for driver in devicetree.DriverIrp.calculate(self):
            header = driver.get_object_header()
            driver_name = str(header.NameInfo.Name or '')

            for i, function in enumerate(driver.MajorFunction):
                function = driver.MajorFunction[i]
                module = tasks.find_module(mods, mod_addrs, self.kernel_space.address_mask(function))
                if module:
                    module_name = str(module.BaseDllName or '')
                else:
                    module_name = "Unknown"
                #records.append((driver.DriverStart.v(), MAJOR_FUNCTIONS[i], function.v(), module_name))
                records.append((str(driver.DriverStart.v()), str(MAJOR_FUNCTIONS[i]), str(function.v()), module_name))

        self.cur.executemany("insert or ignore into kernel_mods_irp values (?, ?, ?, ?)", records)
        return [record[3] for record in records if self.kmod.DllBase.v() == record[0]]

    def IRP_HookingModuleName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in DriverItem/IRP/HookingModuleName'.format(condition))
            return False

        mod_names = []
        count = self.util.fetchone_from_db(self.cur, "kernel_mods_irp", "count(*)")
        if count > 0:
            mod_names = self.fetchall_from_db_by_base("kernel_mods_irp", "mod_name")
        else:
            mod_names = self.extract_IRP_info()
        return self.util.check_strings(mod_names, content, condition, preserve_case)

    # based on callbacks
    def extract_callbacks(self):
        debug.info("[time-consuming task] extracting kernel callbacks...")

        records = []
        # added for default option values (filescan)
        self._config.VIRTUAL = False
        self._config.SHOW_UNALLOCATED = False
        self._config.START = None
        self._config.LENGTH = None

        for (sym, cb, detail), mods, mod_addrs in callbacks.Callbacks.calculate(self):
            module = tasks.find_module(mods, mod_addrs, mods.values()[0].obj_vm.address_mask(cb))
            type_name = '{0}'.format(sym)
            #records.append((module.DllBase.v(), type_name, cb.v(), str(detail or "-")))
            records.append((str(module.DllBase.v()), type_name, str(cb.v()), str(detail or "-")))

        if len(records) == 0:
            records.append(('dummy', 'dummy', 'dummy', 'dummy')) # insert dummy for done
        self.cur.executemany("insert or ignore into kernel_mods_callbacks values (?, ?, ?, ?)", records)
        return [record[1] for record in records if self.kmod.DllBase.v() == record[0]]

    def CallbackRoutine_Type(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in DriverItem/CallbackRoutine/Type'.format(condition))
            return False

        types = []
        count = self.util.fetchone_from_db(self.cur, "kernel_mods_callbacks", "count(*)")
        if count > 0:
            types = self.fetchall_from_db_by_base("kernel_mods_callbacks", "type")
        else:
            types = self.extract_callbacks()
        return self.util.check_strings(types, content, condition, preserve_case)

    # based on timers
    def extract_timers(self):
        debug.info("[time-consuming task] extracting kernel timers...")

        records = []
        # added for default option value
        self._config.LISTHEAD = None

        for timer, module in timers.Timers.calculate(self):
            if timer.Header.SignalState.v():
                signaled = "Yes"
            else:
                signaled = "-"
            due_time = "{0:#010x}:{1:#010x}".format(timer.DueTime.HighPart, timer.DueTime.LowPart)
            #records.append((module.DllBase.v(), timer.obj_offset, due_time, timer.Period.v(), signaled, timer.Dpc.DeferredRoutine.v()))
            records.append((str(module.DllBase.v()), str(timer.obj_offset), due_time, timer.Period.v(), signaled, str(timer.Dpc.DeferredRoutine.v())))

        if len(records) == 0:
            records.append(('dummy', 'dummy', 'dummy', 'dummy', 'dummy', 'dummy')) # insert dummy for done
        self.cur.executemany("insert or ignore into kernel_mods_timers values (?, ?, ?, ?, ?, ?)", records)
        timer_routines = [record[5] for record in records if self.kmod.DllBase.v() == record[0]]
        return len(timer_routines)

    def TimerRoutineIncluded(self, content, condition, preserve_case):
        if not self.util.is_condition_bool(condition):
            debug.error('{0} condition is not supported in DriverItem/TimerRoutineIncluded'.format(condition))
            return False

        included = 0
        count = self.util.fetchone_from_db(self.cur, "kernel_mods_timers", "count(*)") # total
        if count > 0:
            included = self.fetchall_from_db_by_base("kernel_mods_timers", "count(*)")[0] # per kmod
        else:
            included = self.extract_timers()

        debug.debug('{0}={1}'.format(str(self.kmod.BaseDllName  or ''), included))
        if (included > 0 and content.lower() == 'true') or (included == 0 and content.lower() == 'false'):
            return True
        else:
            return False

class HookItem(ssdt.SSDT):
    def __init__(self, cur, _config):
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()

    # based on ssdt
    def extract_SSDT_hooked_functions(self):
        debug.info("[time-consuming task] extracting hooked entries in SSDT...")
        records = []

        # need to be modified in the future
        hooked_wl = ['win32k.sys', 'ntkrnlpa.exe', 'ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrpamp.exe']
        hooked_wl_inline = ['win32k.sys', 'ntkrnlpa.exe', 'ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrpamp.exe', 'hal.dll']

        addr_space = utils.load_as(self._config)
        syscalls = addr_space.profile.syscalls
        bits32 = addr_space.profile.metadata.get('memory_model', '32bit') == '32bit'

        for idx, table, n, vm, mods, mod_addrs in ssdt.SSDT.calculate(self):
            for i in range(n):
                if bits32:
                    syscall_addr = obj.Object('address', table + (i * 4), vm).v()
                else:
                    offset = obj.Object('long', table + (i * 4), vm).v()
                    syscall_addr = table + (offset >> 4)
                try:
                    syscall_name = syscalls[idx][i]
                except IndexError:
                    syscall_name = "UNKNOWN"

                syscall_mod = tasks.find_module(mods, mod_addrs, addr_space.address_mask(syscall_addr))
                if syscall_mod:
                    syscall_modname = syscall_mod.BaseDllName.v()
                else:
                    syscall_modname = "UNKNOWN"

                if syscall_modname.lower() not in hooked_wl:
                    records.append((idx, idx * 0x1000 + i, syscall_addr, syscall_name, syscall_modname, False))
                    continue

                hook_name = ''
                # for inline hook
                if (addr_space.profile.metadata.get('memory_model', '32bit') == '32bit' and syscall_mod is not None):
                    ret = apihooks.ApiHooks.check_inline(va = syscall_addr, addr_space = vm,
                                            mem_start = syscall_mod.DllBase,
                                            mem_end = syscall_mod.DllBase + syscall_mod.SizeOfImage)
                    if ret is not None:
                        (hooked, data, dest_addr) = ret
                        if hooked:
                            hook_mod = tasks.find_module(mods, mod_addrs, dest_addr)
                            if hook_mod:
                                hook_name = hook_mod.BaseDllName.v()
                            else:
                                hook_name = "UNKNOWN"

                            if hook_name.lower() not in hooked_wl_inline:
                                records.append((idx, idx * 0x1000 + i, dest_addr, syscall_name, hook_name, True))

        if len(records) == 0:
            records.append(('dummy', 'dummy', 'dummy', 'dummy', 'dummy', 'dummy')) # insert dummy for done
        self.cur.executemany("insert or ignore into ssdt_hooked values (?, ?, ?, ?, ?, ?)", records)
        return [record[3] for record in records]

    def SSDT_HookedFunctionName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in HookItem/SSDT/HookedFunctionName'.format(condition))
            return False

        syscall_names = []
        count = self.util.fetchone_from_db(self.cur, "ssdt_hooked", "count(*)")
        if count > 0:
            syscall_names = self.util.fetchall_from_db(self.cur, "ssdt_hooked", "syscall_name")
        else:
            syscall_names = self.extract_SSDT_hooked_functions()
        return self.util.check_strings(syscall_names, content, condition, preserve_case)

class FileItem(mftparser.MFTParser):
    def __init__(self, cur, _config):
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()

    # based on mftparser
    def extract_MFT_entries(self, is_inode=False, is_name=False, is_extension=False, is_path=False, is_size=False):
        debug.info("[time-consuming task] extracting NTFS MFT entries...")
        records = []

        # added for default option values (mftparser)
        self._config.MACHINE = ""
        self._config.OFFSET = None
        self._config.ENTRYSIZE = 1024
        self._config.DEBUGOUT = False
        self._config.NOCHECK = False

        for offset, mft_entry, attributes in mftparser.MFTParser.calculate(self):
            full = ""
            for a, i in attributes:
                size = -1
                if a.startswith("FILE_NAME"):
                    if hasattr(i, "ParentDirectory"):
                        name = mft_entry.remove_unprintable(i.get_name()) or "(Null)"
                        if len(name.split('.')) > 1:
                            ext = name.split('.')[-1]
                        else:
                            ext = ''
                        full = mft_entry.get_full_path(i)
                        #size = int(i.RealFileSize)
                        size = str(i.RealFileSize.v())
                        debug.debug('NTFS file info from MFT entry $FN: name={0}, ext={1}, full={2}'.format(name, ext, full))
                        records.append((offset, mft_entry.RecordNumber.v(), name, ext, full, size))

        if len(records) == 0:
            records.append((0, 0, 'dummy', 'dummy', 'dummy', 0)) # insert dummy for done
        self.cur.executemany("insert or ignore into files values (?, ?, ?, ?, ?, ?)", records)

        if is_inode:
            return [record[1] for record in records]
        elif is_name:
            return [record[2] for record in records]
        elif is_extension:
            return [record[3] for record in records]
        elif is_path:
            return [record[4] for record in records]
        elif is_size:
            #return [record[5] for record in records]
            return [long(record[5]) for record in records]

    def INode(self, content, condition, preserve_case):
        if not self.util.is_condition_integer(condition):
            debug.error('{0} condition is not supported in FileItem/INode'.format(condition))
            return False

        ent_nums = []
        count = self.util.fetchone_from_db(self.cur, "files", "count(*)")
        if count > 0:
            ent_nums = self.util.fetchall_from_db(self.cur, "files", "inode")
        else:
            ent_nums = self.extract_MFT_entries(is_inode=True)
        return self.util.check_integers(ent_nums, content, condition, preserve_case)

    def FileName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in FileItem/FileName'.format(condition))
            return False

        names = []
        count = self.util.fetchone_from_db(self.cur, "files", "count(*)")
        if count > 0:
            names = self.util.fetchall_from_db(self.cur, "files", "name")
        else:
            names = self.extract_MFT_entries(is_name=True)
        return self.util.check_strings(names, content, condition, preserve_case)

    def FileExtension(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in FileItem/FileExtension'.format(condition))
            return False

        exts = []
        count = self.util.fetchone_from_db(self.cur, "files", "count(*)")
        if count > 0:
            exts = self.util.fetchall_from_db(self.cur, "files", "extension")
        else:
            exts = self.extract_MFT_entries(is_extension=True)
        return self.util.check_strings(exts, content, condition, preserve_case)

    def FullPath(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in FileItem/FullPath'.format(condition))
            return False

        paths = []
        count = self.util.fetchone_from_db(self.cur, "files", "count(*)")
        if count > 0:
            paths = self.util.fetchall_from_db(self.cur, "files", "path")
        else:
            paths = self.extract_MFT_entries(is_path=True)
        return self.util.check_strings(paths, content, condition, preserve_case)

    def SizeInBytes(self, content, condition, preserve_case):
        if not self.util.is_condition_integer(condition):
            debug.error('{0} condition is not supported in FileItem/SizeInBytes'.format(condition))
            return False

        sizes = []
        count = self.util.fetchone_from_db(self.cur, "files", "count(*)")
        if count > 0:
            sizes = self.util.fetchall_from_db(self.cur, "files", "size")
        else:
            sizes = self.extract_MFT_entries(is_size=True)
        return self.util.check_integers(sizes, content, condition, preserve_case)

class IOCParseError(Exception):
    pass

class IOC_Scanner:
    def __init__(self):
        self.iocs = {} # elementTree representing the IOC
        self.ioc_name = {} # guid -> name mapping
        self.level = 1 # xml hierarchical level in the IOC
        self.iocEvalString = '' # AND/OR logic of the IOC evaluation
        self.iocLogicString = '' # AND/OR logic result for display
        self.item_obj = None
        self.display_mode = False
        self.cur = None
        self._config = None
        self.items = {'Process':None, 'Registry':None, 'Service':None, 'Driver':None, 'Hook':None, 'File':None}
        self.checked_results = {} # for repeatedly checked Items except ProcessItem and DriverItem
        self.total_score = 0

    def __len__(self):
        return len(self.iocs)

    def insert(self, filename):
        errors = []
        if os.path.isfile(filename):
            debug.info('loading IOC from: {0}'.format(filename))
            try:
                self.parse(ioc_api.IOC(filename))
            except ioc_api.IOCParseError,e:
                debug.error('Parse Error [{0}]'.format(e))
        elif os.path.isdir(filename):
            debug.info('loading IOCs from: {0}'.format(filename))
            for fn in glob.glob(filename+os.path.sep+'*.ioc'):
                if not os.path.isfile(fn):
                    continue
                else:
                    try:
                        self.parse(ioc_api.IOC(fn))
                    except ioc_api.IOCParseError,e:
                        debug.error('Parse Error [{0}]'.format(str(e)))
        else:
            pass
        debug.info('Parsed [{0}] IOCs'.format(str(len(self))))
        return errors

    def parse(self, ioc_obj):
        if ioc_obj is None:
            return
        iocid = ioc_obj.root.get('id')
        if iocid in self.iocs:
            debug.error('duplicate IOCs (UUID={0})'.format(iocid))

        # check items
        try:
            ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
        except IndexError, e:
            debug.warning('Could not find criteria nodes for IOC [{0}]. '.format(str(iocid)))
            return
        for document in ioc_logic.xpath('//Context/@document'):
            item_name = document[:-4]
            if not item_name in self.items.keys():
                debug.error('Not supported item = {0} in IOC [{1}]. '.format(document, str(iocid)))
                return

        self.iocs[iocid] = ioc_obj
        return True

    def prepare(self, cur, _config):
        self.cur = cur
        self._config = _config

    def with_item(self, iocid, name):
        ioc_obj = self.iocs[iocid]
        ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
        if len(ioc_logic.xpath('//Context[@document="{0}Item"]'.format(name))) > 0:
            return True
        else:
            return False

    def with_item_all(self, name):
        for iocid in self.iocs:
            if self.with_item(iocid, name):
                return True
        return False

    def check_indicator_item(self, node, params, is_last_item):
        iocResult = False
        global g_detail_on
        score = 0

        condition = node.get('condition')
        preserve_case = node.get('preserve-case')
        negate = node.get('negate')

        document = node.xpath('Context/@document')[0]
        search = node.xpath('Context/@search')[0]
        content = node.findtext('Content')
        logicOperator = str(node.getparent().get("operator")).lower()

        theid = node.get('id')
        param_desc = ''
        param_cnt = 0
        note = ''
        for refid, name, value in params:
            if theid == refid:
                if name == 'detail' and value == 'on':
                    g_detail_on = True
                    param_cnt += 1
                elif name == 'score':
                    score += int(value)
                    param_cnt += 1
                elif name == 'note':
                    param_cnt += 1
                    note = value
        if param_cnt > 0:
            param_desc = ' ('
            if g_detail_on:
                param_desc += 'detail=on;'
            if score > 0:
                param_desc += 'score={0};'.format(score)
            if note != '':
                param_desc += 'note="{0}";'.format(note)
            param_desc += ')'

        if negate == 'true':
            item_desc = 'Not ' + search + ' ' + condition + ' ' + content + param_desc
        else:
            item_desc = search + ' ' + condition + ' ' + content + param_desc

        if self.display_mode:
            if is_last_item:
                self.iocLogicString += '  '*self.level + item_desc + '\n'
            else:
                self.iocLogicString += '  '*self.level + item_desc + '\n' + '  '*self.level + str(logicOperator) + '\n'
            return

        method = '_'.join(search.split('/')[1:])
        item_name = document[:-4] # fetch '*' from '*Item'
        if not item_name in self.items.keys():
            debug.error('{0} not supported in this plugin'.format(document))
        if item_name != 'Process' and item_name != 'Driver' and self.items[item_name] is None:
            self.items[item_name] = eval('{0}(self.cur, self._config)'.format(document))
        if not method in dir(self.items[item_name]):
            debug.error('{0} not supported in this plugin'.format(search))

        the_term = search + content + condition + preserve_case
        if item_name != 'Process' and item_name != 'Driver' and (the_term) in self.checked_results.keys():
            debug.debug('reusing results about other Items except repeated ProcessItem/DriverItem ("{0}" = {1})'.format(the_term, self.checked_results[the_term]))
            iocResult = self.checked_results[the_term]
        else:
            iocResult = eval('self.items["{0}"].{1}(r"{2}","{3}","{4}")'.format(item_name, method, content, condition, preserve_case))
            #if negate == 'true' and iocResult == True:
            if negate == 'true':
                iocResult = not iocResult
        if item_name != 'Process' and item_name != 'Driver' and (the_term) not in self.checked_results.keys():
            self.checked_results[the_term] = iocResult

        if is_last_item:
            self.iocEvalString += ' ' + str(iocResult)
            if iocResult:
                self.iocLogicString += '  '*self.level + colorama.Style.BRIGHT + g_color_term + '>>> ' + item_desc + colorama.Fore.RESET + colorama.Style.RESET_ALL + '\n'
                self.total_score += score
            else:
                self.iocLogicString += '  '*self.level + item_desc + '\n'
        else:
            self.iocEvalString += ' ' + str(iocResult) + ' ' + str(logicOperator)
            if iocResult:
                self.iocLogicString += '  '*self.level + colorama.Style.BRIGHT + g_color_term + '>>> '  + item_desc + colorama.Fore.RESET + colorama.Style.RESET_ALL + '\n' + '  '*self.level + str(logicOperator) + '\n'
                self.total_score += score
            else:
                self.iocLogicString += '  '*self.level + item_desc + '\n' + '  '*self.level + str(logicOperator) + '\n'

        g_detail_on = False

    def walk_indicator(self, node, params):
        expected_tag = 'Indicator'
        if node.tag != expected_tag:
            raise ValueError('node expected tag is [{0}]'.format(expected_tag))

        debug.debug('entering walk_indicator: {0}={1}'.format(node.get('id'), node.get('operator')))
        for chn in node.getchildren():
            chn_id = chn.get('id')

            if chn.tag == 'IndicatorItem':
                if chn == node.getchildren()[-1]:
                    self.check_indicator_item(chn, params, True)
                else:
                    self.check_indicator_item(chn, params, False)

            elif chn.tag == 'Indicator':
                debug.debug('parent id=operator: {0}={1}'.format(chn.getparent().get('id'), chn.getparent().get('operator')))
                operator = chn.get('operator').lower()
                if operator not in ['or', 'and']:
                    raise IOCParseError('Indicator@operator is not AND/OR. [{0}] has [{1}]'.format(chn_id, operator) )

                self.iocEvalString += ' ('
                self.iocLogicString += '  '*self.level + '(\n'
                self.level+=1

                self.walk_indicator(chn, params)

                self.level-=1
                logicOperator = str(chn.getparent().get("operator")).lower()
                if chn == node.getchildren()[-1]:
                    self.iocLogicString += '  '*self.level + ')\n'
                    self.iocEvalString += ' )'
                else:
                    '''
                    theid = chn.getparent().get('id')
                    print theid
                    for refid, name, value in params:
                        if theid == refid:
                            if name == 'note':
                                logicOperator += '(note="{0}")'.format(value)
                    '''
                    self.iocLogicString += '  '*self.level + ')\n' + '  '*self.level + str(logicOperator) + '\n'
                    self.iocEvalString += ' )' + ' ' + str(logicOperator)

            else:
                # should never get here
                raise IOCParseError('node is not a Indicator/IndicatorItem')

    def walk_parameter(self, node):
        expected_tag = 'parameters'
        if node.tag != expected_tag:
            raise ValueError('walk_parameter: node expected tag is [{0}]'.format(expected_tag))

        params = []
        for chn in node.getchildren():
            if chn.tag != 'param':
                raise ValueError('walk_parameter: chn expected tag is [param]')
            #theid = chn.get('id')
            refid = chn.get('ref-id')
            name = chn.get('name')
            value = chn.findtext('value')
            params.append((refid, name, value))

        return params

    def scan(self, iocid, process, kmod):
        result = ''

        if len(self) < 1:
            debug.error('no iocs available to scan')
            return result

        if process is not None:
            self.items['Process'] = ProcessItem(process, self.cur, self._config)
        if kmod is not None:
            self.items['Driver'] = DriverItem(kmod, self.cur, self._config)

        ioc_obj = self.iocs[iocid]

        try:
            ioc_params = ioc_obj.root.xpath('.//parameters')[0]
            #params = ioc_params.getchildren()[0]
        except IndexError, e:
            debug.debug('Could not find children for the top level parameters/children nodes for IOC [{0}]'.format(str(iocid)))
        else:
            params = self.walk_parameter(ioc_params)

        ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
        try:
            tlo = ioc_logic.getchildren()[0]
        except IndexError, e:
            debug.warning('Could not find children for the top level criteria/children nodes for IOC [{0}]'.format(str(iocid)))
            return result

        self.walk_indicator(tlo, params)
        debug.debug(self.iocEvalString)
        if eval(self.iocEvalString):
            result += 'IOC matched (by logic)! short_desc="{0}" id={1}\n'.format(ioc_obj.metadata.findtext('.//short_description'), iocid)
            result += 'logic (matched item is magenta-colored):\n{0}'.format(self.iocLogicString)
        elif self.total_score >= SCORE_THRESHOLD:
            result += 'IOC matched (by score)! short_desc="{0}" id={1}\n'.format(ioc_obj.metadata.findtext('.//short_description'), iocid)
            result += 'logic (matched item is magenta-colored):\n{0}'.format(self.iocLogicString)
        elif self._config.test:
            result += '[Test Mode for improving IOC] short_desc="{0}" id={1}\n'.format(ioc_obj.metadata.findtext('.//short_description'), iocid)
            result += 'logic (matched item is magenta-colored):\n{0}'.format(self.iocLogicString)
        self.iocEvalString=""
        self.iocLogicString=""
        self.total_score = 0

        self.items['Process'] = None
        self.items['Driver'] = None
        return result

    def display(self):
        self.display_mode = True
        result = ''

        if len(self) < 1:
            debug.error('no iocs to display')
            return result

        for iocid in self.iocs:
            ioc_obj = self.iocs[iocid]

            try:
                ioc_params = ioc_obj.root.xpath('.//parameters')[0]
                #params = ioc_params.getchildren()[0]
            except IndexError, e:
                debug.debug('Could not find children for the top level parameters/children nodes for IOC [{0}]'.format(str(iocid)))
            else:
                params = self.walk_parameter(ioc_params)

            ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
            try:
                tlo = ioc_logic.getchildren()[0]
            except IndexError, e:
                debug.warning('Could not find children for the top level criteria/children nodes for IOC [{0}]'.format(str(iocid)))
                continue

            self.walk_indicator(tlo, params)
            result += '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n'
            result += 'IOC definition \nshort_desc: {0} \ndesc: {1} \nid: {2}\n'.format(ioc_obj.metadata.findtext('.//short_description'), ioc_obj.metadata.findtext('.//description'), iocid)
            result += 'logic:\n{0}'.format(self.iocLogicString)
            self.iocLogicString=""

        return result

class OpenIOC_Scan(psxview.PsXview, taskmods.DllList):
    """Scan OpenIOC 1.1 based indicators"""
    meta_info = commands.Command.meta_info
    meta_info['author'] = 'Takahiro Haruyama'
    meta_info['copyright'] = 'Copyright (c) 2014 Takahiro Haruyama'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://takahiroharuyama.github.io/'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option = 'p', default = None,
                                help = 'Operate on these Process IDs (comma-separated)',
                                action = 'store', type = 'str')
        self._config.add_option('ioc_dir', short_option = 'i', default = None,
                               help = 'Location of IOCs directory',
                               action = 'store', type = 'str')
        self._config.add_option('show', short_option = 's', default = False,
                               help = 'Display IOC definition only',
                               action = 'store_true')
        self._config.add_option('cache_path', short_option = 'c', default = None,
                               help = 'Specify the cache folder path of analysis result',
                               action = 'store', type = 'str')
        self._config.add_option('kmod', short_option = 'm', default = None,
                               help = 'Operate on these kernel module names (comma-separated, case-insensitive)',
                               action = 'store', type = 'str')
        self._config.add_option('test', short_option = 't', default = False,
                               help = 'display all scan results for improving IOC',
                               action = 'store_true')
        self._config.add_option('erase', short_option = 'e', default = False,
                               help = 'erase cached db then scan',
                               action = 'store_true')
        self._config.add_option('not_carve', short_option = 'n', default = False,
                               help = 'not carve _EPROCESS object (fetch from linked list)',
                               action = 'store_true')
        self.db = None
        self.cur = None
        self.total_secs = 0

    def filter_tasks(self, tasks):
        if self._config.PID is None:
            return tasks

        try:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        except ValueError:
            debug.error("Invalid PID {0}".format(self._config.PID))

        return [t for t in tasks if t.UniqueProcessId in pidlist]

    def clear_tables(self):
        debug.info("Clearing the tables... (old DB or erase flag)")

        self.cur.execute("drop table if exists version")

        self.cur.execute("drop table if exists hidden")
        self.cur.execute("drop table if exists done")
        self.cur.execute("drop table if exists injected")
        self.cur.execute("drop table if exists strings")
        self.cur.execute("drop table if exists vaddump")
        self.cur.execute("drop table if exists impfunc")
        self.cur.execute("drop table if exists handles")
        self.cur.execute("drop table if exists netinfo")
        self.cur.execute("drop table if exists dllpath")
        self.cur.execute("drop table if exists api_hooked")
        self.cur.execute("drop table if exists privs")

        self.cur.execute("drop table if exists kernel_mods")
        self.cur.execute("drop table if exists kernel_mods_impfunc")
        self.cur.execute("drop table if exists kernel_mods_strings")
        self.cur.execute("drop table if exists kernel_mods_irp")
        self.cur.execute("drop table if exists kernel_mods_callbacks")
        self.cur.execute("drop table if exists kernel_mods_timers")

        self.cur.execute("drop table if exists regpath")
        self.cur.execute("drop table if exists shimcache")
        self.cur.execute("drop table if exists service")
        self.cur.execute("drop table if exists ssdt_hooked")
        self.cur.execute("drop table if exists files")

    def make_tables(self):
        debug.info("Making new DB tables...")

        self.cur.execute("create table if not exists version(version unique)")
        self.cur.execute("insert into version values(?)", (g_version,))

        self.cur.execute("create table if not exists hidden(pid unique, result, offset unique, cmdline)")
        self.cur.execute("create table if not exists done(pid unique, injected, strings, vaddump, impfunc, handles, netinfo, dllpath, api_hooked, privs)")
        self.cur.execute("create table if not exists injected(pid, start, size)")
        self.cur.execute("create table if not exists strings(pid, string)")
        self.cur.execute("create table if not exists vaddump(pid unique, size)")
        self.cur.execute("create table if not exists impfunc(pid, iat, call, mod_name, func_name)")
        self.cur.execute("create table if not exists handles(pid, type, name)")
        self.cur.execute("create table if not exists netinfo(pid, protocol, laddr, lport, raddr, rport, state)")
        self.cur.execute("create table if not exists dllpath(pid, path, hidden)")
        self.cur.execute("create table if not exists api_hooked(pid, mode, type, hooked_module, hooked_func, hooking_module)")
        self.cur.execute("create table if not exists privs(pid, priv)")

        self.cur.execute("create table if not exists kernel_mods(offset unique, name, base, size, fullname)")
        self.cur.execute("create table if not exists kernel_mods_impfunc(base, iat, call, mod_name, func_name)")
        self.cur.execute("create table if not exists kernel_mods_strings(base, string)")
        self.cur.execute("create table if not exists kernel_mods_irp(base, mj_func, addr, mod_name)")
        self.cur.execute("create table if not exists kernel_mods_callbacks(base, type, callback, detail)")
        self.cur.execute("create table if not exists kernel_mods_timers(base, offset, duetime, period, signaled, routine)")

        self.cur.execute("create table if not exists regpath(path unique)")
        self.cur.execute("create table if not exists shimcache(path, modified)")
        self.cur.execute("create table if not exists service(service_name, display_name, bin_path)")
        self.cur.execute("create table if not exists ssdt_hooked(table_idx, entry_idx, syscall_ptr, syscall_name, hooking_mod_name, inline_hooked)")
        self.cur.execute("create table if not exists files(offset, inode, name, extension, path, size)")

    def init_db(self, f_erase):
        global g_cache_path
        image_url = self._config.opts["location"]
        image_path = urllib.url2pathname(image_url.split('///')[1])

        if self._config.cache_path is None:
            g_cache_path = os.path.join(os.path.dirname(image_path), os.path.basename(image_path).split('.')[0] + '_cache')
            if not os.path.exists(g_cache_path):
                os.mkdir(g_cache_path)
        else:
            g_cache_path = self._config.cache_path
        self.db = sqlite3.connect(os.path.join(g_cache_path, os.path.basename(image_path).split('.')[0] + '.db'))
        self.cur = self.db.cursor()

        # version is null or not matched, make new tables
        self.cur.execute("select * from sqlite_master where type='table'")
        if self.cur.fetchone() == None:
            self.make_tables()
        else:
            self.cur.execute("select * from version")
            db_version = self.cur.fetchone()[0]
            if db_version != g_version or f_erase:
                self.clear_tables()
                self.make_tables()
            else:
                debug.info("Results in existing database loaded")

    def parse_cmdline(self, process):
        debug.debug(process.ImageFileName)
        #if (str(process.ImageFileName) != "System") and (not isinstance(process.Peb, obj.NoneObject)):
        if not isinstance(process.Peb.ProcessParameters.CommandLine.v(), obj.NoneObject):
            debug.debug('Hi pid={0}'.format(process.UniqueProcessId))
            cmdline = str(process.Peb.ProcessParameters.CommandLine).lower()
            debug.debug('name="{0}", cmdline="{1}" (pid{2})'.format(process.ImageFileName, cmdline or None, process.UniqueProcessId))
            if cmdline is not None:
                name_idx = cmdline.find(str(process.ImageFileName).lower())
                debug.debug('name_idx={0}'.format(name_idx))
                if name_idx != -1:
                    a = re.search(r'\.exe|\.msi|\.ocx|\.dll|\.cab|\.cat|\.js|\.vbs|\.scr', cmdline) # any other?
                    if a is not None:
                        debug.debug("name='{0}', path='{1}', arg='{2}' (pid{3})".format(process.ImageFileName, cmdline[:a.end()].strip('" '), cmdline[a.end():].strip('" '), process.UniqueProcessId))
                        return cmdline[:a.end()].strip('" '), cmdline[a.end():].strip('" ')
        return 'none', 'none'

    # based on psxview
    def extract_all_active_procs(self, not_carve):
        kernel_space = utils.load_as(self._config)
        flat_space = utils.load_as(self._config, astype = 'physical')
        self.cur.execute("select count(*) from hidden")
        carved = self.cur.fetchone()[0]

        procs = []
        if carved > 0:
            self.cur.execute("select offset from hidden")
            for record in self.cur.fetchall():
                if isinstance(self.virtual_process_from_physical_offset(kernel_space, record[0]), obj.NoneObject):
                    procs.append(obj.Object("_EPROCESS", offset = record[0], vm = flat_space))
                else:
                    procs.append(self.virtual_process_from_physical_offset(kernel_space, record[0]))
            #return [self.virtual_process_from_physical_offset(kernel_space, record[0]) for record in self.cur.fetchall()]
            #return [obj.Object("_EPROCESS", offset = record[0], vm = flat_space) for record in self.cur.fetchall()]
            #return [obj.Object("_EPROCESS", offset = record[0], vm = kernel_space) for record in self.cur.fetchall()]
        else:
            records = []
            procs = []
            if not_carve:
                debug.info('getting processes from linked list... (-n option enabled)')
                procs = list(tasks.pslist(kernel_space))
                for proc in procs:
                    cmdline = proc.Peb.ProcessParameters.CommandLine.v() or ''
                    offset = kernel_space.vtop(proc.obj_offset)
                    records.append((proc.UniqueProcessId.v(), False, offset, cmdline))
            else:
                debug.info("[time-consuming task] extracting all processes including hidden/dead ones...")
                all_tasks = list(tasks.pslist(kernel_space))
                ps_sources = {}
                ps_sources['pslist'] = self.check_pslist(all_tasks)
                ps_sources['psscan'] = self.check_psscan()
                #ps_sources['thrdproc'] = self.check_thrdproc(kernel_space)
                ps_sources['pspcid'] = self.check_pspcid(kernel_space)

                seen_offsets = []
                pids = []
                for source in ps_sources.values():
                    for offset in source.keys():
                        if offset not in seen_offsets:
                            seen_offsets.append(offset)
                            #if source[offset].ExitTime != 0: # exclude dead process even if it is included in process list
                            #if (source[offset].ExitTime != 0) and (not ps_sources['pslist'].has_key(offset)): # exclude dead process not included in process list <- cannot resolve from ethread!
                            #    continue
                            if isinstance(self.virtual_process_from_physical_offset(kernel_space, offset), obj.NoneObject):
                                ep = obj.Object("_EPROCESS", offset = offset, vm = flat_space)
                            else:
                                ep = self.virtual_process_from_physical_offset(kernel_space, offset)
                            if source[offset].UniqueProcessId not in pids: # cross view in crashdump file seems to be buggy (duplicated processes) :-(
                                result = not (ps_sources['pslist'].has_key(offset) and ps_sources['psscan'].has_key(offset) and ps_sources['pspcid'].has_key(offset))
                                if result == True and source[offset].ExitTime != 0:
                                    # I checked there were some dead processes without exit time, but I don't know other methods to judge them...
                                    result = False
                                cmdline = ep.Peb.ProcessParameters.CommandLine.v() or ''
                                if isinstance(ep.UniqueProcessId.v(), obj.NoneObject):
                                    debug.warning('skipping NoneObject from flat_space')
                                    continue
                                #pid = 0 if isinstance(ep.UniqueProcessId.v(), obj.NoneObject) else ep.UniqueProcessId.v()
                                records.append((ep.UniqueProcessId.v(), bool(result), offset, cmdline))
                                procs.append(ep)
                                pids.append(ep.UniqueProcessId)

            self.cur.executemany("insert or ignore into hidden values (?, ?, ?, ?)", records)
            debug.debug('{0} procs carved'.format(len(procs)))
        return procs

    def extract_all_loaded_kernel_mods(self):
        self.cur.execute("select count(*) from kernel_mods")
        cnt = self.cur.fetchone()[0]
        kernel_space = utils.load_as(self._config)

        if cnt > 0:
            self.cur.execute("select offset from kernel_mods")
            return [obj.Object("_LDR_DATA_TABLE_ENTRY", offset = record[0], vm = kernel_space) for record in self.cur.fetchall()]
        else:
            # currently get kernel modules from linked list because the result of modscan is noisy. need to improve for hidden malicious modules in the future
            debug.info("[time-consuming task] extracting all loaded kernel modules...")
            mods = list(win32.modules.lsmod(kernel_space))
            #records = [(mod.obj_offset, str(mod.BaseDllName  or ''), mod.DllBase.v(), mod.SizeOfImage.v(), str(mod.FullDllName or '')) for mod in mods]
            records = [(str(mod.obj_offset), str(mod.BaseDllName  or ''), str(mod.DllBase.v()), mod.SizeOfImage.v(), str(mod.FullDllName or '')) for mod in mods]
            self.cur.executemany("insert or ignore into kernel_mods values (?, ?, ?, ?, ?)", records)
            #for record in records:
            #    print record
            #    self.cur.execute("insert or ignore into kernel_mods values (?, ?, ?, ?, ?)", record)
            return mods

    def filter_mods(self, mods):
        if self._config.kmod is not None:
            try:
                modlist = [m.lower() for m in self._config.kmod.split(',')]
            except ValueError:
                debug.error("Invalid kmod option {0}".format(self._config.kmod))

            filtered_mods = [mod for mod in mods if str(mod.BaseDllName  or '').lower() in modlist]
            if len(filtered_mods) == 0:
                debug.error("Cannot find kernel module {0}.".format(self._config.kmod))
            return filtered_mods
        return mods

    def calculate(self):
        # load IOCs
        scanner = IOC_Scanner()
        if self._config.ioc_dir is None:
            debug.error("You should specify IOCs directory")
        scanner.insert(self._config.ioc_dir)

        # display mode
        if self._config.show:
            definitions = scanner.display()
            yield definitions
        else:
            self.init_db(self._config.erase)
            scanner.prepare(self.cur, self._config)
            procs = [None]
            kmods = [None]
            if scanner.with_item_all('Process'):
                with Timer() as t:
                    procs = self.extract_all_active_procs(self._config.not_carve)
                debug.debug("=> elapsed scan: {0}s for process carving".format(t.secs))
                self.total_secs += t.secs
                #print procs
                # pre-generated process entries in db for all updated tasks (e.g., netinfo)
                for process in self.filter_tasks(procs):
                    #pid = 0 if isinstance(process.UniqueProcessId.v(), obj.NoneObject) else process.UniqueProcessId.v()
                    self.cur.execute("insert or ignore into done values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (process.UniqueProcessId.v(), False, False, False, False, False, False, False, False, False))
            if scanner.with_item_all('Driver'):
                kmods = self.extract_all_loaded_kernel_mods()

            if len(procs) > 1:
                debug.info('{0} processes found'.format(len(procs)))
            if len(kmods) > 1:
                debug.info('{0} kernel modules found'.format(len(kmods)))
            self.db.commit() # save procs/mods into db

            for iocid in scanner.iocs:
                debug.info('Scanning iocid={0}'.format(iocid))
                if (not scanner.with_item(iocid, 'Process')) and (not scanner.with_item(iocid, 'Driver')):
                    debug.debug('Scanning... (Process=None, Driver=None)')
                    with Timer() as t:
                        result = scanner.scan(iocid, None, None)
                    debug.debug("=> elapsed scan: {0}s".format(t.secs))
                    self.total_secs += t.secs
                    if result != '':
                        yield None, None, result
                elif scanner.with_item(iocid, 'Process') and (not scanner.with_item(iocid, 'Driver')):
                    debug.debug('Scanning... (Driver=None)')
                    for process in self.filter_tasks(procs):
                        with Timer() as t:
                            result = scanner.scan(iocid, process, None)
                        debug.debug("=> elapsed scan: {0}s, pid={1}".format(t.secs, process.UniqueProcessId))
                        self.total_secs += t.secs
                        if result != '':
                            yield process, None, result
                elif (not scanner.with_item(iocid, 'Process')) and scanner.with_item(iocid, 'Driver'):
                    debug.debug('Scanning... (Process=None)')
                    for kmod in self.filter_mods(kmods):
                        with Timer() as t:
                            result = scanner.scan(iocid, None, kmod)
                        debug.debug("=> elapsed scan: {0}s, kmod={1}, kmod_base=0x{2:x}".format(t.secs, str(kmod.BaseDllName  or ''), kmod.DllBase))
                        self.total_secs += t.secs
                        if result != '':
                            yield None, kmod, result
                else:
                    debug.warning('Combination of ProcessItem and DriverItem will take very long time. If possible, define separately or specify PID/kmod.')
                    debug.debug('Scanning...')
                    for kmod in self.filter_mods(kmods):
                        for process in self.filter_tasks(procs):
                            with Timer() as t:
                                result = scanner.scan(iocid, process, kmod)
                            pid = ', pid={0}'.format(process.UniqueProcessId) if process is not None else ''
                            kmod_name = ', kmod={0}'.format(str(kmod.BaseDllName  or '')) if kmod is not None else ''
                            debug.debug("=> elapsed scan: {0}s{1}(base=0x{2:x}){3}".format(t.secs, kmod_name, kmod.DllBase, pid))
                            self.total_secs += t.secs
                            if result != '':
                                yield process, kmod, result
                self.db.commit()

    def render_text(self, outfd, data):
        if self._config.show:
            for definitions in data:
                outfd.write(definitions)
            outfd.write('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')
        else:
            for process, kmod, ioc_result in data:
                outfd.write('***************************************************************\n')
                outfd.write(ioc_result)
                if process is not None:
                    outfd.write("Note: ProcessItem was evaluated only in {0} (Pid={1})\n".format(process.ImageFileName, process.UniqueProcessId))
                if kmod is not None:
                    outfd.write("Note: DriverItem was evaluated only in {0} (base=0x{1:x})\n".format(str(kmod.BaseDllName  or ''), kmod.DllBase))
                outfd.write('***************************************************************\n')

            self.db.commit()
            self.cur.close()
            debug.info("=> elapsed scan total: about {0} s".format(self.total_secs))

