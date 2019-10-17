import sys
import re
import xml.etree.ElementTree as ET
import volatility.debug as debug
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.filescan as filescan
import volatility.plugins.dumpfiles as dumpfiles
import volatility.win32 as win32
import volatility.utils as utils
import volatility.plugins.common as common
from volatility.renderers import TreeGrid

# HKLM\Software\
SOFTWARE_RUN_KEYS = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]

# HKCU\
NTUSER_RUN_KEYS = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Run",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
]


# Active Setup only executes commands from the SOFTWARE hive
# See: https://helgeklein.com/blog/2010/04/active-setup-explained/
#      http://blogs.msdn.com/b/aruns_blog/archive/2011/06/20/active-setup-registry-key-what-it-is-and-how-to-create-in-the-package-using-admin-studio-install-shield.aspx
#      http://blog.spiderlabs.com/2014/07/backoff-technical-analysis.html
ACTIVE_SETUP_KEY = "Microsoft\\Active Setup\\Installed Components"


# Abusing MS Fix-It patches to ensure persistence
# References:
# https://www.blackhat.com/docs/asia-14/materials/Erickson/WP-Asia-14-Erickson-Persist-It-Using-And-Abusing-Microsofts-Fix-It-Patches.pdf
# http://blog.cert.societegenerale.com/2015/04/analyzing-gootkits-persistence-mechanism.html
APPCOMPAT_SDB_KEY = "Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"


# Winlogon Notification packages are supported in pre-Vista versions of Windows only
# See: http://technet.microsoft.com/en-us/library/cc721961(v=ws.10).aspx
WINLOGON_NOTIFICATION_EVENTS = [
    "Lock",
    "Logoff",
    "Logon",
    "Shutdown",
    "StartScreenSaver",
    "StartShell",
    "Startup",
    "StopScreenSaver",
    "Unlock",
]

WINLOGON_REGISTRATION_KNOWN_DLLS = [
    'crypt32.dll',
    'cryptnet.dll',
    'cscdll.dll',
    'dimsntfy.dll',
    'sclgntfy.dll',
    'wlnotify.dll',
    'wzcdlg.dll',
]

WINLOGON_COMMON_VALUES = {
    'Userinit': 'userinit.exe',
    'VmApplet': 'rundll32 shell32,Control_RunDLL "sysdm.cpl"',
    'Shell': 'Explorer.exe',
    'TaskMan': "Taskmgr.exe",
    'System': 'lsass.exe',
}

# Service key -> value maps
# Original list from regripper plugins, extra / repeated values from
# http://technet.microsoft.com/en-us/library/cc759275(v=ws.10).aspx
# http://www.atmarkit.co.jp/ait/articles/1705/01/news009_2.html (in Japanese)
# https://github.com/processhacker/processhacker/blob/master/phlib/svcsup.c
# https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-createservicea
# https://www.codemachine.com/downloads/win10/winnt.h
SERVICE_TYPES = {
    0x001: "Kernel driver",
    0x002: "File system driver",
    0x004: "Arguments for adapter",
    0x008: "File system driver",
    0x010: "Win32_Own_Process",
    0x020: "Win32_Share_Process",
    0x050: "User_Own_Process TEMPLATE",
    0x060: "User_Share_Process TEMPLATE",
    0x0D0: "User_Own_Process INSTANCE",
    0x0E0: "User_Share_Process INSTANCE",
    0x100: "Interactive",
    0x110: "Interactive",
    0x120: "Share_process Interactive",
    -1: "Unknown",
}

SERVICE_STARTUP = {
    0x00: "Boot Start",
    0x01: "System Start",
    0x02: "Auto Start",
    0x03: "Manual",
    0x04: "Disabled",
    -1: "Unknown",
}


def sanitize_path(path):
    # Clears the path of most equivalent forms
    if path:
        path = path.lower()
        path = path.replace("%systemroot%\\", '')
        path = path.replace("\\systemroot\\", '')
        path = path.replace("%windir%", '')
        path = path.replace("\\??\\", '')
        path = path.replace('\x00', '')
        path = path.replace('"', '').replace("'", '')
        return path

    else:
        return ''


def get_indented_dict(d, depth=0):
    output = ""
    for key in d:
        output += "{}{}: ".format(" " * depth * 2, key)
        if isinstance(d[key], dict):
            output += "\n" + get_indented_dict(d[key], depth + 1)
        elif isinstance(d[key], list):
            output += '\n'
            for e in d[key]:
                output += get_indented_dict(e, depth + 1)
        else:
            output += "{}\n".format(d[key])
    return output


class Autoruns(common.AbstractWindowsCommand):
    """Searches the registry and memory space for applications running at system startup and maps them to running processes"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("ASEP-TYPE", short_option='t', default=None,
                          help='Only collect the ASEP types specified. Select from: autoruns, services, appinit, winlogon, tasks, activesetup, sdb (comma-separated)',
                          action='store', type='str')
        config.remove_option("VERBOSE")
        config.add_option("VERBOSE", short_option='v', default=False,
                          help='Show entries that are normally filtered out (Ex. Services from the System32 folder)',
                          action='store_true')

        self.process_dict = {}
        self.autoruns = []
        self.services = []
        self.appinit_dlls = []
        self.winlogon = []
        self.winlogon_registrations = []
        self.tasks = []
        self.activesetup = []
        self.sdb = []

    def get_dll_list(self):
        addr_space = utils.load_as(self._config)
        task_objects = win32.tasks.pslist(addr_space)
        for task in task_objects:
            if task.Peb:
                self.process_dict[int(task.UniqueProcessId)] = (task, [m for m in task.get_load_modules()])

    # Matches a given module (executable, DLL) to a running process by looking either
    # in the CommandLine parameters or in the loaded modules
    def find_pids_for_imagepath(self, module):
        pids = []
        module = sanitize_path(module)
        if module:
            for pid in self.process_dict:
                # case where the image path matches the process' command-line information
                if self.process_dict[pid][0].Peb:
                    cmdline = self.process_dict[pid][0].Peb.ProcessParameters.CommandLine
                    if module in sanitize_path(str(cmdline or '[no cmdline]')):
                        pids.append(pid)

                # case where the module is actually loaded process (case for DLLs loaded by services)
                for dll in self.process_dict[pid][1]:
                    if module in sanitize_path(str(dll.FullDllName or '[no dllname]')):
                        pids.append(pid)

        return list(set(pids))

    # Returns [] or a list of tuples(dll, key path, key.LastWriteTime, [int(pids)])
    def get_appinit_dlls(self):

        debug.debug('Started get_appinit_dlls()')
        key_path="Microsoft\\Windows NT\\CurrentVersion\\Windows"
        results = []

        try:
            self.regapi.reset_current()
            key = self.regapi.reg_get_key(hive_name='software', key=key_path)
            appinit_values = self.regapi.reg_get_value(None, None, value='AppInit_DLLs', given_root=key)

        except Exception as e:
            debug.warning('get_appinit_dlls() failed to complete. Exception: {} {}'.format(type(e).__name__, e.args))

        else:
            if appinit_values:
                # Split on space or comma: https://msdn.microsoft.com/en-us/library/windows/desktop/dd744762(v=vs.85).aspx
                appinit_dlls = str(appinit_values).replace('\x00', '').replace(',', ' ').split(' ')
                results = [(dll, key_path, key.LastWriteTime, "AppInit_DLLs", self.find_pids_for_imagepath(dll)) for dll in appinit_dlls if dll]

        debug.debug('Finished get_appinit_dlls()')
        return results

    # Winlogon Notification packages are supported in pre-Vista versions of Windows only
    # See: http://technet.microsoft.com/fr-fr/library/cc721961(v=ws.10).aspx
    # returns [] or a list of tuples from parse_winlogon_registration_key()
    def get_winlogon_registrations(self):

        debug.debug('Started get_winlogon_registrations()')
        results = []
        notify_key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"

        try:
            self.regapi.reset_current()
            for subkey in self.regapi.reg_get_all_subkeys(hive_name='software', key=notify_key):
                parsed_entry = self.parse_winlogon_registration_key(subkey)
                if parsed_entry and (self._config.VERBOSE or (parsed_entry[0].split('\\')[-1] not in WINLOGON_REGISTRATION_KNOWN_DLLS)):
                    results.append(parsed_entry)

        except Exception as e:
            debug.warning('get_winlogon_registrations() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_winlogon_registrations()')
        return results

    # Returns None or (str(dllname), [(str(trigger)),str(event))], key.LastWriteTime, key path, [int(pids)])
    def parse_winlogon_registration_key(self, key):

        dllname = ""
        events = []
        pids = []
        key_path = self.regapi.reg_get_key_path(key) or str(key.Name)

        try:
            for v_name, v_data in self.regapi.reg_yield_values(hive_name=None, key=None, given_root=key):
                val_name = str(v_name or '')
                val_data = str(v_data or '').replace('\x00', '')

                if val_name.lower() == 'dllname':
                    dllname = val_data
                    pids = self.find_pids_for_imagepath(dllname)
                elif val_name in WINLOGON_NOTIFICATION_EVENTS:
                    events.append((val_name, val_data))

        except Exception as e:
            debug.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        if dllname:
            return (dllname, events, key.LastWriteTime, key_path, pids)

    # Returns [] or a list of tuples(val_name, val_data, key.LastWriteTime, expected_val_data, [int(pids)])
    def get_winlogon(self):

        debug.debug('Started get_winlogon()')
        winlogon = []
        winlogon_key_path="Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

        try:
            self.regapi.reset_current()
            key = self.regapi.reg_get_key(hive_name='software', key=winlogon_key_path)
            if key:
                for v_name, v_data in self.regapi.reg_yield_values(hive_name=None, key=None, given_root=key):
                    val_name = str(v_name or '')
                    val_data = str(v_data or '').replace('\x00', '')

                    if val_data and val_name in WINLOGON_COMMON_VALUES:
                        pids = self.find_pids_for_imagepath(val_data)
                        winlogon.append((val_name, val_data, key.LastWriteTime, WINLOGON_COMMON_VALUES[val_name], winlogon_key_path, pids))

        except Exception as e:
            debug.warning('get_winlogon() failed to complete. Exception: {} {}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_winlogon()')
        return winlogon

    # Returns [] or a list of tuples from parse_service_key()
    def get_services(self):

        debug.debug('Started get_services()')
        results = []
        service_key_path = "{}\\Services".format(self.currentcs)

        try:
            self.regapi.reset_current()
            for service_sk in self.regapi.reg_get_all_subkeys(hive_name='system', key=service_key_path):
                parsed_service = self.parse_service_key(service_sk)
                if parsed_service and (self._config.VERBOSE or 'system32' not in parsed_service[5].lower()):
                    results.append(parsed_service)

        except Exception as e:
            debug.warning('get_services() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_services()')
        return results

    # Returns None or (key_path, timestamp, display_name, SERVICE_STARTUP[startup], SERVICE_TYPES[type], image_path, service_dll, [int(pids)])
    def parse_service_key(self, service_key):

        try:
            values = {str(val_name): str(val_data).replace('\x00', '') for val_name, val_data in self.regapi.reg_yield_values(None, None, given_root=service_key)}

            image_path = values.get("ImagePath", '')
            display_name = values.get("DisplayName",'')
            service_dll = values.get("ServiceDll", '')
            main = values.get("ServiceMain", '')
            startup = int(values.get("Start", -1))
            type = int(values.get("Type", -1))
            timestamp = service_key.LastWriteTime
            key_path = self.regapi.reg_get_key_path(service_key) or str(service_key.Name)

            # Check if the service is not set to automatically start or does not have an image path
            # More details here: http://technet.microsoft.com/en-us/library/cc759637(v=ws.10).aspx
            if not image_path or startup not in [0, 1, 2]:
                return None

            if 'svchost.exe -k' in image_path.lower() or SERVICE_TYPES[type] == 'Share_Process':
                sk = self.regapi.reg_get_key(hive_name='system', key='Parameters', given_root=service_key)
                if sk and not service_dll:
                    timestamp = sk.LastWriteTime
                    service_dll = self.regapi.reg_get_value(hive_name='system', key='', value="ServiceDll", given_root=sk)
                    main = self.regapi.reg_get_value(hive_name='system', key='', value='ServiceMain', given_root=sk)

                if not service_dll and '@' in display_name:
                    timestamp = service_key.LastWriteTime
                    service_dll = display_name.split('@')[1].split(',')[0]

            if service_dll:
                service_dll = service_dll.replace('\x00', '')
                pids = self.find_pids_for_imagepath(service_dll)
                if main:
                    service_dll = "{} ({})".format(service_dll, main.replace('\x00', ''))
            else:
                pids = self.find_pids_for_imagepath(image_path)

        except Exception as e:
            debug.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        return (key_path, timestamp, display_name, SERVICE_STARTUP[startup], SERVICE_TYPES[type], image_path, service_dll, pids)

    # Returns [] or a list of tuples from parse_activesetup_keys()
    def get_activesetup(self):

        debug.debug('Started get_activesetup()')
        results = []

        try:
            self.regapi.reset_current()
            for subkey in self.regapi.reg_get_all_subkeys(hive_name='software', key=ACTIVE_SETUP_KEY):
                r = self.parse_activesetup_keys(subkey)
                if r:
                    results.append(r)

        except Exception as e:
            debug.warning('get_activesetup() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_activesetup()')
        return results

    # Returns None or a tuple(exe path, subkey.LastWriteTime, key path, [int(pids)])
    def parse_activesetup_keys(self, subkey):

        key_path = self.regapi.reg_get_key_path(subkey) or str(subkey.Name)

        try:
            stub_path_val = self.regapi.reg_get_value(hive_name='software', key='', value='StubPath', given_root=subkey)
            stub_path_val = str(stub_path_val or '').replace('\x00', '')
        except Exception as e:
            debug.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        if stub_path_val:
            pids = self.find_pids_for_imagepath(stub_path_val)
            return (stub_path_val, subkey.LastWriteTime, key_path, pids)

    # Returns [] or a list of tuples from parse_sdb_key()
    def get_sdb(self):

        debug.debug('Started get_sdb()')
        results = []

        try:
            self.regapi.reset_current()
            sdb_keys = self.regapi.reg_get_all_subkeys(hive_name='software', key=APPCOMPAT_SDB_KEY)
            for subkey in sdb_keys:
                parsed_sdb_entry = self.parse_sdb_key(subkey)
                if parsed_sdb_entry:
                    results.append(parsed_sdb_entry)

        except Exception as e:
            debug.warning('get_sdb() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_sdb()')
        return results

    #Returns None or a tuple(exe, db_path, subkey.LastWriteTime, key path, [int(pids)])
    def parse_sdb_key(self, subkey):

        key_path = self.regapi.reg_get_key_path(subkey) or str(subkey.Name)

        try:
            desc = sanitize_path(self.regapi.reg_get_value('software', '', 'DatabaseDescription', subkey) or '')
            db_path = sanitize_path(self.regapi.reg_get_value('software', '', 'DatabasePath', subkey) or '')
            pids = self.find_pids_for_imagepath(desc)
        except Exception as e:
            debug.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        if desc:
            return (desc, db_path, subkey.LastWriteTime, key_path, pids)

    # Returns [] or a list of tuples from parse_autoruns_key()
    def get_autoruns(self):

        debug.debug('Started get_autoruns()')
        results = []
        hive_key_list = []

        try:
            # Gather all software run keys
            self.regapi.reset_current()
            for run_key in SOFTWARE_RUN_KEYS:
                hive_key_list += [k for k in self.regapi.reg_yield_key(hive_name='software', key=run_key)]

            # Gather all ntuser run keys
            self.regapi.reset_current()
            for run_key in NTUSER_RUN_KEYS:
                hive_key_list += [k for k in self.regapi.reg_yield_key(hive_name='ntuser.dat', key=run_key)]

            # hive_key = (key pointer, hive_name)
            for hive_key in hive_key_list:
                results += self.parse_autoruns_key(hive_key)

        except Exception as e:
            debug.warning('get_autoruns() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_autoruns()')
        return results

    # Returns [] or a list of tuples(exe path, hive name, key path, key.LastWriteTime, value name, [int(pids)])
    def parse_autoruns_key(self, hive_key):

        results = []
        key = hive_key[0]
        hive_name = hive_key[1]
        key_path = self.regapi.reg_get_key_path(key) or str(key.Name)

        try:
            # val_data is the exe path
            for v_name, v_data in self.regapi.reg_yield_values(None, None, given_root=key):
                val_name = str(v_name or '')
                val_data = str(v_data or '').replace('\x00', '')

                if val_data:
                    pids = self.find_pids_for_imagepath(val_data)
                    results.append((val_data, hive_name, key_path, key.LastWriteTime, val_name, pids))

        except Exception as e:
            debug.warning('Failed while parsing {}. Exception: {} {}'.format(key_path, type(e).__name__, e.args))

        return results

    def get_tasks(self):

        debug.debug('Started get_tasks()')
        addr_space = utils.load_as(self._config)
        f = filescan.FileScan(self._config)
        tasks = []
        parsed_tasks = []

        try:
            for file in f.calculate():
                filename = str(file.file_name_with_device() or '')
                if "system32\\tasks\\" in filename.lower() and (('system32\\tasks\\microsoft' not in filename.lower() or self._config.VERBOSE)):
                    tasks.append((file.obj_offset, filename))
                    debug.debug("Found task: 0x{0:x} {1}".format(file.obj_offset, filename))

            for offset, name in tasks:

                self._config.PHYSOFFSET = '0x{:x}'.format(offset)
                df = dumpfiles.DumpFiles(self._config)
                self._config.DUMP_DIR = '.'
                for data in df.calculate():
                    # Doing this with mmap would probably be cleaner
                    # Create a sufficiently large (dynamically resizable?)
                    # memory map so that we can seek and write the file accordingly
                    #
                    # SystemError: mmap: resizing not available--no mremap()

                    chopped_file = {}

                    for mdata in data['present']:
                        rdata = addr_space.base.read(mdata[0], mdata[2])
                        chopped_file[mdata[1]] = rdata

                    task_xml = "".join(part[1] for part in sorted(chopped_file.items(), key=lambda x: x[0]))

                    parsed = self.parse_task_xml(task_xml, name)

                    if parsed:
                        args = parsed['Actions']['Exec'].get("Arguments", None)
                        if args:
                            parsed['Actions']['Exec']['Command'] += " {}".format(args)
                        pids = self.find_pids_for_imagepath(parsed['Actions']['Exec']['Command'])
                        parsed_tasks.append((name.split('\\')[-1], parsed, task_xml, pids))

        except Exception as e:
            debug.warning('get_tasks() failed to complete. Exception: {0} {1}'.format(type(e).__name__, e.args))

        debug.debug('Finished get_tasks()')
        return parsed_tasks

    def parse_task_xml(self, xml, f_name):
        raw = xml
        xml = re.sub('\x00\x00+', '', xml) + '\x00'
        if xml:
            try:
                xml = xml.decode('utf-16')
                xml = re.sub(r"<Task(.*?)>", "<Task>", xml)
                xml = xml.encode('utf-16')

                root = ET.fromstring(xml)
                d = {}

                for e in root.findall("./RegistrationInfo/Date"):
                    d['Date'] = e.text or ''
                for e in root.findall("./RegistrationInfo/Description"):
                    d['Description'] = e.text or ''
                for e in root.findall("./Actions"):
                    d['Actions'] = self.visit_all_children(e)
                for e in root.findall("./Settings/Enabled"):
                    d['Enabled'] = e.text or ''
                for e in root.findall("./Settings/Hidden"):
                    d['Hidden'] = e.text or ''
                for t in root.findall("./Triggers/*"):
                    d['Triggers'] = self.visit_all_children(t)

                if not d.get("Actions", {}).get('Exec', {}).get("Command", False):
                    return None

                return d
            except UnicodeDecodeError as e:
                debug.warning('Error while parsing the following task: {}'.format(f_name))
                debug.debug('UnicodeDecodeError for: {}'.format(repr(raw)))

    def visit_all_children(self, node):
        d = {}
        for c in node:
            d[c.tag] = self.visit_all_children(c)

        if node.text:
            if node.text.strip(' \t\n\r'):
                d = node.text.strip(' \t\n\r')
        return d

    def calculate(self):
        self.get_dll_list()
        self.regapi = registryapi.RegistryApi(self._config)
        self.currentcs = self.regapi.reg_get_currentcontrolset() or "ControlSet001"
        asep_list = ['autoruns', 'services', 'appinit', 'winlogon', 'tasks', 'activesetup', 'sdb']
        os_major = utils.load_as(self._config).profile.metadata.get('major', 0)

        # If all_offsets is empty then regapi was unable to find
        # hive offsets and we exit with an error message
        if not self.regapi.all_offsets:
            debug.error('Unable to find registry hives.')

        if self._config.ASEP_TYPE:
            debug.debug('Config: {}'.format(self._config.ASEP_TYPE))
            asep_list = [s for s in self._config.ASEP_TYPE.replace(' ', '').split(',')]

        # Scan for ASEPs and populate the lists
        if 'autoruns' in asep_list:
            self.autoruns = self.get_autoruns()
        if 'services' in asep_list:
            self.services = self.get_services()
        if 'appinit' in asep_list:
            self.appinit_dlls = self.get_appinit_dlls()
        if 'winlogon' in asep_list:
            self.winlogon = self.get_winlogon()
            if os_major == 5:
                self.winlogon_registrations = self.get_winlogon_registrations()
        if 'tasks' in asep_list:
            self.tasks = self.get_tasks()
        if 'activesetup' in asep_list:
            self.activesetup = self.get_activesetup()
        if 'sdb' in asep_list:
            self.sdb = self.get_sdb()

        #Returns a generator to generator() that generates the unified output data
        return self.get_unified_output_data()

    def get_unified_output_data(self):
        for exe_path, hive, key, timestamp, val_name, pids in self.autoruns:
            yield [exe_path,
                   'Autoruns',
                   timestamp,
                   val_name,
                   ", ".join([str(p) for p in pids]),
                   hive,
                   key,
                   val_name,
                   ""]
        for exe_path, key, timestamp, val_name, pids in self.appinit_dlls:
            yield [exe_path,
                   'AppInit Dlls',
                   timestamp,
                   '-',
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   val_name,
                   ""]
        for exe_path, events, timestamp, key, pids in self.winlogon_registrations:
            yield [exe_path,
                   'Winlogon (Notify)',
                   timestamp,
                   'Hooks: {0}'.format(", ".join([e[1] for e in events])),
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   "Dllname",
                   ""]
        for val_name, exe_path, timestamp, common_value, key, pids in self.winlogon:
            yield [exe_path,
                   'Winlogon ({})'.format(val_name),
                   timestamp,
                   "Default value: {}".format(common_value),
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   val_name,
                   ""]
        for key, timestamp, display_name, start, type, exe_path, entry, pids in self.services:
            yield [exe_path,
                   'Services',
                   timestamp,
                   "{0} - {1} ({2} - {3})".format(key.split('\\')[-1], display_name, type, start),
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SYSTEM",
                   key,
                   "",
                   entry]
        for name, task, task_xml, pids in self.tasks:
            yield [task['Actions']['Exec']['Command'],
                   'Scheduled Tasks',
                   task.get('Date', ""),
                   "{} ({})".format(name, task.get('Description', "N/A")),
                   ", ".join([str(p) for p in pids]),
                   "",
                   "",
                   "",
                   ""]
        for exe_path, timestamp, key, pids in self.activesetup:
            yield [exe_path,
                   "Active Setup",
                   timestamp,
                   "-",
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   "StubPath",
                   ""]
        for desc, exe_path, timestamp, key, pids in self.sdb:
            yield [exe_path,
                   "SDB",
                   timestamp,
                   desc,
                   ", ".join([str(p) for p in pids]),
                   "Windows/System32/config/SOFTWARE",
                   key,
                   "",
                   ""]

    def unified_output(self, data):
        """This standardizes the output formatting"""
        return TreeGrid([("Executable", str),
                        ("Source", str),
                        ("Last write time", str),
                        ("Details", str),
                        ("PIDs", str),
                        ("Hive", str),
                        ("Key", str),
                        ("Name", str),
                        ("Share Process Dll", str)],
                        self.generator(data))

    def generator(self, data):
        """This yields data according to the unified output format"""
        for executable, source, lastWriteTime, details, pids, hive, key, name, spDllPath in data:
            yield (0, [str(executable), str(source), str(lastWriteTime), str(details), str(pids), str(hive), str(key), str(name), str(spDllPath)])

    def render_table(self, outfd, data):
        self.table_header(outfd,
                          [("Executable", "<65"),
                           ("Source", "30"),
                           ("Last write time", "28"),
                           ("Details", "60"),
                           ("PIDs", "15")
                           ])

        for exe, source, timestamp, details, pids, hive, key, name, share_dll in data:
            if share_dll:
                exe = share_dll
            self.table_row(outfd, exe, source, timestamp, details, pids)

    def render_text(self, outfd, data):
        previous_source = ""
        for exe, source, timestamp, details, pids, hive, key, name, share_dll in data:
            if source != previous_source:
                outfd.write("\n\n")
                outfd.write("{:=<50}\n\n".format(source))

            if source == "Services":
                outfd.write("Service: {}\n".format(details))
                outfd.write("    Image path: {0} (Last modified: {1})\n".format(exe, timestamp))
                outfd.write("    PIDs: {}\n".format(pids))
                if share_dll:
                    outfd.write("    Loads: {}\n".format(share_dll))
            elif source == "Autoruns":
                outfd.write("Hive: {}\n".format(hive))
                outfd.write("    {0} (Last modified: {1})\n".format(key, timestamp))
                outfd.write("        {0:30} : {1} (PIDs: {2})\n".format(exe, details, pids))
            elif source == "Active Setup":
                outfd.write("Command line: {}\nLast-written: {} (PIDs: {})\n".format(exe, timestamp, pids))
            elif source == "SDB":
                previous_source = source
                continue
            elif source == "Winlogon (Notify)":
                outfd.write("{0} (Last write time: {1})\n".format(exe, timestamp))
                outfd.write("    PIDs: {}\n".format(pids))
                outfd.write("    {}\n".format(details))
            elif "Winlogon" in source:
                outfd.write("{0}: {1}\n".format(name, exe))
                outfd.write("    {}\n".format(details))
                outfd.write("    PIDs: {}\n".format(pids))
                outfd.write("    Last write time: {}\n".format(timestamp))
            elif source == "AppInit Dlls":
                outfd.write("Exe path: {}\n".format(exe))
                outfd.write("PIDS: {}\n".format(pids))
            elif source == "Scheduled Tasks":
                previous_source = source
                continue

            outfd.write("\n")
            previous_source = source

        if self.tasks:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Scheduled tasks "))
            for name, task, task_xml, pids in self.tasks:
                outfd.write("==== Task name: {} (PIDs: {})\n".format(name, ", ".join([str(p) for p in pids]) or "-"))
                outfd.write(get_indented_dict(task))
                outfd.write('\n')
                outfd.write("Raw XML:\n\n---------\n{}\n---------\n\n\n".format(task_xml))

        if self.sdb:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("SDB Fix-it patches "))
            for desc, path, timestamp, pids in self.sdb:
                outfd.write("Description: \"{}\"\nLast-written: {}\nPatch: {}\n\n".format(desc, timestamp, path))