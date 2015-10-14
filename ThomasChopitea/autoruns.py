import volatility.debug as debug
import volatility.win32.rawreg as rawreg
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.registry.hivelist as hivelist
import volatility.plugins.filescan as filescan
import volatility.plugins.dumpfiles as dumpfiles
import volatility.win32.hive as hivemod
import volatility.win32 as win32
import volatility.obj as obj
import volatility.utils as utils
import xml.etree.ElementTree as ET
import re
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


# Acitve Setup only executes commands from the SOFTWARE hive
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

WINLOGON_NOTIFICATION_EVENTS = [    "Lock",
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
service_types = { 0x001 : "Kernel driver",
                  0x002 : "File system driver",
                  0x004 : "Argumetns for adapter",
                  0x008 : "File system driver",
                  0x010 : "Own_Process",
                  0x020 : "Share_Process",
                  0x100 : "Interactive",
                  0x110 : "Interactive",
                  0x120 : "Share_process Interactive",
                     -1 : "Unknown" }

service_startup = {   0x00 : "Boot Start",
                      0x01 : "System Start",
                      0x02 : "Auto Start",
                      0x03 : "Manual",
                      0x04 : "Disabled",
                        -1 : "Unknown" }

def sanitize_paths(path):
    # Clears the path of most equivalent forms
    path = path.lower()
    path = path.replace("%systemroot%\\", '')
    path = path.replace("\\systemroot\\", '')
    path = path.replace("%windir%", '')
    path = path.replace("\\??\\", '')
    path = path.replace('\x00', '')
    path = path.replace('"', '').replace("'", '')
    return path

def get_indented_dict(d, depth=0):
    output = ""
    for key in d:
        output += "{}{}: ".format(" "*depth*2, key)
        if isinstance(d[key], dict):
            output += "\n" + get_indented_dict(d[key], depth+1)
        elif isinstance(d[key], list):
            output += '\n'
            for e in d[key]:
                output += get_indented_dict(e, depth+1)
        else:
            output += "{}\n".format(d[key])

    return output




class Autoruns(hivelist.HiveList):
    """Searches the registry and memory space for applications running at system startup and maps them to running processes"""
    def __init__(self, config, *args, **kwargs):
        hivelist.HiveList.__init__(self, config, *args, **kwargs)

        config.add_option("ASEP-TYPE", short_option = 't', default = None,
                          help = 'Show these ASEP types: autoruns, services, appinit, winlogon, tasks, sdb (comma-separated)',
                          action = 'store', type = 'str')

        config.add_option("VERBOSE", short_option = 'v', default = False,
                          help = 'Verbose output: display less relevant results',
                          action = 'store_true')

        self.regapi = registryapi.RegistryApi(self._config)

    def get_dll_list(self):
        addr_space = utils.load_as(self._config)
        task_objects = win32.tasks.pslist(addr_space)
        self.process_dict = {}
        for task in task_objects:
            if task.Peb:
                self.process_dict[int(task.UniqueProcessId)] = (task, [m for m in task.get_load_modules()])

    def find_pids_for_imagepath(self, module):
        pids = []
        # Matches a given module (executable, DLL) to a running process by looking either
        # in the CommandLine parameters or in the loaded modules
        module = sanitize_paths(module)
        if module:
            for pid in self.process_dict:
                # case where the image path matches the process' command-line information
                if self.process_dict[pid][0].Peb:
                    cmdline = self.process_dict[pid][0].Peb.ProcessParameters.CommandLine
                    if module.lower() in sanitize_paths(str(self.process_dict[pid][0].Peb.ProcessParameters.CommandLine or '[no cmdline]').lower()):
                        pids.append(pid)

                # case where the module is actually lodaded process (case for DLLs loaded by services)
                for dll in self.process_dict[pid][1]:
                    if module.lower() in sanitize_paths(str(dll.FullDllName or '[no dllname]').lower()):
                        pids.append(pid)

        return list(set(pids))

    def hive_name(self, hive):
        try:
            return hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
        except AttributeError:
            return "[no name]"

    def dict_for_key(self, key):
        # Inspired from the Volatility printkey plugin
        valdict = {}
        for v in rawreg.values(key):
            tp, data = rawreg.value_data(v)

            if tp == 'REG_BINARY' or tp == 'REG_NONE':
                data = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(data)])
            if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                data = data.encode("ascii", 'backslashreplace')
            if tp == 'REG_MULTI_SZ':
                for i in range(len(data)):
                    data[i] = data[i].encode("ascii", 'backslashreplace')

            valdict[str(v.Name)] = str(data)
        return valdict

    def get_appinit_dlls(self):

        self.regapi.set_current(hive_name = "software")
        appinit_values = self.regapi.reg_get_value(hive_name='software', key="Microsoft\\Windows NT\\CurrentVersion\\Windows", value='AppInit_DLLs')
        if appinit_values:
            appinit_dlls = appinit_values.replace('\x00', '').split(' ')

            if len(appinit_dlls) > 0:
                return appinit_dlls
            else:
                return None

    # Winlogon Notification packages are supported in pre-Vista versions of Windows only
    # See: http://technet.microsoft.com/fr-fr/library/cc721961(v=ws.10).aspx
    def get_winlogon_registrations(self):
        self.regapi.set_current(hive_name = "software")

        winlogon_registrations = []
        for subkey in self.regapi.reg_get_all_subkeys(hive_name = 'software', key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"):
            reg = self.parse_winlogon_registration_key(subkey)
            if reg:
                if (self._config.VERBOSE == True) or (self._config.VERBOSE == False and reg[0].split('\\')[-1] not in WINLOGON_REGISTRATION_KNOWN_DLLS):
                    winlogon_registrations.append(reg)

        return winlogon_registrations

    def get_winlogon(self):
        self.regapi.set_current(hive_name = "software")

        winlogon = []
        winlogon_key = self.regapi.reg_get_key(hive_name = 'software', key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        valdict = self.dict_for_key(winlogon_key)
        timestamp = winlogon_key.LastWriteTime

        for value in valdict:
            if value in WINLOGON_COMMON_VALUES:
                pids = self.find_pids_for_imagepath(valdict[value])
                winlogon.append((value, valdict[value].replace('\x00', ''), timestamp, WINLOGON_COMMON_VALUES[str(value)], pids))

        return winlogon

    def parse_winlogon_registration_key(self, key):
        k = self.dict_for_key(key)
        events = [(evt, k[evt].replace('\x00', '')) for evt in WINLOGON_NOTIFICATION_EVENTS if evt in k]

        dllname = ""
        for dictkey in k:
            if dictkey.lower() == 'dllname': # Nasty hack the variable "DLLName" has no consistent case
                dllname = k[dictkey]

        pids = []
        if dllname:
            pids = self.find_pids_for_imagepath(dllname)

        return (dllname.replace('\x00',''), events, key.LastWriteTime, pids)

    def parse_service_key(self, service_key):

        name = str(service_key.Name)

        values = {str(name): str(dat) for name, dat in self.regapi.reg_yield_values(hive_name='system', key='', given_root=service_key)}

        image_path = values.get("ImagePath", None)
        if not image_path:
            return
        display_name = values.get("DisplayName")
        startup = int(values.get("Start"))
        type = int(values.get("Type"))

        timestamp = service_key.LastWriteTime

        # The service is run through svchost - try to resolve the parameter name
        entry = None

        if "svchost.exe -k" in image_path:
            sk = self.regapi.reg_get_key(hive_name='system', key='Parameters', given_root=service_key)
            if sk:
                timestamp = sk.LastWriteTime
                entry = self.regapi.reg_get_value(hive_name='system', key='', value="ServiceDll", given_root=sk)
                main = self.regapi.reg_get_value(hive_name='system', key='', value='ServiceMain', given_root=sk)
                if main:
                    entry += " ({})".format(main)
                entry = entry.replace('\x00', '')

        # Check if the service is set to automatically start
        # More details here: http://technet.microsoft.com/en-us/library/cc759637(v=ws.10).aspx

        if startup in [0, 1, 2]:
            if entry:
                pids = self.find_pids_for_imagepath(entry)
            else:
                pids = self.find_pids_for_imagepath(image_path)

            return (name, timestamp, display_name, service_startup[startup], service_types[type], image_path, entry, pids)

    def get_services(self):
        # Get the CurrentControlSet symlink
        currentcs = self.regapi.reg_get_currentcontrolset()
        if currentcs == None:
            currentcs = "ControlSet001"

        services = []
        self.regapi.set_current(hive_name = "system")
        for service in self.regapi.reg_get_all_subkeys(hive_name='system', key=currentcs+"\\Services"):
            service = self.parse_service_key(service)
            if service:
                if (self._config.VERBOSE == True) or (self._config.VERBOSE == False and 'system32' not in service[5].lower() and service[5] != "Unknown"):
                    services.append(service)

        return services

    def get_activesetup(self):
        self.regapi.set_current(hive_name = "software")
        activesetup_keys = self.regapi.reg_get_all_subkeys(hive_name='software', key=ACTIVE_SETUP_KEY)
        results = []

        for subkey in activesetup_keys:
            r = self.parse_activesetup_keys(subkey)
            if r:
                results.append(r)

        return results

    def parse_activesetup_keys(self, subkey):
        valdict = self.dict_for_key(subkey)
        if 'StubPath' in valdict and valdict.get('StubPath', '').replace('\x00', ''):
            pids = self.find_pids_for_imagepath(valdict['StubPath'])
            return (valdict['StubPath'].replace('\x00', ''), subkey.LastWriteTime, pids)
        else:
            return None

    def get_sdb(self):
        self.regapi.set_current(hive_name = "software")
        sdb_keys = self.regapi.reg_get_all_subkeys(hive_name='software', key=APPCOMPAT_SDB_KEY)
        results = []

        for subkey in sdb_keys:
            r = self.parse_sdb_key(subkey)
            if r:
                results.append(r)

        return results

    def parse_sdb_key(self, subkey):
        valdict = self.dict_for_key(subkey)
        desc = sanitize_paths(valdict['DatabaseDescription'])
        timestamp = subkey.LastWriteTime
        path = sanitize_paths(valdict['DatabasePath'])
        pids = self.find_pids_for_imagepath(desc)

        return (desc, path, timestamp, pids)

    def get_autoruns(self):
        debug.debug("Getting offsets")
        addr_space = utils.load_as(self._config)
        hive_offsets = [h.obj_offset for h in hivelist.HiveList.calculate(self)]
        debug.debug("Found %s hives" % len(hive_offsets))
        hives = {}
        ntuser_hive_roots = []
        software_hive_root = None
        system_hive_root = None

        # Cycle through all hives until we find NTUSER.DAT or SOFTWARE
        # This enables us to search all memory-resident NTUSER.DAT hives

        for hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)

            name = self.hive_name(obj.Object("_CMHIVE", vm = addr_space, offset = hoff))
            root = rawreg.get_root(h)

            if 'ntuser.dat' in name.split('\\')[-1].lower():
                keys = NTUSER_RUN_KEYS
                ntuser_hive_roots.append(root)
            elif 'software' in name.split('\\')[-1].lower():
                keys = SOFTWARE_RUN_KEYS
                software_hive_root = root
            elif 'system' in name.split('\\')[-1].lower():
                system_hive_root = root
                continue
            else: continue

            debug.debug("Searching for keys in %s" % name)

            for full_key in keys:
                results = []
                debug.debug("  Opening %s" % (full_key))
                key = rawreg.open_key(root, full_key.split('\\'))
                results = self.parse_autoruns_key(key)

                if len(results) > 0:
                    h = hives.get(name, {})
                    h[(full_key, key.LastWriteTime)] = results
                    hives[name] = h

        return hives

    def parse_autoruns_key(self, key):

        valdict = self.dict_for_key(key)
        results = []
        for v in valdict:
            if valdict[v] not in ["", None, "\x00"]:
                pids = self.find_pids_for_imagepath(valdict[v])
                results.append((v, valdict[v].replace('\x00', ''), pids))

        return results

    def get_tasks(self):
        addr_space = utils.load_as(self._config)
        f = filescan.FileScan(self._config)
        tasks = []
        parsed_tasks = []
        for file in f.calculate():
            filename = str(file.file_name_with_device() or '')
            if "system32\\tasks\\" in filename.lower() and ('system32\\tasks\\microsoft' not in filename.lower() or self._config.VERBOSE):
                header = file.get_object_header()
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

                parsed = self.parse_task_xml(task_xml)

                if parsed:
                    args = parsed['Actions']['Exec'].get("Arguments", None)
                    if args:
                        parsed['Actions']['Exec']['Command'] += " {}".format(args)
                    pids = self.find_pids_for_imagepath(parsed['Actions']['Exec']['Command'])
                    parsed_tasks.append((name.split('\\')[-1], parsed, task_xml, pids))

        return parsed_tasks




    def parse_task_xml(self, xml):
        xml = re.sub('\x00\x00+', '', xml) + '\x00'
        xml = xml.decode('utf-16')
        xml = re.sub(r"<Task(.*?)>", "<Task>", xml)
        xml = xml.encode('utf-16')

        root = ET.fromstring(xml)
        d = {}

        for e in root.findall("./RegistrationInfo/Date"):
            d['Date'] = e.text
        for e in root.findall("./RegistrationInfo/Description"):
            d['Description'] = e.text
        for e in root.findall("./Actions"):
            d['Actions'] = self.visit_all_children(e)
        for e in root.findall("./Settings/Enabled"):
            d['Enabled'] = e.text
        for e in root.findall("./Settings/Hidden"):
            d['Hidden'] = e.text
        for t in root.findall("./Triggers/*"):
            d['Triggers'] = self.visit_all_children(t)

        if not d.get("Actions", {}).get('Exec', {}).get("Command", False):
            return None

        return d


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

        if self._config.ASEP_TYPE:
            asep_list = [s for s in self._config.ASEP_TYPE.split(',')]
        else:
            asep_list = ['autoruns', 'services', 'appinit', 'winlogon', 'tasks', 'activesetup', 'sdb']

        self.autoruns = []
        self.services = []
        self.appinit_dlls = []
        self.winlogon = []
        self.winlogon_registrations = []
        self.tasks = []
        self.activesetup = []
        self.sdb = []

        # Scan for ASEPs and populate the lists
        if 'autoruns' in asep_list:
            self.autoruns = self.get_autoruns()
        if 'services' in asep_list:
            self.services = self.get_services()
        if 'appinit' in asep_list:
            self.appinit_dlls = self.get_appinit_dlls()
        if 'winlogon' in asep_list:
            self.winlogon = self.get_winlogon()
            self.winlogon_registrations = self.get_winlogon_registrations()
        if 'tasks' in asep_list:
            self.tasks = self.get_tasks()
        if 'activesetup' in asep_list:
            self.activesetup = self.get_activesetup()
        if 'sdb' in asep_list:
            self.sdb = self.get_sdb()




    def render_table(self, outfd, data):
        self.table_header(outfd,
                          [("Executable", "<65"),
                           ("Source", "30"),
                           ("Last write time", "28"),
                           ("Details", "60"),
                           ("PIDs", "15")
                           ])

        for line in self.winlogon_registrations:
            self.table_row(outfd, line[0] or '', 'Winlogon (Notify)', line[2], 'Hooks: {0}'.format(", ".join([e[1] for e in line[1]]), len(line[1])), ", ".join([str(p) for p in line[3]]) or "-")

        for line in self.winlogon:
            self.table_row(outfd, line[1].replace('\x00', ''), 'Winlogon ({})'.format(line[0]), line[2], "Default value: {}".format(line[3]), ", ".join([str(p) for p in line[4]]) or "-")

        for hive in self.autoruns:
            source = hive.split('\\')[-1]
            if source == "NTUSER.DAT":
                source = hive.split('\\')[-2] + '\\' + source

            for key, timestamp in self.autoruns[hive]:
                for name, dat, pids in self.autoruns[hive][(key, timestamp)]:
                    details = name
                    executable = dat
                    self.table_row(outfd, executable, source + " ({})".format(key.split('\\')[-1]), timestamp, details, ", ".join([str(p) for p in pids]) or "-")

        for name, timestamp, details, start, type, executable, entry, pids in self.services:
            if entry != None:
                name += " (Loads: {})".format(entry)
            self.table_row( outfd,
                            executable.replace('\x00', ''),
                            'Services',
                            timestamp,
                            "{0} - {1} ({2} - {3})".format(name, details.replace('\x00', ''), type, start, ", ".join([str(p) for p in pids]) or "-"))

        for name, task, task_xml, pids in self.tasks:
            self.table_row( outfd,
                            task['Actions']['Exec']['Command'],
                            'Scheduled Tasks',
                            task['Date'],
                            "{} ({})".format(name, task.get('Description', "N/A")),
                            ", ".join([str(p) for p in pids]) or "-"
                            )

        for name, date, pids in self.activesetup:
            self.table_row(outfd,
                           name,
                           "Active Setup",
                           date,
                           "-",
                           ", ".join([str(p) for p in pids]) or "-"
                           )

        for desc, path, timestamp, pids in self.sdb:
            self.table_row(outfd,
                           path,
                           "SDB",
                           timestamp,
                           desc
                           )


    def render_text(self, outfd, data):

        if self.autoruns:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Autoruns "))
            for hive in self.autoruns:
                outfd.write("Hive: {}\n".format(hive))
                for key, timestamp in self.autoruns[hive]:
                    outfd.write("    {0} (Last modified: {1})\n".format(key, timestamp))
                    for name, dat, pids in self.autoruns[hive][(key, timestamp)]:
                        outfd.write("        {0:30} : {1} (PIDs: {2})\n".format(name, dat, ", ".join([str(p) for p in pids]) or "-"))
                outfd.write("\n")

        if self.services:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Services "))
            for name, timestamp, display_name, startup, type, executable, entry, pids in self.services:
                outfd.write("Service: {0} ({1}) - {2}, {3}\n".format(name, display_name, type, startup))
                outfd.write("    Image path: {0} (Last modified: {1})\n".format(executable, timestamp))
                outfd.write("    PIDs: {}\n".format(", ".join([str(p) for p in pids]) or "-"))
                if entry:
                    outfd.write("    Loads: {}\n".format(entry))
                outfd.write("\n")

        if self.winlogon:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Winlogon "))
            for value, data, timestamp, default, pids in self.winlogon:
                outfd.write("{0}: {1} (default: {2})\n".format(value, data.replace('\x00', ''), default))
                outfd.write("    PIDs: {}\n".format(", ".join([str(p) for p in pids]) or "-"))
                outfd.write("    Last write time: {}\n".format(timestamp))
                outfd.write("\n")

        if self.winlogon_registrations:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Winlogon Notify registrations "))
            for image, hooks, timestamp, pids in self.winlogon_registrations:
                outfd.write("{0} (Last write time: {1})\n".format(image, timestamp))
                outfd.write("    PIDs: {}\n".format(", ".join([str(p) for p in pids]) or "-"))
                outfd.write("    Hooks: \n")
                for hook in hooks:
                    outfd.write("        {0:<20} {1}\n".format(hook[0], hook[1]))
                outfd.write("\n")

        if self.tasks:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Scheduled tasks "))
            for name, task, task_xml, pids in self.tasks:
                outfd.write("==== Task name: {} (PIDs: {})\n".format(name, ", ".join([str(p) for p in pids]) or "-"))
                outfd.write(get_indented_dict(task))
                outfd.write('\n')
                outfd.write("Raw XML:\n\n---------\n{}\n---------\n\n\n".format(task_xml))

        if self.activesetup:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("Active Setup "))
            for imagename, last_write_time, pids in self.activesetup:
                outfd.write("Command line: {}\nLast-written: {} (PIDs: {})\n\n".format(imagename, last_write_time, ", ".join([str(p) for p in pids]) or "-"))

        if self.sdb:
            outfd.write("\n\n")
            outfd.write("{:=<50}\n\n".format("SDB Fix-it patches "))
            for desc, path, timestamp, pids in self.sdb:
                outfd.write("Description: \"{}\"\nLast-written: {}\nPatch: {}\n\n".format(desc, timestamp, path))



