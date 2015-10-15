#!/usr/bin/env python
# VolDiff malware analysis script by @aim4r
__author__ = 'aim4r'

# IMPORTS ================================================================
import os
import sys
import time
import datetime
import difflib
import shutil
import re
import string
import simplejson
import urllib
import urllib2
import hashlib
from subprocess import Popen

# VARIABLES ================================================================
version = "2.1.4"
path_to_volatility = "vol.py"
max_concurrent_subprocesses = 3
diff_output_threshold = 100
ma_output_threshold = 60
vt_api_key = "473db868008cddb184e609ace3ca05de8e51f806e57eba74005aba2efa4a1e6e"  # the rate limit os 4 requests per IP per minute
devnull = open(os.devnull, 'w')

# volatility plugins to run:
plugins_to_run = ["handles", "psxview", "netscan", "iehistory", "getsids", "pslist", "psscan", "cmdline", "consoles",
                  "dlllist", "filescan", "shimcache", "shellbags", "sessions", "messagehooks", "eventhooks", "svcscan",
                  "envars", "mutantscan", "symlinkscan", "atoms", "atomscan", "drivermodule", "mftparser", "driverscan",
                  "devicetree", "modules", "modscan", "unloadedmodules", "callbacks", "ldrmodules", "privs", "hashdump",
                  "threads", "malfind", "procdump", "idt", "gdt", "driverirp", "deskscan", "timers", "gditimers",
                  "ssdt"]

# volatility plugins to report / only used when a baseline memory image is provided:
plugins_to_report = ["pslist", "psscan", "psxview", "netscan", "iehistory", "malfind", "sessions", "privs",
                     "messagehooks", "eventhooks", "envars", "shimcache", "shellbags", "cmdline", "consoles",
                     "hashdump", "drivermodule", "driverscan", "driverirp", "modules", "modscan", "unloadedmodules",
                     "devicetree", "callbacks", "threads", "mutantscan", "symlinkscan", "ssdt"]

# REGEX EXPRESSIONS ================================================================
# regex expressions used to analyse imports
ransomware_imports = "CreateDesktop"
keylogger_imports = "GetKeyboardState|GetKeyState"
password_extract_imports = "SamLookupDomainInSamServer|NlpGetPrimaryCredential|LsaEnumerateLogonSessions|SamOpenDomain|SamOpenUser|SamGetPrivateData|SamConnect|SamRidToSid|PowerCreateRequest|SeDebugPrivilege|SystemFunction006|SystemFunction040"
clipboard_imports = "OpenClipboard"
process_injection_imports = "VirtualAllocEx|AllocateVirtualMemory|VirtualProtectEx|ProtectVirtualMemory|CreateProcess|LoadLibrary|LdrLoadDll|CreateToolhelp32Snapshot|QuerySystemInformation|EnumProcesses|WriteProcessMemory|WriteVirtualMemory|CreateRemoteThread|ResumeThread|SetThreadContext|SetContextThread|QueueUserAPC|QueueApcThread|WinExec|FindResource"
uac_bypass_imports = "AllocateAndInitializeSid|EqualSid|RtlQueryElevationFlags|GetTokenInformation|GetSidSubAuthority|GetSidSubAuthorityCount"
anti_debug_imports = "SetUnhandledExceptionFilter|CheckRemoteDebugger|DebugActiveProcess|FindWindow|GetLastError|GetWindowThreadProcessId|IsDebugged|IsDebuggerPresent|NtCreateThreadEx|NtGlobalFlags|NtSetInformationThread|OutputDebugString|pbIsPresent|Process32First|Process32Next|TerminateProcess|ThreadHideFromDebugger|UnhandledExceptionFilter|ZwQueryInformation|Sleep|GetProcessHeap"
web_imports = "InternetReadFile|recvfrom|WSARecv|DeleteUrlCacheEntry|CreateUrlCacheEntry|URLDownloadToFile|WSASocket|WSASend|WSARecv|WS2_32|InternetOpen|HTTPOpen|HTTPSend|InternetWrite|InternetConnect"
listen_imports = "RasPortListen|RpcServerListen|RpcMgmtWaitServerListen|RpcMgmtIsServerListening"
service_imports = "OpenService|CreateService|StartService|NdrClientCall2|NtLoadDriver"
shutdown_imports = "ExitWindows"
registry_imports = "RegOpenKey|RegQueryValue|ZwSetValueKey"
file_imports = "CreateFile|WriteFile"
atoms_imports = "GlobalAddAtom"
localtime_imports = "GetLocalTime|GetSystemTime"
driver_imports = "DeviceIoControl"
username_imports = "GetUserName|LookupAccountNameLocal"
machine_version_imports = "GetVersion"
startup_imports = "GetStartupInfo"
diskspace_imports = "GetDiskFreeSpace"
sysinfo_imports = "CreateToolhelp32Snapshot|NtSetSystemInformation|NtQuerySystemInformation|GetCurrentProcess|GetModuleFileName"

# regex expressions used to analyse strings (from process executables)
web_regex_str = "cookie|download|proxy|responsetext|socket|useragent|user-agent|urlmon|user_agent|WebClient|winhttp|http"
antivirus_regex_str = "antivir|anvir|avast|avcons|avgctrl|avginternet|avira|bitdefender|checkpoint|comodo|F-Secure|firewall|kaspersky|mcafee|norton|norman|safeweb|sophos|symantec|windefend"
virtualisation_regex_str = "000569|001C14|080027|citrix|parallels|proxmox|qemu|SbieDll|Vbox|VMXh|virm|virtualbox|virtualpc|vmsrvc|vpc|winice|vmware|xen"
sandbox_regex_str = "anubis|capturebat|cuckoo|deepfreeze|debug|fiddler|fireeye|inctrl5|installwatch|installspy|netmon|noriben|nwinvestigatorpe|perl|processhacker|python|regshot|sandb|schmidti|sleep|snort|systracer|uninstalltool|tcpdump|trackwinstall|whatchanged|wireshark"
sysinternals_regex_str = "filemon|sysinternal|procdump|procexp|procmon|psexec|regmon|sysmon"
shell_regex_str = "shellexecute|shell32"
keylogger_regex_str = "backspace|klog|keylog|shift"
filepath_regex_str = 'C:\\\(?:[^\\\/:*?"<>|\r\n]+\\\)*[^\\\/:*?"<>|\r\n]*'
password_regex_str = "brute|credential|creds|mimikatz|passwd|password|pwd|sniff|stdapi|WCEServicePipe|wce_krbtkts"
powershell_regex_str = "powerview|powershell"
sql_regex_str = "SELECT|INSERT|sqlite|MySQL"
infogathering_regex_str = "driverquery|gethost|wmic|GetVolumeInformation|systeminfo|tasklist|reg.exe"
tool_regex_str = "cain|clearev|ipscan|netsh|rundll32|timestomp|torrent"
banking_regex_str = "banc|banco|bank|Barclays|hsbc|jpmorgan|lloyds|natwest|nwolb|paypal|rbc.com|santander"
socialsites_regex_str = "facebook|instagram|linkedin|pastebin|twitter|yahoo|youtube"
exec_regex_str = ".*\.bat|.*\.cmd|.*\.class|.*\.exe|.*\.jar|.*\.js|.*\.jse|.*\.SCR|.*\.VBE|.*\.vbs"
crypto_regex_str = "bitlocker|bitcoin|CIPHER|crypt|locker|logkey|publickey|ransom|truecrypt|veracrypt"
rat_regex_str = "backdoor|botnet|login|malware|rootkit|screenshot|Trojan|Vnc|VncStart"
browser_regex_str = "chrome|firefox|mozilla|opera"
other_regex_str = "admin|currentversion|hosts|registry|smtp|UserInit|.*\.pdb"

# regex expressions used to extract ips, domains and email addresses
ips_regex = r"(?!\b\d{1,3}\.\d{1,3}\.\d{1,3}\.0\b)\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
domains_regex_http = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
domains_regex_ftp = 'ftp[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
domains_regex_file = 'file[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
emails_regex = r"\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b"

# regex expressions used to analyse registry handles
registry_infogathering_regex = "SOFTWARE\\\MICROSOFT|Parameters|SOFTWARE\\\POLICIES"
registry_proxy_settings_regex = "INTERNET SETTINGS"
registry_locale_regex = "NLS\\\LOCALE"
registry_hostname_regex = "COMPUTERNAME"
registry_installed_programs_regex = "CurrentVersion\\\App Paths|CurrentVersion\\\Uninstall|Installed Components"
registry_remote_control_regex = "Terminal Server|Realvnc"
registry_firewall_regex = "firewall"
registry_services_regex = "CurrentControlSet\\\services"
registry_network_regex = "NetworkList|Tcpip"
registry_autorun_regex = "CurrentVersion\\\Explorer|CurrentVersion\\\Run|CurrentVersion\\\Windows|Current Version\\\Policies\\\Explorer|CurrentVersion\\\Winlogon|Shell Extensions"
registry_command_processor_regex = "Command Processor"
registry_crypto_regex = "CRYPTOGRAPHY"
registry_tracing_regex = "TRACING"
registry_file_associations_regex = "SYSTEMFILEASSOCIATIONS"
registry_ie_security_regex = "INTERNET EXPLORER\\\SECURITY"
registry_security_center_regex = "Security Center"

# suspicious processes and dlls
hacker_process_regex = "at.exe|chtask.exe|clearev|ftp.exe|net.exe|nbtstat.exe|net1.exe|ping.exe|powershell|procdump.exe|psexec|quser.exe|reg.exe|regsvr32.exe|schtasks|systeminfo.exe|taskkill.exe|timestomp|winrm|wmic|xcopy.exe"
hacker_dll_regex = "mimilib.dll|sekurlsa.dll|wceaux.dll|iamdll.dll|VMCheck.dll"
# suspicious process names
l33t_process_name = "snss|crss|cssrs|csrsss|lass|isass|lssass|lsasss|scvh|svch0st|svhos|svchst|svchosts|lsn|g0n|l0g|nvcpl|rundii|wauclt|spscv|spppsvc|sppscv|sppcsv|taskchost|tskhost|msorsv|corsw|arch1ndex|wmipvr|wmiprse|runddl|crss.exe"
# "usual" process names
usual_processes = "sppsvc.exe|audiodg.exe|mscorsvw.exe|SearchIndexer|TPAutoConnSvc|TPAutoConnect|taskhost.exe|smss.exe|wininit.exe|services.exe|lsass.exe|svchost.exe|lsm.exe|explorer.exe|winlogon|conhost.exe|dllhost.exe|spoolsv.exe|vmtoolsd.exe|WmiPrvSE.exe|msdtc.exe|TrustedInstall|SearchFilterHo|csrss.exe|System|ipconfig.exe|cmd.exe|dwm.exe|mobsync.exe|DumpIt.exe|VMwareTray.exe|wuauclt.exe|LogonUI.exe|SearchProtocol|vssvc.exe|WMIADAP.exe"
# suspicious filepaths
susp_filepath = "\\\ProgramData|\\\Recycle|\\\Windows\\\Temp|\\\Users\\\All|\\\Users\\\Default|\\\Users\\\Public|\\\ProgramData|AppData"
temp_filepath = "\\\TMP|\\\TEMP|\\\AppData"
# usual timers
usual_timers = "ataport.SYS|ntoskrnl.exe|NETIO.SYS|storport.sys|afd.sys|cng.sys|dfsc.sys|discache.sys|HTTP.sys|luafv.sys|ndis.sys|Ntfs.sys|rdbss.sys|rdyboost.sys|spsys.sys|srvnet.sys|srv.sys|tcpip.sys|usbccgp.sys|netbt.sys|volsnap.sys|dxgkrnl.sys|bowser.sys|fltmgr.sys"
# usual gditimers
usual_gditimers = "dllhost.exe|explorer.exe|csrss.exe"
# usual ssdt
usual_ssdt = "(ntos|win32k)"
# usual atoms and atomscan dlls
usual_atoms_dlls = "system32\\\wls0wndh.dll|System32\\\pnidui.dll|system32\\\stobject.dll|vmusr\\\\vmtray.dll|system32\\\EXPLORERFRAME.dll|system32\\\uxtheme.dll|system32\\\MsftEdit.dll|system32\\\SndVolSSO.DLL|system32\\\\fxsst.dll|system32\\\WINMM.dll"
# extensions of interest
susp_extensions_regex = "\.job$|\.pdb$|\.xls$|\.doc$|\.pdf$|\.tmp$|\.temp$|\.rar$|\.zip$|\.bat|\.cmd$|\.class$|\.jar$|\.jse$|\.SCR$|\.VBE$|\.vbs$"

# DICTIONARIES/LISTS USED FOR PROCESS CHECKS ================================================================
# list of "unique" processes
uniq_processes = ["services.exe", "System", "wininit.exe", "smss.exe", "lsass.exe", "lsm.exe", "explorer.exe"]
# expected execution path for some processes
process_execpath = {'smss.exe': "\systemroot\system32\smss.exe",
                    "crss.exe": "\windows\system32\csrss.exe",
                    "wininit.exe": "wininit.exe",
                    "services.exe": "\windows\system32\services.exe",
                    "lsass.exe": "\windows\system32\lsass.exe",
                    "svchost.exe": "\windows\system32\svchost.exe",
                    "lsm.exe": "\windows\system32\lsm.exe",
                    "explorer.exe": "\windows\explorer.exe",
                    "winlogon.exe": "winlogon.exe",
                    "sppsvc.exe": "\windows\system32\sppsvc.exe"}

# expected process parent/child relationship
parent_child = {'services.exe': ["sppsvc.exe", "taskhost.exe", "mscorsvw.exe", "TPAutoConnSvc", "SearchIndexer", "svchost.exe", "taskhost.exe", "spoolsv.exe"],
                'System': ["smss.exe"], 'csrss.exe': ["conhost.exe"],
                'svchost.exe': ["WmiPrvSE.exe", "audiodg.exe"],
                'wininit.exe': ["services.exe", "lsass.exe", "lsm.exe"]
                }

# expected process sessions
session0_processes = ["wininit.exe", "services.exe", "svchost.exe", "lsm.exe", "lsass.exe"]
session1_processes = ["winlogon.exe"]

# VOLATILITY PROFILES ================================================================
profiles = ["VistaSP0x86", "VistaSP0x64", "VistaSP1x86", "VistaSP1x64", "VistaSP2x86", "VistaSP2x64",
            "Win2003SP0x86", "Win2003SP1x86", "Win2003SP1x64", "Win2003SP2x86", "Win2003SP2x64",
            "Win2008SP1x86", "Win2008SP1x64", "Win2008SP2x86", "Win2008SP2x64", "Win2008R2SP0x64", "Win2008R2SP1x64",
            "Win2012R2x64", "Win2012x64",
            "Win7SP0x86", "Win7SP0x64", "Win7SP1x86", "Win7SP1x64",
            "Win8SP0x86", "Win8SP0x64", "Win8SP1x86", "Win8SP1x64",
            "WinXPSP2x86", "WinXPSP1x64", "WinXPSP2x64", "WinXPSP3x86"]

preferred_profiles = ["Win7SP0x86", "Win7SP0x64", "Win7SP1x86", "Win7SP1x64"]


# PRINT VOLDIFF BANNER ================================================================
def print_voldiff_banner():
    print ("             _    ___ _  __  __ ")
    print (" /\   /\___ | |  /   (_)/ _|/ _|")
    print (" \ \ / / _ \| | / /\ / | |_| |_ ")
    print ("  \ V / (_) | |/ /_//| |  _|  _|")
    print ("   \_/ \___/|_/___,' |_|_| |_|  ")
    print ("\nVolDiff: Malware Memory Footprint Analysis (v%s)\n" % version)


# PRINT HELP SECTION ================================================================
def print_help():
    print ("Usage: ./VolDiff.py [BASELINE_IMAGE] INFECTED_IMAGE PROFILE [OPTIONS]")
    print ("\nOptions:")
    print ("--help                display this help and exit")
    print ("--version             display version information and exit")
    print ("--dependencies        display information about script dependencies and exit")
    print ("--malware-checks      hunt and report suspicious anomalies (slow, recommended)")
    print ("--output-dir [dir]    custom directory to store analysis results")
    print ("--no-report           do not create a report")
    print ("\nTested using Volatility 2.4 (vol.py) on Windows 7 images.")
    sys.exit()


# PRINT VERSION INFORMATION ================================================================
def print_version():
    print ("This is a free software: you are free to change and redistribute it.")
    print ("There is no warranty, to the extent permitted by law.")
    print ("Written by @aim4r. Report bugs to voldiff[@]gmail.com.")
    sys.exit()


# PRINT DEPENDENCIES ================================================================
def print_dependencies():
    print ("Requires volatility 2.4 (vol.py) to be installed.")
    sys.exit()


# VERIFY PATH TO VOLATILITY EXISTS ================================================================
def check_volatility_path(path):
    if os.path.isfile(path):
        return True
    for p in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(p, path)
        if os.path.exists(full_path):
            return True
    return False


# VERIFY ENOUGH ARGUMENTS ARE SUPPLIED ================================================================
def check_enough_arguments_supplied(n=4):
    if len(sys.argv) < n:
        print("Not enough arguments supplied. Please use the --help option for help.")
        sys.exit()


# SET PROFILE AND FIND PATH TO MEMORY IMAGE(S) ================================================================
def check_profile(pr):
    if pr not in profiles:
        print ("Please specify a valid Volatility Windows profile for use (such as Win7SP1x64).")
        sys.exit()
    if pr not in preferred_profiles:
        print(
            "WARNING: This script was only tested using Windows 7 profiles. The specified profile (%s) seems different!" % pr)
    else:
        print ("Profile: %s" % pr)
    return


# COMPLETION AND CLEANUP FUNCTION ================================================================
def script_completion(start_time):
    if 'report' in globals():
        report.write("\n\nEnd of report.")
        report.close()
        open_report(output_dir + "/VolDiff_Report.txt")
    notify_completion("VolDiff execution completed.")
    shutil.rmtree(output_dir + '/tmpfolder')
    completion_time = time.time() - start_time
    a = int(completion_time / 60)
    b = int(completion_time % 60)
    if 'devnull' in globals():
        devnull.close()
    print("\nVolDiff execution completed in %s minutes and %s seconds." % (a, b))
    sys.exit()


# DIFFING RESULTS ================================================================
def diff_files(path1, path2, diffpath):
    with open(path1, "r") as file1:
        with open(path2, "r") as file2:
            diff = difflib.unified_diff(file1.readlines(), file2.readlines())
            with open(diffpath, 'w+') as file3:
                print >> file3, ''.join(list(diff))
                file3.seek(0)
                lines = file3.readlines()
                file3.seek(0)
                for line in lines:
                    if line.startswith("+") and not line.startswith("+++"):
                        file3.write(line[1:])
                file3.truncate()
    return


# REPORT CREATION ================================================================
def report_plugin(plugin, header_lines=0, threshold=diff_output_threshold):
    report.write("\n\nNew %s entries." % plugin)
    report.write("\n==========================================================================================================================\n")
    if header_lines != 0:
        with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as f:
            for i in range(header_lines):
                line = next(f, '').strip()
                report.write(line + "\n")
    line_counter = 0
    with open(output_dir + "/" + plugin + "/diff_" + plugin + ".txt") as diff:
        for line in diff:
            line_counter += 1
            if line_counter < threshold:
                report.write(line)
            else:
                report.write("\nWarning: too many new entries to report, output truncated!\n")
                break
    return


# OPENING REPORT ================================================================
def open_report(report_path):
    if os.name == 'posix':
        p = Popen(['xdg-open', report_path], stdout=devnull, stderr=devnull)
        p.wait()
    elif os.name == 'mac':
        p = Popen(['open', report_path], stdout=devnull, stderr=devnull)
        p.wait()
    elif os.name == 'nt':
        p = Popen(['cmd', '/c', 'start', report_path], stdout=devnull, stderr=devnull)  # cmd /c start [filename]
        p.wait()


# NOTIFYING ABOUT SCRIPT COMPLETION ================================================================
def notify_completion(message):
    if os.name == 'posix':
        p = Popen(['notify-send', message], stdout=devnull, stderr=devnull)
        p.wait()


# MALWARE ANALYSIS FUNCTIONS ================================================================
def open_full_plugin(plugin="psscan", lines_to_ignore=2, state="infected"):
    if os.path.isfile(output_dir + "/" + plugin + "/" + state + "_" + plugin + ".txt"):
        f = open(output_dir + "/" + plugin + "/" + state + "_" + plugin + ".txt")
    else:
        f = open(output_dir + "/" + plugin + "/" + plugin + ".txt")
    for i in xrange(lines_to_ignore):
        next(f, '')
    return f


def open_diff_plugin(plugin="psscan", lines_to_ignore=2):
    if os.path.isfile(output_dir + "/" + plugin + "/diff_" + plugin + ".txt"):
        f = open(output_dir + "/" + plugin + "/diff_" + plugin + ".txt")
    else:
        f = open(output_dir + "/" + plugin + "/" + plugin + ".txt")
        for i in xrange(lines_to_ignore):
            next(f, '')
    return f


def anomaly_search(plugin, regex_to_include, ignorecase='yes', regex_to_exclude='', diff="diff"):
    match_list = []
    if diff == "diff":
        f = open_diff_plugin(plugin)
    else:
        f = open_full_plugin(plugin)
    for line in f:
        if ignorecase == 'yes':
            if re.search(regex_to_include, line, re.IGNORECASE):
                if regex_to_exclude == '':
                    match_list.append(line)
                elif not re.search(regex_to_exclude, line, re.IGNORECASE):
                    match_list.append(line)
        else:
            if re.search(regex_to_include, line):
                if regex_to_exclude == '':
                    match_list.append(line)
                elif not re.search(regex_to_exclude, line):
                    match_list.append(line)
    f.close()
    return match_list


def anomaly_search_inverted(plugin, regex_to_exclude, ignorecase='yes', regex_to_include=''):
    match_list = []
    f = open_diff_plugin(plugin)
    for line in f:
        if ignorecase == 'yes':
            if not re.search(regex_to_exclude, line, re.IGNORECASE):
                if regex_to_include == '':
                    match_list.append(line)
                elif re.search(regex_to_include, line, re.IGNORECASE):
                    match_list.append(line)
        else:
            if not re.search(regex_to_exclude, line):
                if regex_to_include == '':
                    match_list.append(line)
                elif re.search(regex_to_include, line):
                    match_list.append(line)
    f.close()
    return match_list


def report_anomalies(headline, anomaly_list, delim="=", plugin="", header_lines=0, threshold=ma_output_threshold):
    if len(anomaly_list) != 0:
        report.write("\n\n%s" % headline)
        if delim == "=":
            report.write(
                "\n==========================================================================================================================\n")
        elif delim == '-':
            report.write(
                "\n--------------------------------------------------------------------------------------------------------------------------\n")
        if header_lines != 0 and plugin != "":
            if os.path.isfile(output_dir + "/" + plugin + "/infected_" + plugin + ".txt"):
                with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as f:
                    for i in range(header_lines):
                        line = next(f, '').strip()
                        report.write(line + "\n")
            else:
                with open(output_dir + "/" + plugin + "/" + plugin + ".txt") as f:
                    for i in range(header_lines):
                        line = next(f, '').strip()
                        report.write(line + "\n")
        if len(anomaly_list) > threshold:
            anomaly_list_to_report = anomaly_list[0:threshold]
            anomaly_list_to_report.append("\nWarning: too many entries to report, output truncated!\n")
        else:
            anomaly_list_to_report = anomaly_list
        for line in anomaly_list_to_report:
            report.write(line)
    return


def extract_substrings(input_list, regex):
    extracted_list = []
    for entry in input_list:
        subentries = entry.split(' ')
        for subentry in subentries:
            if re.search(regex, subentry, re.IGNORECASE):
                extracted_list.append(subentry)
    return extracted_list


def tidy_list(input_list):
    updatedlist = []
    for entry in input_list:
        if not re.search("\\n", entry):
            entry += '\n'
        updatedlist.append(entry)
    updatedlist = sorted(set(updatedlist))
    return updatedlist


def find_ips_domains_emails(plugin):
    f = open_diff_plugin(plugin, 0)
    ips = []
    ips_to_report = []
    ips_regex_exclude = r"127\.0\.0\.1|0\.0\.0\.0"
    for line in f:
        if re.search(ips_regex, line, re.IGNORECASE):
            ips += re.findall(ips_regex, line, re.IGNORECASE)
    for ip in ips:
        if not re.search(ips_regex_exclude, ip, re.IGNORECASE):
            ips_to_report.append(ip)
    domains = []
    f.seek(0)
    for line in f:
        if re.search(domains_regex_http, line, re.IGNORECASE):
            domains += re.findall(domains_regex_http, line, re.IGNORECASE)
        if re.search(domains_regex_ftp, line, re.IGNORECASE):
            domains += re.findall(domains_regex_ftp, line, re.IGNORECASE)
        if re.search(domains_regex_file, line, re.IGNORECASE):
            domains += re.findall(domains_regex_file, line, re.IGNORECASE)
    emails = []
    f.seek(0)
    for line in f:
        if re.search(emails_regex, line, re.IGNORECASE):
            emails += re.findall(emails_regex, line, re.IGNORECASE)
    ips_domains_emails = ips_to_report + domains + emails
    ips_domains_emails = tidy_list(ips_domains_emails)
    f.close()
    return ips_domains_emails


def get_pids(procname, plugin="psscan"):
    pids = []
    if procname == "":
        return pids
    f = open_full_plugin(plugin, 2)
    for line in f:
        if re.search(' ' + procname + ' ', line, re.IGNORECASE):
            pids.append(re.sub(' +', ' ', line).split(' ')[2])
    pids = sorted(set(pids))
    f.close()
    return pids


def get_associated_process_lines_pids(pids, plugin="psscan"):
    f = open_full_plugin(plugin, 2)
    associated_psscan_lines = []
    for line in f:
        for pid in pids:
            if re.sub(' +', ' ', line).split(' ')[2] == str(pid):
                associated_psscan_lines.append(line)
    f.close()
    return associated_psscan_lines


def get_associated_process_lines_ppids(ppids, plugin="psscan"):
    f = open_full_plugin(plugin, 2)
    associated_psscan_lines = []
    for line in f:
        for ppid in ppids:
            if re.sub(' +', ' ', line).split(' ')[3] == str(ppid):
                associated_psscan_lines.append(line)
    f.close()
    return associated_psscan_lines


def get_childs_of(pids):
    f = open_full_plugin("psscan", 2)
    childs = []
    for line in f:
        for pid in pids:
            ppid = re.sub(' +', ' ', line).split(' ')[3]
            if ppid == str(pid):
                childs.append(re.sub(' +', ' ', line).split(' ')[2])
    childs = sorted(set(childs))
    f.close()
    return childs


def get_parent_pids_of(childs):
    f = open_full_plugin("psscan", 2)
    parents = []
    for line in f:
        for child in childs:
            if re.sub(' +', ' ', line).split(' ')[2] == child:
                parents.append(re.sub(' +', ' ', line).split(' ')[3])
    parents = sorted(set(parents))
    f.close()
    return parents


def get_procnames(pids):
    f = open_full_plugin("psscan", 2)
    procnames = []
    for line in f:
        for pid in pids:
            if re.sub(' +', ' ', line).split(' ')[2] == pid:
                procnames.append(re.sub(' +', ' ', line).split(' ')[1])
    f.close()
    return procnames


def get_all_pids(exception_regex=''):
    f = open_full_plugin("psscan", 2)
    pids = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        else:
            pid = re.sub(' +', ' ', line).split(' ')[2]
            if pid != "0":
                pids.append(pid)
    pids = sorted(set(pids))
    f.close()
    return pids


def get_diff_pids(exception_regex=''):
    f = open_diff_plugin("psscan", 2)
    pids = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        else:
            pid = re.sub(' +', ' ', line).split(' ')[2]
            if pid != "0":
                pids.append(pid)
    pids = sorted(set(pids))
    f.close()
    return pids


def get_procname(pid, plugin='psscan'):
    f = open_full_plugin(plugin, 2)
    procnamee = ""
    for line in f:
        if re.search(r"[a-zA-Z\.]\s+%s " % pid, line, re.IGNORECASE):
            procnamee = (re.sub(' +', ' ', line).split(' ')[1])
            break
    procnamee = str(procnamee)
    f.close()
    return procnamee


def get_all_procnames(plugin='psscan', exception_regex=''):
    f = open_full_plugin(plugin, 2)
    procnames = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        else:
            procnames.append(re.sub(' +', ' ', line).split(' ')[1])
    procnames = sorted(set(procnames))
    f.close()
    return procnames


def get_all_ppids(exception_regex=''):
    f = open_full_plugin("psscan", 2)
    ppids = []
    for line in f:
        if exception_regex != '' and re.search(exception_regex, line, re.IGNORECASE):
            continue
        elif re.sub(' +', ' ', line).split(' ')[2] != "0":
            ppids.append(re.sub(' +', ' ', line).split(' ')[3])
    ppids = sorted(set(ppids))
    f.close()
    return ppids


def get_session(pid):
    session = ""
    f = open_full_plugin("pslist", 2)
    for line in f:
        if re.search(' ' + str(pid) + ' ', line, re.IGNORECASE):
            session = re.sub(' +', ' ', line).split(' ')[6]
            break
    f.close()
    return session


def get_execpath(pid):
    execpath = ''
    procnamep = get_procname(pid)
    f = open_full_plugin("dlllist", 0)
    for line in f:
        if re.search(procnamep + ' pid.*' + str(pid), line, re.IGNORECASE):
            command_line = next(f, '')
            execpath = re.sub("Command line : ", "", command_line)
            execpath = re.sub(".:", "", execpath)
            execpath = re.sub(" .*", "", execpath)
            execpath = re.sub("\n", "", execpath)
    f.close()
    return execpath


def get_cmdline(pid):
    cmdline = []
    procnamec = get_procname(pid)
    f = open_full_plugin("cmdline", 0)
    for line in f:
        if re.search(procnamec + ' pid.* ' + pid, line, re.IGNORECASE):
            cmdline.append(line)
            line = next(f, '')
            cmdline.append(line)
            break
    if cmdline:
        if not re.search("Command", cmdline[1], re.IGNORECASE):
            cmdline = []
    f.close()
    return cmdline


def deadproc_activethreads():
    f = open_full_plugin("psxview", 2)
    dead_proc_active_threads = []
    for line in f:
        if 'UTC' in str(re.sub(' +', ' ', line).split(' ')[9:]) and re.sub(' +', ' ', line).split(' ')[5] == "True":
            dead_proc_active_threads.append(line)
    f.close()
    return dead_proc_active_threads


def get_hosts_contents(memory_image_file):
    hostscontent = []
    f = open_full_plugin("filescan", 2)
    qaddressb = ""
    for line in f:
        if re.search("etc\\\hosts$", line, re.IGNORECASE):
            qaddressb = re.sub(' +', ' ', line).split(' ')[0]
            break
    if qaddressb != "":
        hostsfolder = tmpfolder + "hosts/"
        if not os.path.isdir(hostsfolder):
            os.makedirs(hostsfolder)
        process_var = Popen([path_to_volatility, "--profile", profile, "-f", memory_image_file, "dumpfiles", "-Q", qaddressb, "-D", hostsfolder], stdout=devnull, stderr=devnull)
        process_var.wait()
        dumped_hosts_filename = os.listdir(hostsfolder)
        if len(dumped_hosts_filename) == 1:
            with open(hostsfolder + str(dumped_hosts_filename[0]), mode='rb') as hosts:
                for line in hosts:
                    if not re.search("^#", line) and re.search(" ", line):
                        hostscontent.append(line)
    hostscontent = sorted(set(hostscontent))
    f.close()
    return hostscontent


def filter_new_services():
    filtered_services = []
    diff_svcscan = open_diff_plugin("svcscan", 0)
    baseline_svcscan = open_full_plugin("svcscan", 0, "baseline")
    for line in diff_svcscan:
        if line not in baseline_svcscan and not re.search("Offset:", line, re.IGNORECASE):
            filtered_services.append(line)
        baseline_svcscan.seek(0)
    filtered_services = set(filtered_services)
    baseline_svcscan.close()
    diff_svcscan.close()
    return filtered_services


def get_associated_services(pid):
    services = []
    full_svcscan = open_full_plugin("svcscan", 0)
    for line in full_svcscan:
        if re.search("Process ID: " + str(pid) + "\n", line, re.IGNORECASE):
            services.append("\n")
            services.append(line)
            for i in xrange(5):
                line = next(full_svcscan, '')
                services.append(line)
    full_svcscan.close()
    return services


def get_malfind_pids():
    malfind_pids = []
    f = open_diff_plugin("malfind", 0)
    for line in f:
        if re.search("Address:", line):
            malfind_pids.append(re.sub(' +', ' ', line).split(' ')[3])
    malfind_pids = sorted(set(malfind_pids))
    f.close()
    return malfind_pids


def get_malfind_injections(pid, m="dual"):
    malfind_injections = []
    f = open_diff_plugin("malfind", 0)
    if m == "dual":
        n = 6
    else:
        n = 7
    for line in f:
        if re.search("Pid: " + str(pid) + " ", line):
            malfind_injections.append("\n")
            malfind_injections.append(line)
            for i in xrange(n):
                line = next(f, '')
                malfind_injections.append(line)
    f.close()
    return malfind_injections


def analyse_registry(pid):
    rhit = False
    registry_analysis_matrix = {"\nCollects information about system": registry_infogathering_regex,
                                "\nQueries / modifies proxy settings": registry_proxy_settings_regex,
                                "\nReads information about supported languages": registry_locale_regex,
                                "\nIdentifies machine name": registry_hostname_regex,
                                "\nIdentifies installed programs": registry_installed_programs_regex,
                                "\nQueries / modifies remote control settings": registry_remote_control_regex,
                                "\nQueries / modifies firewall settings": registry_firewall_regex,
                                "\nQueries / modifies service settings": registry_services_regex,
                                "\nQueries / modifies network settings": registry_network_regex,
                                "\nHas access to autorun registry keys": registry_autorun_regex,
                                "\nQueries / modifies the Windows command processor": registry_command_processor_regex,
                                "\nQueries / modifies encryption seettings": registry_crypto_regex,
                                "\nQueries / modifies file association settings": registry_file_associations_regex,
                                "\nQueries / modifies security seettings": registry_ie_security_regex,
                                }
    for reg_key in registry_analysis_matrix:
        registry = anomaly_search("handles", registry_analysis_matrix[reg_key], "yes", "", "diff")
        registry_to_report = []
        for key in registry:
            if re.search(" " + str(pid) + " ", key, re.IGNORECASE) and re.search("Key", key, re.IGNORECASE):
                a = re.sub(' +', ' ', key).split(' ')[5:]
                b = re.sub('\n', '', ' '.join(a))
                registry_to_report.append(b)
        if len(registry_to_report) > 0:
            if not rhit:
                report.write("\n\nInteresting registry handles:")
                report.write(
                    "\n--------------------------------------------------------------------------------------------------------------------------\n")
                rhit = True
            report_string = ""
            registry_to_report = sorted(set(registry_to_report))
            for regkey in registry_to_report:
                report_string += "  " + regkey + "\n"
            report.write(reg_key + ":\n" + report_string)


def analyse_imports(pid):
    import_analysis_matrix = {"Can create new desktops ": ransomware_imports,
                              "Can track keyboard strokes ": keylogger_imports,
                              "Can extract passwords ": password_extract_imports,
                              "Can access the clipboard ": clipboard_imports,
                              "Can inject code to other processes ": process_injection_imports,
                              "Can bypass UAC ": uac_bypass_imports,
                              "Can use antidebug techniques ": anti_debug_imports,
                              "Can receive or send files from or to internet ": web_imports,
                              "Can listen for inbound connections ": listen_imports,
                              "Can create or start services ": service_imports,
                              "Can restart or shutdown the system ": shutdown_imports,
                              "Can interact with the registry ": registry_imports,
                              "Can create or write to files ": file_imports,
                              "Can create atoms ": atoms_imports,
                              "Can identify machine time ": localtime_imports,
                              "Can interact with or query device drivers ": driver_imports,
                              "Can enumerate username ": username_imports,
                              "Can identify machine version information ": machine_version_imports,
                              "Can query startup information ": startup_imports,
                              "Can enumerate free disk space ": diskspace_imports,
                              "Can enumerate system information ": sysinfo_imports
                              }
    impscanfolder = tmpfolder + "impscan/"
    hit = False
    if os.path.isfile(impscanfolder + str(pid) + ".txt"):
        for susp_imports_codename in import_analysis_matrix:
            regex = import_analysis_matrix[susp_imports_codename]
            susp_functions = []
            with open(impscanfolder + str(pid) + ".txt", "r") as imports:
                for function in imports:
                    if re.search(regex, function, re.IGNORECASE):
                        susp_functions.append(re.sub(' +', ' ', function).split(' ')[3])
            if len(susp_functions) > 0:
                if not hit:
                    report.write("\n\nInteresting imports:")
                    report.write(
                        "\n--------------------------------------------------------------------------------------------------------------------------\n")
                    hit = True
                report_string = ""
                susp_functions = sorted(set(susp_functions))
                for function in susp_functions:
                    if function == susp_functions[-1]:
                        report_string += re.sub("\n", "", function)
                    else:
                        report_string += (re.sub("\n", "", function) + ", ")
                report.write(susp_imports_codename + "(" + report_string + ").\n")


def strings(filepath, minimum=4):
    with open(filepath, "rb") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= minimum:
                yield result
            result = ""


def analyse_strings(pid):
    strings_analysis_matrix = {"IP address(es)": ips_regex,
                               "Email(s)": emails_regex,
                               "HTTP URL(s)": domains_regex_http,
                               "FTP URL(s)": domains_regex_ftp,
                               "File URL(s)": domains_regex_file,
                               "Web related keyword(s)": web_regex_str,
                               "Keylogger keyword(s)": keylogger_regex_str,
                               "Password keyword(s)": password_regex_str,
                               "RAT keyword(s)": rat_regex_str,
                               "Tool(s)": tool_regex_str,
                               "Banking keyword(s)": banking_regex_str,
                               "Social website(s)": socialsites_regex_str,
                               "Antivirus keyword(s)": antivirus_regex_str,
                               "Anti-sandbox keyword(s)": sandbox_regex_str,
                               "Virtualisation keyword(s)": virtualisation_regex_str,
                               "Sysinternal tool(s)": sysinternals_regex_str,
                               "Powershell keyword(s)": powershell_regex_str,
                               "SQL keyword(s)": sql_regex_str,
                               "Shell keyword(s)": shell_regex_str,
                               "Information gathering keyword(s)": infogathering_regex_str,
                               "Executable file(s)": exec_regex_str,
                               "Encryption keyword(s)": crypto_regex_str,
                               "Filepath(s)": filepath_regex_str,
                               "Browser keyword(s)": browser_regex_str,
                               "Misc keyword(s)": other_regex_str
                               }
    dumpfolder = tmpfolder + str(pid) + "/"
    filelist = os.listdir(dumpfolder)
    hit = False
    for susp_strings_codename in strings_analysis_matrix:
        regex = strings_analysis_matrix[susp_strings_codename]
        susp_strings = []
        for f in filelist:
            for stringa in strings(dumpfolder + f):
                if re.search(regex, stringa, re.IGNORECASE):
                    for i in re.findall(regex, stringa, re.IGNORECASE):
                        susp_strings.append(i)
        if len(susp_strings) > 0:
            if not hit:
                report.write("\n\nSuspicious strings from process memory:")
                report.write("\n--------------------------------------------------------------------------------------------------------------------------\n")
                hit = True
            report_string = ""
            susp_strings = sorted(set(susp_strings))
            for susp_string in susp_strings:
                if susp_string == susp_strings[-1]:
                    report_string += re.sub("\n", "", susp_string)
                else:
                    report_string += (re.sub("\n", "", susp_string) + ", ")
            report.write(susp_strings_codename + ": " + report_string + "\n")


def check_expected_parent(pid):
    fl = False
    expected_parent = ""
    childname = get_procname(pid, 'psscan')
    parent = ""
    for parent in parent_child:
        if childname in parent_child[parent]:
            fl = True
            expected_parent = parent
            break
    if fl:
        actual_parent = get_procname(get_parent_pids_of([pid, ])[0], "psscan")
        if actual_parent.lower() != parent.lower():
            j = get_associated_process_lines_pids(get_pids(actual_parent))
            l = get_associated_process_lines_pids(get_pids(expected_parent))
            k = get_associated_process_lines_pids([pid, ])
            report_anomalies("Unexpected parent process (" + actual_parent + " instead of " + expected_parent + "):", k + j + l, '-', "psscan", 2)


def get_remote_share_handles(pid):
    share_handles_to_report = []
    remote_share = anomaly_search("handles", "Device\\\(LanmanRedirector|Mup)", 'yes', '', "diff")
    for share_handle in remote_share:
        if re.sub(' +', ' ', share_handle).split(' ')[1] == pid:
            share_handles_to_report.append(share_handle)
    return share_handles_to_report


def get_raw_sockets(pid):
    raw_sockets_to_report = []
    raw_sockets = anomaly_search("handles", "\\\Device\\\RawIp", 'yes', '', "diff")
    for raw_socket in raw_sockets:
        if re.sub(' +', ' ', raw_socket).split(' ')[1] == pid:
            raw_sockets_to_report.append(raw_socket)
    return raw_sockets_to_report


def get_md5(pid):
    md5 = ""
    dump_folder = tmpfolder + str(pid) + "/"
    filelist = os.listdir(dump_folder)
    for f in filelist:
        if f == "executable." + str(pid) + ".exe":
            md5 = hashlib.md5(open(dump_folder + f).read()).hexdigest()
            break
    return md5


def report_virustotal_md5_results(md5, api):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5, "apikey": api}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response_dict = {}
    network_error = False
    try:
        response = urllib2.urlopen(req)
        json = response.read()
        if json != "":
            response_dict = simplejson.loads(json)
    except urllib2.URLError:
        network_error = True
    if not network_error:
        report.write("\n\nVirusTotal scan results:")
        report.write("\n--------------------------------------------------------------------------------------------------------------------------\n")
        report.write("MD5 value: " + md5 + "\n")
        if "response_code" in response_dict:
            if response_dict["response_code"] == 1:
                report.write("VirusTotal scan date: " + str(response_dict["scan_date"]) + "\n")
                report.write("VirusTotal engine detections: " + str(response_dict["positives"]) + "/" + str(response_dict["total"]) + "\n")
                report.write("Link to VirusTotal report: " + str(response_dict["permalink"]) + "\n")
            else:
                report.write("Could not find VirusTotal scan results for the MD5 value above.\n")
        else:
            report.write("VirusTotal request rate limit reached, could not retrieve results.\n")


def main():
    # PRINT VOLDIFF BANNER ================================================================
    print_voldiff_banner()
    global output_dir
    global report
    global tmpfolder
    global profile
    global baseline_memory_image
    global infected_memory_image
    global memory_image

    # CHECK THAT VOL.PY IS INSTALLED ================================================================
    if not check_volatility_path(path_to_volatility):
        print("vol.py does not seem to be installed. Please ensure that volatility is installed/functional before using VolDiff.")
        sys.exit()

    # READ SYS.ARGV VARIABLES ================================================================
    if not len(sys.argv) > 1:
        print_help()
    elif "--help" in sys.argv:
        print_help()
    elif "--version" in sys.argv:
        print_version()
    elif "--dependencies" in sys.argv:
        print_dependencies()
    if "--output-dir" in sys.argv:
        check_enough_arguments_supplied(5)
    else:
        check_enough_arguments_supplied(3)
    if os.path.isfile(sys.argv[2]):
        mode = "dual"
        if os.path.isfile(sys.argv[1]):
            baseline_memory_image = sys.argv[1]
            print ("Path to baseline memory image: %s" % baseline_memory_image)
        else:
            print ("Please specify a valid path to a baseline memory image.")
            sys.exit()
        infected_memory_image = sys.argv[2]
        print ("Path to infected memory image: %s" % infected_memory_image)

        if len(sys.argv) == 3:
            print ("Profile is not specified. Please specify a profile to use (such as Win7SP1x64).")
            sys.exit()
        else:
            check_profile(sys.argv[3])
            profile = sys.argv[3]
    else:
        mode = "standalone"
        if os.path.isfile(sys.argv[1]):
            memory_image = sys.argv[1]
            print ("Only one memory image specified: standalone mode")
            print ("Path to memory image: %s" % memory_image)
        else:
            print ("Please specify a valid path to a baseline memory image.")
            sys.exit()
        if len(sys.argv) == 2:
            print ("Profile is not specified. Please specify a profile to use (such as Win7SP1x64)!")
            sys.exit()
        else:
            check_profile(sys.argv[2])
            profile = sys.argv[2]

    # CREATE FOLDER TO STORE OUTPUT ================================================================
    starttime = time.time()
    output_dir = 'VolDiff_' + datetime.datetime.now().strftime("%d-%m-%Y_%H:%M")
    if os.name == 'nt':
        output_dir = 'VolDiff_' + datetime.datetime.now().strftime("%d-%m-%Y_%H%M")  # can't name file/dir with :
    tmpval = False
    for arg in sys.argv:
        if tmpval:
            output_dir = arg
            tmpval = False
        if arg == "--output-dir":
            tmpval = True
    tmpfolder = output_dir + '/tmpfolder/'
    os.makedirs(tmpfolder)

    # RUN VOLATILITY PLUGINS ================================================================
    print ("\nRunning a selection of volatility plugins (time consuming):")
    sub_procs = {}
    file_dict = {}
    proc_counter = 0
    for plugin in plugins_to_run:
        print("Volatility plugin %s execution in progress..." % plugin)
        plugin_path = output_dir + '/' + plugin + '/'
        os.makedirs(plugin_path)
        if plugin == "mutantscan" or plugin == "handles" or plugin == "privs" or plugin == "envars":
            option = "--silent"
        elif plugin == "threads":
            option = "-F OrphanThread"
        elif plugin == "psxview":
            option = "-R"
        elif plugin == "malfind":
            if mode == "dual":
                dump_dir_baseline = output_dir + '/malfind/dump_dir_baseline/'
                os.makedirs(dump_dir_baseline)
                option = "--dump-dir=" + output_dir + "/malfind/dump_dir_baseline/"
                file_dict[plugin + "baseline"] = open(output_dir + '/' + plugin + '/' + "baseline_" + plugin + ".txt", "w")
                sub_procs[plugin + "baseline"] = Popen([path_to_volatility, "--profile", profile, "-f", baseline_memory_image, plugin, option], stdout=file_dict[plugin + "baseline"], stderr=devnull)
                proc_counter += 1
                if proc_counter >= max_concurrent_subprocesses:
                    for pr in sub_procs:
                        sub_procs[pr].wait()
                    proc_counter = 0
                    sub_procs = {}
                dump_dir_infected = output_dir + '/malfind/dump_dir_infected/'
                os.makedirs(dump_dir_infected)
                option = "--dump-dir=" + output_dir + "/malfind/dump_dir_infected/"
                file_dict[plugin + "infected"] = open(output_dir + '/' + plugin + '/' + "infected_" + plugin + ".txt", "w")
                sub_procs[plugin + "infected"] = Popen([path_to_volatility, "--profile", profile, "-f", infected_memory_image, plugin, option], stdout=file_dict[plugin + "infected"], stderr=devnull)
                proc_counter += 1
                if proc_counter >= max_concurrent_subprocesses:
                    for pr in sub_procs:
                        sub_procs[pr].wait()
                    proc_counter = 0
                    sub_procs = {}
            else:
                dump_dir = output_dir + '/malfind/dump_dir/'
                os.makedirs(dump_dir)
                option = "--dump-dir=" + output_dir + "/malfind/dump_dir/"
                file_dict[plugin] = open(output_dir + '/' + plugin + '/' + plugin + ".txt", "w")
                sub_procs[plugin] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, plugin, option], stdout=file_dict[plugin], stderr=devnull)
                proc_counter += 1
                if proc_counter >= max_concurrent_subprocesses:
                    for pr in sub_procs:
                        sub_procs[pr].wait()
                    proc_counter = 0
                    sub_procs = {}
            continue
        elif plugin == "procdump":
            option = "--dump-dir=" + output_dir + "/procdump/"
            if mode == "dual":
                sub_procs[plugin] = Popen([path_to_volatility, "--profile", profile, "-f", infected_memory_image, plugin, "-u", option], stdout=devnull, stderr=devnull)
                proc_counter += 1
                if proc_counter >= max_concurrent_subprocesses:
                    for pr in sub_procs:
                        sub_procs[pr].wait()
                    proc_counter = 0
                    sub_procs = {}
            else:
                sub_procs[plugin] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, plugin, "-u", option], stdout=devnull, stderr=devnull)
                proc_counter += 1
                if proc_counter >= max_concurrent_subprocesses:
                    for pr in sub_procs:
                        sub_procs[pr].wait()
                    proc_counter = 0
                    sub_procs = {}
            continue
        else:
            option = ''
        # option set, running vol.py processes in //:
        if mode == "dual":
            file_dict[plugin + "baseline"] = open(output_dir + '/' + plugin + '/' + "baseline_" + plugin + ".txt", "w")
            sub_procs[plugin + "baseline"] = Popen([path_to_volatility, "--profile", profile, "-f", baseline_memory_image, plugin, option], stdout=file_dict[plugin + "baseline"], stderr=devnull)
            proc_counter += 1
            if proc_counter >= max_concurrent_subprocesses:
                for pr in sub_procs:
                    sub_procs[pr].wait()
                proc_counter = 0
                sub_procs = {}
            file_dict[plugin + "infected"] = open(output_dir + '/' + plugin + '/' + "infected_" + plugin + ".txt", "w")
            sub_procs[plugin + "infected"] = Popen([path_to_volatility, "--profile", profile, "-f", infected_memory_image, plugin, option], stdout=file_dict[plugin + "infected"], stderr=devnull)
            proc_counter += 1
            if proc_counter >= max_concurrent_subprocesses:
                for pr in sub_procs:
                    sub_procs[pr].wait()
                proc_counter = 0
                sub_procs = {}
        else:
            file_dict[plugin] = open(output_dir + '/' + plugin + '/' + plugin + ".txt", "w")
            sub_procs[plugin] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, plugin, option], stdout=file_dict[plugin], stderr=devnull)
            proc_counter += 1
            if proc_counter >= max_concurrent_subprocesses:
                for pr in sub_procs:
                    sub_procs[pr].wait()
                proc_counter = 0
                sub_procs = {}
    # ensuring that all subprocesses are completed before proceeding:
    for pr in sub_procs:
        sub_procs[pr].wait()
    for f in file_dict:
        file_dict[f].close()

    # DEV MODE SWITCH ================================================================
    if "--devmode" in sys.argv:
        raw_input('\nChange files and hit enter once ready.')

    # DIFF OUTPUT RESULTS ================================================================
    if mode == "dual":
        print ("Diffing output results...")
        for plugin in plugins_to_run:
            if plugin != "procdump":
                diff_files(output_dir + '/' + plugin + '/baseline_' + plugin + ".txt",
                           output_dir + '/' + plugin + '/infected_' + plugin + ".txt",
                           output_dir + '/' + plugin + '/diff_' + plugin + ".txt")

    if "--no-report" in sys.argv:
        script_completion(starttime)

    # CREATE REPORT ================================================================
    report = open(output_dir + "/VolDiff_Report.txt", 'w')

    if mode == "dual":
        report.write("             _    ___ _  __  __ \n")
        report.write(" /\   /\___ | |  /   (_)/ _|/ _|\n")
        report.write(" \ \ / / _ \| | / /\ / | |_| |_ \n")
        report.write("  \ V / (_) | |/ /_//| |  _|  _|\n")
        report.write("   \_/ \___/|_/___,' |_|_| |_|  \n")

        report.write("\nVolatility analysis report generated by VolDiff v%s" % version)
        report.write("\nDownload the latest VolDiff version from https://github.com/aim4r/VolDiff/")
        report.write("\n\nBaseline memory image: %s" % baseline_memory_image)
        report.write("\nInfected memory image: %s" % infected_memory_image)
        report.write("\nProfile: %s" % profile)
        report.write("\nDate and time: " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M"))

        no_new_entries = []

        for plugin in plugins_to_report:
            if os.stat(output_dir + "/" + plugin + "/diff_" + plugin + ".txt").st_size == 0:
                no_new_entries.append(plugin)

            # processing pslist and psscan output:
            elif plugin == "pslist" or plugin == "psscan":
                # store baseline pids in a list
                with open(output_dir + "/" + plugin + "/baseline_" + plugin + ".txt") as baseline:
                    baseline_pids = []
                    for line in baseline:
                        pid = re.sub(' +', ' ', line).split(' ')[2]
                        baseline_pids.append(pid)
                    sorted(set(baseline_pids))
                # store infected pids in a list
                with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as infected:
                    infected_pids = []
                    for line in infected:
                        pid = re.sub(' +', ' ', line).split(' ')[2]
                        infected_pids.append(pid)
                    sorted(set(infected_pids))
                # get the diff between both
                diff_pids = []
                for pid in infected_pids:
                    if pid not in baseline_pids:
                        diff_pids.append(pid)
                # print diff lines
                if len(diff_pids) > 0:
                    report.write("\n\nNew %s entries." % plugin)
                    report.write(
                        "\n==========================================================================================================================\n")
                    with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as f:
                        for i in range(2):
                            line = next(f, '').strip()
                            report.write(line + "\n")
                    for pid in diff_pids:
                        with open(output_dir + "/" + plugin + "/infected_" + plugin + ".txt") as f:
                            for line in f:
                                if re.search(r"[a-zA-Z\.]\s+%s " % pid, line, re.IGNORECASE):
                                    report.write(line)

            # processing netscan output
            elif plugin == "netscan":
                report_plugin(plugin, 1)

            # filtering mutantscan output
            elif plugin == "mutantscan":

                with open(output_dir + "/" + plugin + "/diff_" + plugin + ".txt") as diff_mutants:
                    mutants = []
                    for line in diff_mutants:
                        mutant = ' '.join((re.sub(' +', ' ', line).split(' ')[5:]))
                        if mutant != '\n':
                            mutants.append(mutant)
                    mutants = sorted(set(mutants))
                    if len(mutants) > 0:
                        report.write("\n\nNew %s entries." % plugin)
                        report.write(
                            "\n==========================================================================================================================\n")
                        for mutant in mutants:
                            report.write(mutant)

            # ensuring malfind output is completely reported
            elif plugin == "malfind":
                report_plugin(plugin, 0, 500)

            # processing plugins that don't need output formatting:
            elif plugin == "devicetree" or plugin == "orphanthreads" or plugin == "cmdline" or plugin == "consoles" or plugin == "svcscan" or plugin == "driverirp" or plugin == "shellbags" or plugin == "iehistory" or plugin == "sessions" or plugin == "eventhooks":
                report_plugin(plugin)

            # processing other plugins:
            else:
                report_plugin(plugin, 2)

        # display list of plugins with no notable changes:
        if len(no_new_entries) != 0:
            report.write("\n\nNo notable changes to highlight from the following plugins.")
            report.write(
                "\n==========================================================================================================================\n")
            for plugin in no_new_entries:
                report.write(plugin + "\n")

        # display list of plugins hidden from report (verbose):
        report.write("\n\nPlugins that were executed but are not included in the report above.")
        report.write(
            "\n==========================================================================================================================\n")
        report.write(
            "filescan\nhandles\ngetsids\ndeskscan\ndlllist\nldrmodules\natoms\nsvcscan\natomscan\nidt\ngdt\ntimers\ngditimers")

    # MALWARE CHECKS ================================================================
    if "--malware-checks" not in sys.argv:
        if mode == "standalone":
            try:
                os.remove(output_dir + "/VolDiff_Report.txt")
            except:
                pass
        script_completion(starttime)

    # PRINT BANNERS ================================================================
    print("\nHunting for malicious artifacts in memory...")
    if mode == "dual":
        report.write("\n\n")
        report.write("   _               _           _         __                 _ _       \n")
        report.write("  /_\  _ __   __ _| |_   _ ___(_)___    /__\ ___  ___ _   _| | |_ ___ \n")
        report.write(" //_\\\\| '_ \\ / _\`| | | | / __| / __|  / \\/// _ \\/ __| | | | | __/ __|\n")
        report.write("/  _  \\ | | | (_| | | |_| \\__ \\ \\__ \\ / _  \\  __/\\__ \\ |_| | | |_\\__ \\\n")
        report.write("\_/ \_/_| |_|\__,_|_|\__, |___/_|___/ \/ \_/\___||___/\__,_|_|\__|___/\n")
        report.write("                     |___/                                            \n")
    elif mode == "standalone":
        report.write("\n")
        report.write("             _    ___ _  __  __     _               _           _         __                 _ _       \n")
        report.write(" /\   /\___ | |  /   (_)/ _|/ _|   /_\  _ __   __ _| |_   _ ___(_)___    /__\ ___  ___ _   _| | |_ ___ \n")
        report.write(" \\ \\ / / _ \\| | / /\\ / | |_| |_   //_ \\| '_ \\ / _\`| | | | / __| / __|  / \\/// _ \\/ __| | | | | __/ __|\n")
        report.write("  \\ V / (_) | |/ /_//| |  _|  _| /  _  \\ | | | (_| | | |_| \\__ \\ \\__ \\ / _  \\  __/\\__ \\ |_| | | |_\\__ \\\n")
        report.write("   \_/ \___/|_/___,' |_|_| |_|   \_/ \_/_| |_|\__,_|_|\__, |___/_|___/ \/ \_/\___||___/\__,_|_|\__|___/\n")
        report.write("                                                      |___/                                            \n")
        report.write("\nVolatility analysis report of %s (%s)" % (memory_image, profile))
        report.write("\nReport created by VolDiff v" + version + " on the " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M"))
        report.write("\nDownload the latest VolDiff version from https://github.com/aim4r/VolDiff/")

    # PIDS FOR ANALYSIS ================================================================
    pids_to_analyse = {}
    if mode == "standalone":
        unusual_pids = get_all_pids(usual_processes)
        for pid in unusual_pids:
            if pid in pids_to_analyse:
                pids_to_analyse[pid] += ", non-default process"
            else:
                pids_to_analyse[pid] = "non-default process"
        malfind_pids = get_malfind_pids()
        for pid in malfind_pids:
            if pid in pids_to_analyse:
                pids_to_analyse[pid] += ", potential code injection"
            else:
                pids_to_analyse[pid] = "potential code injection"
    else:
        unusual_pids = get_diff_pids("conhost.exe|ipconfig.exe|cmd.exe")
        for pid in unusual_pids:
            if pid in pids_to_analyse:
                pids_to_analyse[pid] += ", new process"
            else:
                pids_to_analyse[pid] = "New process"
        malfind_pids = get_malfind_pids()
        for pid in malfind_pids:
            if pid in pids_to_analyse:
                pids_to_analyse[pid] += ", potential code injection"
            else:
                pids_to_analyse[pid] = "potential code injection"

    # MALWARE CHECKS - NETWORK ================================================================
    # compute unique IPs from netscan output:
    report_anomalies("IP addresses found in netscan output.", find_ips_domains_emails("netscan"))
    # compute unique IPs and domains from iehistory output:
    report_anomalies("IP addresses, domains and emails found in iehistory output.", find_ips_domains_emails("iehistory"))

    # MALWARE CHECKS - PROCESS ANOMALIES ================================================================
    # verify PID of System process = 4
    system_pids = get_pids("system")
    system_process_check = False
    for pid in system_pids:
        if pid != '4':
            system_process_check = True
            if pid in pids_to_analyse:
                pids_to_analyse[pid] += ", unusual pid (not 4)"
            else:
                pids_to_analyse[pid] = "unusual pid (not 4)"
    if system_process_check:
        l = get_associated_process_lines_pids(system_pids)
        report_anomalies("Unusual system process PID (different to 4).", l, "=", "psscan", 2)
    # verify that only one instance of certain processes is running:
    for process in uniq_processes:
        pids = get_pids(process)
        if len(pids) > 1:
            l = get_associated_process_lines_pids(get_pids(process))
            report_anomalies("Unexpected multiple instances of " + process + ".", l, "=", "psscan", 2)
    # verify that some processes do not have a child:
    nochild_processes = ["lsass.exe", "lsm.exe"]
    for process in nochild_processes:
        pids = get_pids(process)
        childs = get_childs_of(pids)
        if len(childs) > 0:
            parent_lines = get_associated_process_lines_pids(get_pids(process))
            child_lines = get_associated_process_lines_pids(childs)
            report_anomalies("Process " + process + " has unexpected childs.", parent_lines + child_lines, "=", "psscan", 2)
            for pid in pids:
                pidchilds = get_childs_of([pid, ])
                if len(pidchilds) > 0:
                    if pid in pids_to_analyse:
                        pids_to_analyse[pid] += ", has unexpected child process"
                    else:
                        pids_to_analyse[pid] = "has unexpected child process"
    # verify child/parent process relationships:
    for parent in parent_child:
        for child in parent_child[parent]:
            child_pids = get_pids(child)
            for pid in child_pids:
                parent_pids = get_parent_pids_of([pid, ])
                parent_procnames = get_procnames(parent_pids)
                for parent_procname in parent_procnames:
                    if parent_procname.lower() != parent.lower():
                        j = get_associated_process_lines_pids([pid, ])
                        l = get_associated_process_lines_pids(parent_pids)
                        report_anomalies("Unexpected parent process of " + child + " PID " + pid + " (" + parent_procname + " instead of " + parent + ").", j + l, "=", "psscan", 2)
                        if pid in pids_to_analyse:
                            pids_to_analyse[pid] += ", has an unexpected parent process"
                        else:
                            pids_to_analyse[pid] = "has an unexpected parent process"
    # verify that every process has a parent (except for explorer.exe, csrss.exe, wininit.exe and winlogon.exe)
    pids = get_all_pids()
    ppids = get_all_ppids("explorer.exe|csrss.exe|wininit.exe|winlogon.exe|system")
    for ppid in ppids:
        if ppid not in pids:
            l = get_associated_process_lines_ppids([ppid, ])
            report_anomalies("Parent process with PPID " + ppid + " is not listed in psscan output.", l, "=", "psscan", 2)
    # verify processes are running in expected sessions:
    for process in session0_processes:
        process_pids = get_pids(process)
        for pid in process_pids:
            session = get_session(pid)
            if session != '0':
                l = get_associated_process_lines_pids([pid, ], "pslist")
                report_anomalies("Process " + process + " (" + str(pid) + ") is running in unexpected session (" + session + " instead of 0).", l, "=", "pslist", 2)
                if pid in pids_to_analyse:
                    pids_to_analyse[pid] += ", running in an unusual session"
                else:
                    pids_to_analyse[pid] = "running in an unusual session"
    for process in session1_processes:
        process_pids = get_pids(process)
        for pid in process_pids:
            session = get_session(pid)
            if session != '1':
                l = get_associated_process_lines_pids([pid, ], "pslist")
                report_anomalies("Process " + process + " (" + str(pid) + ") is running in unexpected session (" + session + " instead of 1).", l, "=", "pslist", 2)
                if pid in pids_to_analyse:
                    pids_to_analyse[pid] += ", running in an unusual session"
                else:
                    pids_to_analyse[pid] = "running in an unusual session"
    # check process executable path:
    for process in process_execpath:
        process_pids = get_pids(process)
        for pid in process_pids:
            path = get_execpath(pid)
            correct_path = process_execpath[process]
            if path != "" and path.lower() != correct_path.lower():
                l = get_associated_process_lines_pids([pid, ], "psscan")
                report_anomalies("Process " + process + " (" + pid + ") is running from an unexpected path (" + path.lower() + " instead of " + correct_path.lower() + ").", l, "=", "psscan", 2)
                if pid in pids_to_analyse:
                    pids_to_analyse[pid] += ", running from an unexpected execution path"
                else:
                    pids_to_analyse[pid] = "running from an unexpected execution path"
    # verify if any processes have suspicious l33t names:
    leet_processes = anomaly_search("psscan", l33t_process_name, 'yes', '', "diff")
    report_anomalies("Suspicious process name found.", leet_processes, "=", "psscan", 2)
    for l in leet_processes:
        pid = re.sub(' +', ' ', l).split(' ')[2]
        if pid in pids_to_analyse:
            pids_to_analyse[pid] += ", has a suspicious process name"
        else:
            pids_to_analyse[pid] = "has a suspicious process name"
    # check if any process is running from a TEMP directory:
    pid_list = get_all_pids()
    for pid in pid_list:
        path = get_execpath(pid)
        process = get_procname(pid)
        if re.search(temp_filepath, path, re.IGNORECASE):
            l = get_associated_process_lines_pids([pid, ], "psscan")
            report_anomalies("Process " + process + " PID " + pid + " is running from a temporary folder (" + path.lower() + ").", l, "=", "psscan", 2)
            if pid in pids_to_analyse:
                pids_to_analyse[pid] += ", running from a temporary folder"
            else:
                pids_to_analyse[pid] = "running from a temporary folder"
    # verify if any hacker tools were used in process list:
    hacker_processes = anomaly_search("psscan", hacker_process_regex, 'yes', '', "diff")
    report_anomalies("Process(es) that may have been used for lateral movement, exfiltration etc.", hacker_processes, "=", "psscan", 2)
    # detect process hollowing:
    path = output_dir + "/procdump/"
    dumped_process_filenames = os.listdir(path)
    procnames = get_all_procnames()
    for procnameh in procnames:
        procpids = get_pids(procnameh)
        report_string = ""
        if len(procpids) > 1:
            procname_sizes = []
            unique_procname_sizes = []
            for pid in procpids:
                for dumped_process_filename in dumped_process_filenames:
                    if re.search("executable." + pid + ".exe", dumped_process_filename, re.IGNORECASE):
                        procname_sizes.append(os.stat(path + dumped_process_filename).st_size)
                        unique_procname_sizes = sorted(set(procname_sizes))
                        report_string += procnameh + "   " + pid + "   " + str(
                            os.stat(path + dumped_process_filename).st_size) + "\n"
            if len(unique_procname_sizes) > 1:
                report.write("\n\nPotential process hollowing detected in " + procnameh + " (based on size).")
                report.write(
                    "\n==========================================================================================================================\n")
                report.write("\nProcess       PID    Size")
                report.write("\n----------------------------\n")
                report.write(report_string)
    # detect processes with exit time but active threads:
    report_anomalies("Process(es) with exit time and active threads.", deadproc_activethreads(), "=", "psxview", 2)
    for d in deadproc_activethreads():
        pid = re.sub(' +', ' ', d).split(' ')[2]
        if pid in pids_to_analyse:
            pids_to_analyse[pid] += ", has an exit time and active threads"
        else:
            pids_to_analyse[pid] = "has an exit time and active threads"
    # check if any process has domain or enterprise admin privileges:
    high_privileges_regex = "Domain Admin|Enterprise Admin|Schema Admin"
    high_privileges = anomaly_search("getsids", high_privileges_regex, 'yes', '', "diff")
    report_anomalies("Process(es) with domain or enterprise admin privileges.", high_privileges)
    # check if any process has debug privileges:
    debug_privileges = anomaly_search("getsids", "debug", 'yes', '', "diff")
    report_anomalies("Process(es) with debug privileges.", debug_privileges)

    # MALWARE CHECKS - SUSPICIOUS DLLs/EXEs ================================================================
    # Prefetch artifacts (mftparser): [DUAL ONLY]
    if mode == "dual":
        prefetch_files = anomaly_search("mftparser", ".pf$", 'yes')
        prefetch_files_to_report = []
        for entry in prefetch_files:
            pf = ' '.join((re.sub(' +', ' ', entry).split(' ')[12:]))
            if pf != "":
                prefetch_files_to_report.append(pf)
        report_anomalies("Prefetch artifacts (mftparser).", prefetch_files_to_report)
    # Suspicious dlls/executables (dlllist) - loaded from temp folders, unusual new (DUAL ONLY), etc:
    temp_dlls = anomaly_search("dlllist", temp_filepath, 'yes')
    temp_dlls = extract_substrings(temp_dlls, temp_filepath)
    new_exe_excluded_regex = "system32|explorer.exe|iexplore.exe|VMware|wininit.exe|winlogon.exe|TrustedInstaller.exe|taskhost.exe|mscorsvw.exe|TPAutoConnect.exe|comctl32.dll"
    new_exes = anomaly_search("dlllist", "Command line", 'yes', new_exe_excluded_regex)
    if mode == "dual":
        new_dlls = anomaly_search("dlllist", "C:.*.dll", 'yes', "System32")
        new_dlls = extract_substrings(new_dlls, "C:.*.dll")
        dlls = temp_dlls + new_exes + new_dlls
    else:
        dlls = temp_dlls + new_exes
    dlls_to_report = []
    for dll in dlls:
        b = re.sub('"', '', dll)
        c = re.sub("Command line : ", "", b)
        dlls_to_report.append(c)
    dlls_to_report = tidy_list(dlls_to_report)
    report_anomalies("Suspicious DLLs/EXEs (dlllist).", dlls_to_report)
    # Hidden/suspicious DLLs/EXEs (ldrmodules):
    ldrmodules_excluded_regex_1 = "System32\\\msxml6r.dll|System32\\\oleaccrc.dll|System32\\\imageres.dll|System32\\\\ntdll.dll|System32\\\winlogon.exe|System32\\\services.exe|System32\\\tquery.dll|System32\\\wevtapi.dll"
    hiddendlls1_ldrmodules = anomaly_search("ldrmodules", "False  False  False.*dll$|False  False  False.*exe$", 'yes', ldrmodules_excluded_regex_1)
    ldrmodules_excluded_regex_2 = "system32|explorer.exe|iexplore.exe|.fon$|TrustedInstaller.exe|VMware\\\VMware Tools|mscorsvw.exe"
    hiddendlls2_ldrmodules = anomaly_search("ldrmodules", "False", 'yes', ldrmodules_excluded_regex_2)
    hiddendlls3_ldrmodules = anomaly_search("ldrmodules", "no name", 'yes')
    hiddendlls_ldrmodules = hiddendlls1_ldrmodules + hiddendlls2_ldrmodules + hiddendlls3_ldrmodules
    hiddendlls_ldrmodules = sorted(set(hiddendlls_ldrmodules))
    report_anomalies("Hidden/suspicious DLLs/EXEs (ldrmodules).", hiddendlls_ldrmodules, "=", "ldrmodules", 2)
    # Suspicious DLLs (atoms):
    dll_atoms = anomaly_search("atoms", ".dll$", 'yes', usual_atoms_dlls)
    report_anomalies("Suspicious DLLs (atoms).", dll_atoms, "=", "atoms", 2)
    # Suspicious DLLs (atomscan):
    dll_atomscan = anomaly_search("atomscan", ".dll$", 'yes', usual_atoms_dlls)
    report_anomalies("Suspicious DLLs (atomscan).", dll_atomscan, "=", "atomscan", 2)
    # DLLs used for password theft or VM evasion (ldrmodules):
    suspdll_ldrmodules = anomaly_search("ldrmodules", hacker_dll_regex, 'yes')
    report_anomalies("DLLs used for password theft or VM evasion (ldrmodules).", suspdll_ldrmodules, "=", "ldrmodules", 2)

    # MALWARE CHECKS - SUSPICIOUS FILES ================================================================
    # Interesting files on disk (filescan)
    if mode == "dual":
        suspicious_files1 = anomaly_search("filescan", susp_filepath, 'yes', "\.db$|\.lnk$|\.ini$|\.log$", "diff")
        suspicious_files2 = anomaly_search("filescan", susp_extensions_regex, 'yes', "suspend-vm-default\.bat")
        suspicious_files = suspicious_files1 + suspicious_files2
    else:
        suspicious_files = anomaly_search("filescan", susp_extensions_regex, 'yes')
    suspicious_files_to_report = []
    for entry in suspicious_files:
        en = ' '.join((re.sub(' +', ' ', entry).split(' ')[4:]))
        if en != "":
            suspicious_files_to_report.append(en)
    suspicious_files_to_report = sorted(set(suspicious_files_to_report))
    report_anomalies("Interesting files on disk (filescan).", suspicious_files_to_report, "=", "filescan", 0, 100)
    # Alternate Data Stream (ADS) files (mftparser):
    ads_files = anomaly_search("mftparser", "DATA ADS", 'yes', "Bad$|Max$")
    report_anomalies("Alternate Data Stream (ADS) files (mftparser).", ads_files)

    # MALWARE CHECKS - MISC ================================================================
    # find suspicious desktop instances: [DUAL ONLY]
    if mode == "dual":
        new_desktops = anomaly_search("deskscan", "Desktop:", 'yes', '', 'diff')
        report_anomalies("New desktop instances (deskscan).", new_desktops)
    # find interesting entries in hosts file
    if mode == "dual":
        hostsb = get_hosts_contents(baseline_memory_image)
        hostsi = get_hosts_contents(infected_memory_image)
        hosts = []
        for line in hostsi:
            if line not in hostsb:
                hosts.append(line)
    else:
        hosts = get_hosts_contents(memory_image)
    report_anomalies("Interesting 'hosts' file entries.", hosts)

    # MALWARE CHECKS - PERSISTENCE ================================================================
    # find new services: [Dual Only]
    if mode == "dual":
        services_to_report = filter_new_services()
        report_anomalies("Notable new entries from svcscan.", services_to_report)
    # highlight temp folders appearing in services: [Standalone Only]
    if mode == "standalone":
        temp_services = anomaly_search("svcscan", temp_filepath, 'yes')
        report_anomalies("Temp folders appearing in svcscan output.", temp_services)

    # MALWARE CHECKS - KERNEL ================================================================
    # Keylogger traces (messagehooks):
    keylogger_messagehooks = anomaly_search("messagehooks", "KEYBOARD", 'yes')
    report_anomalies("Keylogger traces (messagehooks).", keylogger_messagehooks, "=", "messagehooks", 2)
    # Unusual timers:
    unusual_timers = anomaly_search_inverted("timers", usual_timers, 'yes')
    if mode == "standalone":
        report_anomalies("Unusual timers.", unusual_timers[2:], "=", "timers", 2)
    else:
        report_anomalies("Unusual timers.", unusual_timers, "=", "timers", 2)
    # Suspicious 'unknown' timers:
    unknown_timers = anomaly_search("timers", "UNKNOWN", 'yes')
    report_anomalies("Suspicious 'unknown' timers.", unknown_timers, "=", "timers", 2)
    # find unusual gditimers:
    unusual_gditimers = anomaly_search_inverted("gditimers", usual_gditimers, 'yes')
    if mode == "standalone":
        report_anomalies("Unusual gditimers.", unusual_gditimers[2:], "=", "gditimers", 2, 20)
    else:
        report_anomalies("Unusual gditimers.", unusual_gditimers, "=", "gditimers", 2, 20)
    # Suspicious 'unknown' callbacks:
    unknown_callbacks = anomaly_search("callbacks", "UNKNOWN", 'yes')
    report_anomalies("Suspicious 'unknown' callbacks.", unknown_callbacks, "=", "callbacks", 2)
    # Suspicious 'unknown' drivermodules:
    unknown_drivermodules = anomaly_search("drivermodule", "UNKNOWN", 'yes')
    report_anomalies("Suspicious 'unknown' drivermodules.", unknown_drivermodules, "=", "drivermodule", 2, 20)
    # Suspicious 'unknown' driverirp entries:
    unknown_driverirp = anomaly_search("driverirp", "UNKNOWN", 'yes')
    report_anomalies("Suspicious 'unknown' driverirp entries.", unknown_driverirp, "=", "", 0, 20)
    # Unusual ssdt entries:
    unusual_ssdt = anomaly_search_inverted("ssdt", usual_ssdt, 'yes', "Entry")
    report_anomalies("Unusual ssdt entries.", unusual_ssdt, "=", "", 0, 20)
    # Suspicious idt entries:
    susp_idt = anomaly_search("idt", "rsrc", 'yes')
    report_anomalies("Suspicious idt entries.", susp_idt, "=", "idt", 2)
    # Suspicious orphan threads:
    orphan_threads = anomaly_search("threads", ".*", 'yes')
    if mode == "standalone":
        report_anomalies("Suspicious orphan threads.", orphan_threads[2:])
    else:
        report_anomalies("Suspicious orphan threads.", orphan_threads)

    # IMPSCAN AND PROCDUMP EXECUTION (IN PREPERATION FOR PROCESS PROFILER) ================================================================
    # run impscan plugin in //
    impscanfolder = tmpfolder + "impscan/"
    if not os.path.isdir(impscanfolder):
        os.makedirs(impscanfolder)
    else:
        shutil.rmtree(impscanfolder)
        os.makedirs(impscanfolder)
    plugin = "impscan"
    i = 0
    subprocesses = {}
    for pid in pids_to_analyse:
        if mode == "dual":
            with open(impscanfolder + str(pid) + ".txt", "w") as f:
                subprocesses[str(pid)] = Popen([path_to_volatility, "--profile", profile, "-f", infected_memory_image, plugin, "--pid=" + str(pid)], stdout=f, stderr=devnull)
        else:
            with open(impscanfolder + str(pid) + ".txt", "w") as f:
                subprocesses[str(pid)] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, plugin, "--pid=" + str(pid)], stdout=f, stderr=devnull)
        i += 1
        if i >= max_concurrent_subprocesses:
            for subproc in subprocesses:
                subprocesses[subproc].wait()
            i = 0
            subprocesses = {}
    for subproc in subprocesses:
        subprocesses[subproc].wait()

    # dump suspicious processes to disk in //
    subprocesses = {}
    i = 0
    for pid in pids_to_analyse:
        procname = get_procname(pid)
        dumpfolder = tmpfolder + str(pid) + "/"
        if not os.path.isdir(dumpfolder):
            os.makedirs(dumpfolder)
        else:
            shutil.rmtree(dumpfolder)
            os.makedirs(dumpfolder)
        offsets = []
        if procname != "":
            f = open_full_plugin("psscan", 2)
            for line in f:
                if re.search(procname + " +" + str(pid) + " ", line, re.IGNORECASE):
                    offsets.append(re.sub(' +', ' ', line).split(' ')[0])
            f.close()
        for offset in offsets:
            if mode == "dual":
                subprocesses[offset] = Popen([path_to_volatility, "--profile", profile, "-f", infected_memory_image, "procdump", "--offset=" + offset, "--dump-dir=" + dumpfolder], stdout=devnull, stderr=devnull)
            else:
                subprocesses[offset] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, "procdump", "--offset=" + offset, "--dump-dir=" + dumpfolder], stdout=devnull, stderr=devnull)
            i += 1
            if i >= max_concurrent_subprocesses:
                for subproc in subprocesses:
                    subprocesses[subproc].wait()
                i = 0
                subprocesses = {}
        if mode == "dual":
            subprocesses[str(pid)] = Popen([path_to_volatility, "--profile", profile, "-f", infected_memory_image, "malfind", "--pid=" + str(pid), "--dump-dir=" + dumpfolder], stdout=devnull, stderr=devnull)
        else:
            subprocesses[str(pid)] = Popen([path_to_volatility, "--profile", profile, "-f", memory_image, "malfind", "--pid=" + str(pid), "--dump-dir=" + dumpfolder], stdout=devnull, stderr=devnull)
        i += 1
        if i >= max_concurrent_subprocesses:
            for subproc in subprocesses:
                subprocesses[subproc].wait()
            i = 0
            subprocesses = {}
    for subproc in subprocesses:
        subprocesses[subproc].wait()

    # DEV MODE SWITCH ================================================================
    if "--devmode" in sys.argv:
        raw_input('\nCheckpoint before executing process profiler.')

    # MALWARE CHECKS - PROCESS PROFILER ================================================================
    # dispay list of processes that will be analysed
    if len(pids_to_analyse) > 0:
        report.write("\n\nProcesses that will be analysed in the next section:")
        report.write(
            "\n==========================================================================================================================\n")
        for pid in pids_to_analyse:
            report.write(get_procname(pid) + " (" + str(pid) + "): " + pids_to_analyse[pid] + ".\n")
        l = get_associated_process_lines_pids(pids_to_analyse, "psscan")
        report_anomalies("Psscan output for suspicious processes.", l, "-", "psscan", 2)

    for pid in pids_to_analyse:
        procname = get_procname(pid)
        report.write("\n\nAnalysis results for " + procname + " PID " + pid + " (" + pids_to_analyse[pid] + "):")
        report.write(
            "\n==========================================================================================================================")
        # print VirusTotal scan results of exec MD5 hash
        if vt_api_key != "":
            susp_md5 = get_md5(pid)
            if susp_md5 != "":
                report_virustotal_md5_results(susp_md5, vt_api_key)
        # print psxview output for the process (psxview)
        l = get_associated_process_lines_pids([pid, ], "psxview")
        report_anomalies("Psxview results:", l, '-', "psxview", 2)
        # print comand line (cmdline)
        cmdline = get_cmdline(pid)
        report_anomalies("Command line (cmdline):", cmdline, '-')
        # analyse network connections (netscan)
        susp_connections = anomaly_search("netscan", " " + str(pid), "yes", "", "diff")
        report_anomalies("Network connections (netscan):", susp_connections, '-', "netscan", 1)
        # print parent process information
        if len(get_parent_pids_of([pid, ])) > 0:
            ppid = get_parent_pids_of([pid, ])[0]
            pids = get_all_pids()
            if ppid not in pids:
                l = get_associated_process_lines_ppids([ppid, ])
                report_anomalies("Parent process (PPID " + ppid + ") is not listed in psscan output:", l, '-', "psscan",
                                 2)
            else:
                l = get_associated_process_lines_pids([ppid, ])
                j = get_associated_process_lines_pids([pid, ])
                report_anomalies("Parent process (PPID " + ppid + ") information:", j + l, '-', "psscan", 2)
        # check if process has an "expected" parent
        check_expected_parent(pid)
        # print child process information
        childs = get_childs_of([pid, ])
        l = get_associated_process_lines_pids(childs)
        report_anomalies("Child process(es):", l, '-', "psscan", 2)
        # print malfind injections (malfind)
        malfind_injections = get_malfind_injections(pid, mode)
        report_anomalies("Code injection (malfind):", malfind_injections, '-')
        # print associated services (svcscan)
        susp_services = get_associated_services(pid)
        report_anomalies("Associated service(s) (svcscan):", susp_services, '-')
        # print envars (envars)
        associated_envars = anomaly_search("envars", " " + str(pid) + " ", "yes", "", "diff")
        report_anomalies("Environment variables (envars):", associated_envars, '-', "envars", 2)
        # print interesting DLLs (ldrmodules)
        dlls1 = anomaly_search("ldrmodules", hacker_dll_regex, 'yes', "", "diff")
        dlls2 = anomaly_search("ldrmodules", "no name", 'yes', "", "diff")
        dlls3 = anomaly_search("ldrmodules", "False  False  False.*dll$|False  False  False.*exe$", 'yes', ldrmodules_excluded_regex_1, "diff")
        dlls4 = anomaly_search("ldrmodules", "False", 'yes', ldrmodules_excluded_regex_2, "diff")
        dlls = sorted(set(dlls1 + dlls2 + dlls3 + dlls4))
        dlls_to_report = []
        for dll in dlls:
            if re.search(" " + str(pid) + " ", dll, re.IGNORECASE):
                dlls_to_report.append(dll)
        report_anomalies("Interesting DLLs (ldrmodules):", dlls_to_report, '-', "ldrmodules", 2)
        # print mutants (handles) DUAL ONLY
        if mode == "dual":
            mutants = anomaly_search("handles", " " + str(pid) + " .*Mutant", "yes", "", "diff")
            report_anomalies("Mutants accessed (handles):", mutants, '-', "handles", 2)
        # print interesting files accessed (handles)
        files1 = anomaly_search("handles", " " + str(pid) + " .*\\\Device\\\RawIp", 'yes', '', "diff")
        files2 = anomaly_search("handles", " " + str(pid) + " .*Device\\\(LanmanRedirector|Mup)", 'yes', '', "diff")
        files3 = anomaly_search("handles", " " + str(pid) + " .*\..{2,3}$", 'yes', "\.mui$", "diff")
        files_to_report = []
        filelist = sorted(set(files1 + files2 + files3))
        for i in filelist:
            if re.search("File", i, re.IGNORECASE):
                files_to_report.append(i)
        report_anomalies("Interesting files accessed (handles):", files_to_report, '-', "handles", 2)
        # print privileges (privs)
        privs = anomaly_search("privs", " " + str(pid) + " ", "yes", "", "diff")
        report_anomalies("Enabled privileges (privs):", privs, '-', "privs", 2)
        # print high privileges (getsids)
        sids = anomaly_search("getsids", "\(" + str(pid) + "\).*(Domain Admin|Enterprise Admin|Schema Admin)", "yes", "", "diff")
        report_anomalies("Process privileges (getsids):", sids, '-')
        # check if process has a raw socket handle:
        raw_sockets = get_raw_sockets(pid)
        report_anomalies("Raw socket handles:", raw_sockets, "-", "handles", 2)
        # check if process has a handle to a remote mapped share:
        share_handles = get_remote_share_handles(pid)
        report_anomalies("Remote share handles:", share_handles, "-", "handles", 2)
        # print handles to interesting registry entries (handles)
        if get_procname(pid) != 'explorer.exe':
            analyse_registry(pid)
        # print interesting imports (impscan)
        if get_procname(pid) != 'explorer.exe':
            analyse_imports(pid)
        # find suspicious strings in process strings (procdump + malfind + strings)
        analyse_strings(pid)

    # CLEANUP AND CLOSURE ================================================================
    script_completion(starttime)


if __name__ == '__main__':
    main()
