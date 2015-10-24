####################################################################################
#### script name: linux_mem_diff.py                                             ####
#### Description: Script to perform Linux Memory Diff Analysis Using Volatility ####
#### Author: Monnappa                                                           ####
####################################################################################

import subprocess
import optparse
import sys
import os

# set the below variables with appropriate values, this is mandatory
python_path = r''         # path to python interpreter, example: r'/usr/bin/python'
vol_path = r''            # path to Volatility script(vol.py), example: r'/root/Volatility/vol.py'

# set the below variables, this is optional, these values can be given while running the script
clean_mem_image = ""
infected_mem_image = ""
mem_image_profile = ""
out_report_file = ""


class MemDiff:
    def __init__(self, python_path, vol_path, clean_mem_file, infected_mem_file, profile):
        self.clean_mem_file = clean_mem_file
        self.infected_mem_file = infected_mem_file
        self.profile = profile
        self.volatility = vol_path
        self.python = python_path
        self.ldrmodules_clean = ""
        self.ldrmoudles_infected = ""
        self.proc_info_clean = {}
        self.proc_info_infected = {}
        self.proc_path_clean = {}
        self.proc_path_infected = {}
        self.proc_lib_clean = {}
        self.proc_lib_infected = {}
        self.ldrmodules_header = ""
        self.ldrmodules_header1 = ""
        self.update_proc_info_clean()
        self.update_proc_info_infected()
        self.update_proc_path_lib_clean()
        self.update_proc_path_lib_infected()


    def run_cmd(self, mem_file, cmd, args=[]):
        pargs = [self.python, self.volatility, self.profile, '-f', mem_file, cmd]
        if len(args):
            pargs.extend(args)
        proc = subprocess.Popen(pargs, stdout=subprocess.PIPE)
        return proc.communicate()[0]

    def ldrmodules(self, mem_file):
        return self.run_cmd(mem_file, 'linux_ldrmodules')

    def update_proc_info_clean(self):
        self.ldrmodules_clean = self.ldrmodules(self.clean_mem_file)
        ldrmodules_clean = self.ldrmodules_clean.splitlines()
        self.ldrmodules_header = ldrmodules_clean[0]
        self.ldrmodules_header1 = ldrmodules_clean[1]
        ldrmodules_clean = ldrmodules_clean[2:]
        for line in ldrmodules_clean:
            pid, proc_name, start, proc_path, kernel, libc = line.split()
            if proc_name in self.proc_info_clean:
                self.proc_info_clean[proc_name].append([pid, proc_name, proc_path,line])
            else:
                self.proc_info_clean[proc_name] = []
                self.proc_info_clean[proc_name].append([pid, proc_name, proc_path,line])

    def update_proc_info_infected(self):
        self.ldrmodules_infected = self.ldrmodules(self.infected_mem_file)
        ldrmodules_infected = self.ldrmodules_infected.splitlines()
        ldrmodules_infected = ldrmodules_infected[2:]
        for line in ldrmodules_infected:
            pid, proc_name, start, proc_path, kernel, libc = line.split()
            if proc_name in self.proc_info_infected:
                self.proc_info_infected[proc_name].append([pid, proc_name, proc_path,line])
            else:
                self.proc_info_infected[proc_name] = []
                self.proc_info_infected[proc_name].append([pid, proc_name, proc_path,line])

    def update_proc_path_lib_clean(self):
        for each_proc in self.proc_info_clean:
            proc_path = []
            proc_lib = []
            each_proc_info = self.proc_info_clean[each_proc]
            for each_info in each_proc_info:
                path = each_info[2]
                if ".so" in path:
                    proc_lib.append(path)
                else:
                    proc_path.append(path)

            if each_proc in self.proc_path_clean:
                self.proc_path_clean[each_proc].extend(list(set(proc_path)))
            else:
                self.proc_path_clean[each_proc] = []
                self.proc_path_clean[each_proc].extend(list(set(proc_path)))

            if each_proc in self.proc_lib_clean:
                self.proc_lib_clean[each_proc].extend(list(set(proc_lib)))
            else:
                self.proc_lib_clean[each_proc] = []
                self.proc_lib_clean[each_proc].extend(list(set(proc_lib)))

    def update_proc_path_lib_infected(self):
        for each_proc in self.proc_info_infected:
            proc_path = []
            proc_lib = []
            each_proc_info = self.proc_info_infected[each_proc]
            for each_info in each_proc_info:
                path = each_info[2]
                if ".so" in path:
                    proc_lib.append(path)
                else:
                    proc_path.append(path)

            if each_proc in self.proc_path_infected:
                self.proc_path_infected[each_proc].extend(list(set(proc_path)))
            else:
                self.proc_path_infected[each_proc] = []
                self.proc_path_infected[each_proc].extend(list(set(proc_path)))

            if each_proc in self.proc_lib_infected:
                self.proc_lib_infected[each_proc].extend(list(set(proc_lib)))
            else:
                self.proc_lib_infected[each_proc] = []
                self.proc_lib_infected[each_proc].extend(list(set(proc_lib)))



    def pslist(self, mem_file):
        return self.run_cmd(mem_file, 'linux_pslist')

    def psxview(self, mem_file):
        return self.run_cmd(mem_file, 'linux_psxview')

    def pidhashtable(self, mem_file):
        return self.run_cmd(mem_file,'linux_pidhashtable')

    def netstat(self, mem_file):
        args = ["-U"]
        return self.run_cmd(mem_file, 'linux_netstat', args)

    def ifconfig(self, mem_file):
        return self.run_cmd(mem_file, 'linux_ifconfig')

    def list_raw(self, mem_file):
        return self.run_cmd(mem_file,'linux_list_raw')

    def library_list(self, mem_file):
        return self.run_cmd(mem_file,'linux_library_list')

    def dmesg(self, mem_file):
        return self.run_cmd(mem_file,'linux_dmesg')

    def lsmod(self, mem_file):
        return self.run_cmd(mem_file,'linux_lsmod')

    def check_modules(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_modules')

    def hidden_modules(self, mem_file):
        return self.run_cmd(mem_file,'linux_hidden_modules')

    def kernel_opened_files(self, mem_file):
        return self.run_cmd(mem_file,'linux_kernel_opened_files')

    def check_creds(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_creds')

    def keyboard_notifiers(self, mem_file):
        return self.run_cmd(mem_file,'linux_keyboard_notifiers')

    def check_tty(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_tty')

    def check_syscall(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_syscall')

    def bash_history(self, mem_file):
        return self.run_cmd(mem_file,'linux_bash')

    def check_fop(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_fop')

    def check_afinfo(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_afinfo')

    def netfilter(self, mem_file):
        return self.run_cmd(mem_file,'linux_netfilter')

    def check_inline_kernel(self, mem_file):
        return self.run_cmd(mem_file,'linux_check_inline_kernel')

    def malfind(self, mem_file):
        return self.run_cmd(mem_file,'linux_malfind')

    def plthook(self, mem_file):
        return self.run_cmd(mem_file,'linux_plthook')

    def apihooks(self, mem_file):
        return self.run_cmd(mem_file,'linux_apihooks')

    def diff_pslist(self):
        diff_list = []
        pslist_clean = self.pslist(self.clean_mem_file)
        pslist_infected = self.pslist(self.infected_mem_file)
        pslist_clean = pslist_clean.splitlines()
        header = pslist_clean[0]
        clean_pslist = {}
        for line in pslist_clean:
            splitted = line.split()
            proc_name = splitted[1]
            pid = splitted[2]
            clean_pslist[proc_name] = line
        pslist_infected = pslist_infected.splitlines()
        infected_pslist = {}
        for line in pslist_infected:
            splitted = line.split()
            proc_name = splitted[1]
            pid = splitted[2]
            infected_pslist[proc_name] = line
        diff_list.append(header)
        for each in infected_pslist:
            if each not in clean_pslist:
                if infected_pslist[each]:
                    diff_list.append(infected_pslist[each])
            else:
                if each in self.proc_path_clean and each in self.proc_path_infected:
                    proc_paths_infected = self.proc_path_infected[each]
                    proc_paths_clean = self.proc_path_clean[each]
                    for each_path in proc_paths_infected:
                        if each_path not in proc_paths_clean:
                            diff_list.append(infected_pslist[each])
        return diff_list

    def diff_psxview(self):
        diff_list = []
        psxview_clean = self.psxview(self.clean_mem_file)
        psxview_infected = self.psxview(self.infected_mem_file)
        psxview_clean = psxview_clean.splitlines()
        header = psxview_clean[0]
        clean_psxview = {}
        for line in psxview_clean:
            splitted = line.split()
            proc_name = splitted[1]
            pid = splitted[2]
            clean_psxview[proc_name] = line
        psxview_infected = psxview_infected.splitlines()
        infected_psxview = {}
        for line in psxview_infected:
            splitted = line.split()
            proc_name = splitted[1]
            pid = splitted[2]
            infected_psxview[proc_name] = line
        diff_list.append(header)
        for each in infected_psxview:
            if each not in clean_psxview:
                if infected_psxview[each]:
                    diff_list.append(infected_psxview[each])
            else:
                if each in self.proc_path_clean and each in self.proc_path_infected:
                    proc_paths_infected = self.proc_path_infected[each]
                    proc_paths_clean = self.proc_path_clean[each]
                    for each_path in proc_paths_infected:
                        if each_path not in proc_paths_clean:
                            diff_list.append(infected_psxview[each])
        return diff_list

    def diff_pidhashtable(self):
        diff_list = []
        pidhashtable_clean = self.pidhashtable(self.clean_mem_file)
        pidhashtable_infected = self.pidhashtable(self.infected_mem_file)
        pidhashtable_clean = pidhashtable_clean.splitlines()
        header = pidhashtable_clean[0]
        clean_pidhashtable = {}
        for line in pidhashtable_clean:
            splitted = line.split()
            proc_name = splitted[1]
            pid = splitted[2]
            clean_pidhashtable[proc_name] = line
        pidhashtable_infected = pidhashtable_infected.splitlines()
        infected_pidhashtable = {}
        for line in pidhashtable_infected:
            splitted = line.split()
            proc_name = splitted[1]
            pid = splitted[2]
            infected_pidhashtable[proc_name] = line
        diff_list.append(header)
        for each in infected_pidhashtable:
            if each not in clean_pidhashtable:
                if infected_pidhashtable[each]:
                    diff_list.append(infected_pidhashtable[each])
            else:
                if each in self.proc_path_clean and each in self.proc_path_infected :
                    proc_paths_infected = self.proc_path_infected[each]
                    proc_paths_clean = self.proc_path_clean[each]
                    for each_path in proc_paths_infected:
                        if each_path not in proc_paths_clean:
                            diff_list.append(infected_pidhashtable[each])
        return diff_list

    def diff_netstat(self):
        diff_list = []
        add_entry = True
        netstat_clean = self.netstat(self.clean_mem_file)
        netstat_infected = self.netstat(self.infected_mem_file)
        netstat_clean = netstat_clean.splitlines()
        netstat_infected = netstat_infected.splitlines()
        for each in netstat_infected:
            inf_entry,inf_pid = each.split("/")
            for each_line in netstat_clean:
                if inf_entry in each_line:
                    add_entry = False
                    break
                else:
                    continue
            if add_entry:
                diff_list.append(each)
            else:
                add_entry = True

        return diff_list

    def diff_ifconfig(self):
        diff_list = []
        ifconfig_clean = self.ifconfig(self.clean_mem_file)
        ifconfig_infected = self.ifconfig(self.infected_mem_file)
        ifconfig_clean = ifconfig_clean.splitlines()
        ifconfig_infected = ifconfig_infected.splitlines()
        header = ifconfig_clean[0]
        diff_list.append(header)
        for each in ifconfig_infected:
            if each not in ifconfig_clean:
                diff_list.append(each)
        return diff_list

    def diff_list_raw(self):
        diff_list = []
        list_raw_clean = self.list_raw(self.clean_mem_file)
        list_raw_infected = self.list_raw(self.infected_mem_file)
        list_raw_clean = list_raw_clean.splitlines()
        list_raw_infected = list_raw_infected.splitlines()
        header = list_raw_clean[0]
        diff_list.append(header)
        for each in list_raw_infected:
            if each not in list_raw_clean:
                diff_list.append(each)
        return diff_list

    def diff_library_list(self):
        diff_list = []
        library_list_clean = self.library_list(self.clean_mem_file)
        library_list_infected = self.library_list(self.infected_mem_file)
        library_list_clean = library_list_clean.splitlines()
        library_list_infected = library_list_infected.splitlines()
        header = library_list_clean[0]
        diff_list.append(header)
        header1 = library_list_clean[1]
        diff_list.append(header1)
        clean_proc_line = {}
        clean_proc_lib_list = {}
        library_list_clean = library_list_clean[2:]
        for line in library_list_clean:
            splitted = line.split()
            proc_name = splitted[0]
            lib_name = splitted[3]
            if proc_name in clean_proc_line:
                clean_proc_line[proc_name].append(line)
            else:
                clean_proc_line[proc_name] = []
                clean_proc_line[proc_name].append(line)

            if proc_name in clean_proc_lib_list:
                clean_proc_lib_list[proc_name].append(lib_name)
            else:
                clean_proc_lib_list[proc_name] = []
                clean_proc_lib_list[proc_name].append(lib_name)

        infected_proc_line= {}
        infected_proc_lib_list = {}
        library_list_infected = library_list_infected[2:]
        for line in library_list_infected:
            splitted = line.split()
            proc_name = splitted[0]
            lib_name = splitted[3]
            if proc_name in infected_proc_line:
                infected_proc_line[proc_name].append(line)
            else:
                infected_proc_line[proc_name] = []
                infected_proc_line[proc_name].append(line)
            if proc_name in infected_proc_lib_list:
                infected_proc_lib_list[proc_name].append(lib_name)
            else:
                infected_proc_lib_list[proc_name] = []
                infected_proc_lib_list[proc_name].append(lib_name)

        for each in infected_proc_lib_list:
            if each not in clean_proc_lib_list:
                diff_list.extend(infected_proc_line[each])
            else:
                clean_libs = clean_proc_lib_list[each]
                infected_libs = infected_proc_lib_list[each]
                for each_lib in infected_libs:
                    if each_lib not in clean_libs:
                        infected_lines = infected_proc_line[each]
                        for each_line in infected_lines:
                            if each_lib in each_line:
                                diff_list.append(each_line)
        return diff_list


    def diff_ldrmodules(self):
        diff_list = []
        diff_list.append(self.ldrmodules_header)
        diff_list.append(self.ldrmodules_header1)
        for proc in self.proc_info_infected:
            add_module = True
            if proc not in self.proc_info_clean:
                info_list = self.proc_info_infected[proc]
                for info in info_list:
                    line = info[3]
                    diff_list.append(line)
            else:
                clean_info_list = self.proc_info_clean[proc]
                infected_info_list = self.proc_info_infected[proc]
                for inf_info in infected_info_list:
                    inf_mod_path = inf_info[2]
                    inf_line = inf_info[3]
                    for cln_info in clean_info_list:
                        cln_mod_path = cln_info[2]
                        if inf_mod_path in cln_mod_path:
                            add_module = False
                            break
                        else:
                            continue
                    if add_module:
                        diff_list.append(inf_line)
                    else:
                        add_module=True

        return diff_list

    def diff_dmesg(self):
        diff_list = []
        dmesg_clean = self.dmesg(self.clean_mem_file)
        dmesg_infected = self.dmesg(self.infected_mem_file)
        dmesg_clean = dmesg_clean.splitlines()
        dmesg_infected = dmesg_infected.splitlines()
        for each in dmesg_infected:
            if each not in dmesg_clean:
                diff_list.append(each)
        return diff_list

    def diff_lsmod(self):
        diff_list = []
        lsmod_clean = self.lsmod(self.clean_mem_file)
        lsmod_infected = self.lsmod(self.infected_mem_file)
        lsmod_clean = lsmod_clean.splitlines()
        clean_lsmod = {}
        for line in lsmod_clean:
            splitted = line.split()
            module = splitted[1]
            clean_lsmod[module] = line
        lsmod_infected = lsmod_infected.splitlines()
        infected_lsmod = {}
        for line in lsmod_infected:
            splitted = line.split()
            module = splitted[1]
            infected_lsmod[module] = line
        for each in infected_lsmod:
            if each not in clean_lsmod:
                diff_list.append(infected_lsmod[each])
        return diff_list

    def diff_check_modules(self):
        diff_list = []
        check_modules_clean = self.check_modules(self.clean_mem_file)
        check_modules_infected = self.check_modules(self.infected_mem_file)
        check_modules_clean = check_modules_clean.splitlines()
        header = check_modules_clean[0]
        clean_check_modules = {}
        for line in check_modules_clean:
            splitted = line.split()
            module = splitted[1]
            clean_check_modules[module] = line
        check_modules_infected = check_modules_infected.splitlines()
        infected_check_modules = {}
        for line in check_modules_infected:
            splitted = line.split()
            module = splitted[1]
            infected_check_modules[module] = line
        diff_list.append(header)
        for each in infected_check_modules:
            if each not in clean_check_modules:
                if infected_check_modules[each]:
                    diff_list.append(infected_check_modules[each])
        return diff_list

    def diff_hidden_modules(self):
        diff_list = []
        hidden_modules_clean = self.hidden_modules(self.clean_mem_file)
        hidden_modules_infected = self.hidden_modules(self.infected_mem_file)
        hidden_modules_clean = hidden_modules_clean.splitlines()
        header = hidden_modules_clean[0]
        clean_hidden_modules = {}
        for line in hidden_modules_clean:
            splitted = line.split()
            module = splitted[1]
            clean_hidden_modules[module] = line
        hidden_modules_infected = hidden_modules_infected.splitlines()
        infected_hidden_modules = {}
        for line in hidden_modules_infected:
            splitted = line.split()
            module = splitted[1]
            infected_hidden_modules[module] = line
        diff_list.append(header)
        for each in infected_hidden_modules:
            if each not in clean_hidden_modules:
                if infected_hidden_modules[each]:
                    diff_list.append(infected_hidden_modules[each])
        return diff_list

    def diff_kernel_opened_files(self):
        diff_list = []
        kernel_opened_files_clean = self.kernel_opened_files(self.clean_mem_file)
        kernel_opened_files_infected = self.kernel_opened_files(self.infected_mem_file)
        kernel_opened_files_clean = kernel_opened_files_clean.splitlines()
        header = kernel_opened_files_clean[0]
        clean_kernel_opened_files = {}
        for line in kernel_opened_files_clean:
            splitted = line.split()
            file_path = splitted[1]
            clean_kernel_opened_files[file_path] = line
        kernel_opened_files_infected = kernel_opened_files_infected.splitlines()
        infected_kernel_opened_files = {}
        for line in kernel_opened_files_infected:
            splitted = line.split()
            file_path = splitted[1]
            infected_kernel_opened_files[file_path] = line
        diff_list.append(header)
        for each in infected_kernel_opened_files:
            if each not in clean_kernel_opened_files:
                if infected_kernel_opened_files[each]:
                    diff_list.append(infected_kernel_opened_files[each])
        return diff_list

    def diff_check_creds(self):
        diff_list = []
        check_creds_clean = self.check_creds(self.clean_mem_file)
        check_creds_infected = self.check_creds(self.infected_mem_file)
        check_creds_clean = check_creds_clean.splitlines()
        check_creds_infected = check_creds_infected.splitlines()
        header = check_creds_clean[0]
        diff_list.append(header)
        for each in check_creds_infected:
            if each not in check_creds_clean:
                diff_list.append(each)
        return diff_list

    def diff_keyboard_notifiers(self):
        diff_list = []
        keyboard_notifiers_clean = self.keyboard_notifiers(self.clean_mem_file)
        keyboard_notifiers_infected = self.keyboard_notifiers(self.infected_mem_file)
        keyboard_notifiers_clean = keyboard_notifiers_clean.splitlines()
        keyboard_notifiers_infected = keyboard_notifiers_infected.splitlines()
        header = keyboard_notifiers_clean[0]
        diff_list.append(header)
        for each in keyboard_notifiers_infected:
            if each not in keyboard_notifiers_clean:
                diff_list.append(each)
        return diff_list

    def diff_check_tty(self):
        diff_list = []
        check_tty_clean = self.check_tty(self.clean_mem_file)
        check_tty_infected = self.check_tty(self.clean_mem_file)
        check_tty_clean = check_tty_clean.splitlines()
        check_tty_infected = check_tty_infected.splitlines()
        header = check_tty_clean[0]
        diff_list.append(header)
        for each in check_tty_infected:
            if each not in check_tty_clean:
                diff_list.append(each)
        return diff_list

    def diff_check_syscall(self):
        diff_list = []
        check_syscall_clean = self.check_syscall(self.clean_mem_file)
        check_syscall_infected = self.check_syscall(self.infected_mem_file)
        check_syscall_clean = check_syscall_clean.splitlines()
        check_syscall_infected = check_syscall_infected.splitlines()
        header = check_syscall_clean[0]
        header1 = check_syscall_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in check_syscall_infected:
            if each not in check_syscall_clean:
                diff_list.append(each)
        return diff_list

    def diff_bash_history(self):
        diff_list = []
        bash_history_clean = self.bash_history(self.clean_mem_file)
        bash_history_infected = self.bash_history(self.infected_mem_file)
        bash_history_clean = bash_history_clean.splitlines()
        bash_history_infected = bash_history_infected.splitlines()
        header = bash_history_clean[0]
        header1 = bash_history_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in bash_history_infected:
            if each not in bash_history_clean:
                diff_list.append(each)
        return diff_list


    def diff_check_afinfo(self):
        diff_list = []
        check_afinfo_clean = self.check_afinfo(self.clean_mem_file)
        check_afinfo_infected = self.check_afinfo(self.infected_mem_file)
        check_afinfo_clean = check_afinfo_clean.splitlines()
        check_afinfo_infected = check_afinfo_infected.splitlines()
        header = check_afinfo_clean[0]
        header1 = check_afinfo_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in check_afinfo_infected:
            if each not in check_afinfo_clean:
                diff_list.append(each)
        return diff_list

    def diff_check_fop(self):
        diff_list = []
        check_fop_clean = self.check_fop(self.clean_mem_file)
        check_fop_infected = self.check_fop(self.infected_mem_file)
        check_fop_clean = check_fop_clean.splitlines()
        check_fop_infected = check_fop_infected.splitlines()
        header = check_fop_clean[0]
        header1 = check_fop_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in check_fop_infected:
            if each not in check_fop_clean:
                diff_list.append(each)
        return diff_list

    def diff_netfilter(self):
        diff_list = []
        netfilter_clean = self.netfilter(self.clean_mem_file)
        netfilter_infected = self.netfilter(self.infected_mem_file)
        netfilter_clean = netfilter_clean.splitlines()
        netfilter_infected = netfilter_infected.splitlines()
        header = netfilter_clean[0]
        header1 = netfilter_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in netfilter_infected:
            if each not in netfilter_clean:
                diff_list.append(each)
        return diff_list

    def diff_check_inline_kernel(self):
        diff_list = []
        check_inline_kernel_clean = self.check_inline_kernel(self.clean_mem_file)
        check_inline_kernel_infected = self.check_inline_kernel(self.infected_mem_file)
        check_inline_kernel_clean = check_inline_kernel_clean.splitlines()
        check_inline_kernel_infected = check_inline_kernel_infected.splitlines()
        header = check_inline_kernel_clean[0]
        header1 = check_inline_kernel_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in check_inline_kernel_infected:
            if each not in check_inline_kernel_clean:
                diff_list.append(each)
        return diff_list

    def diff_plthook(self):
        diff_list = []
        plthook_clean = self.plthook(self.clean_mem_file)
        plthook_infected = self.plthook(self.infected_mem_file)
        plthook_clean = plthook_clean.splitlines()
        plthook_infected = plthook_infected.splitlines()
        header = plthook_clean[0]
        header1 = plthook_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in plthook_infected:
            if each not in plthook_clean:
                diff_list.append(each)
        return diff_list

    def diff_apihooks(self):
        diff_list = []
        apihooks_clean = self.apihooks(self.clean_mem_file)
        apihooks_infected = self.apihooks(self.infected_mem_file)
        apihooks_clean = apihooks_clean.splitlines()
        apihooks_infected = apihooks_infected.splitlines()
        header = apihooks_clean[0]
        header1 = apihooks_clean[1]
        diff_list.append(header)
        diff_list.append(header1)
        for each in apihooks_infected:
            if each not in apihooks_clean:
                diff_list.append(each)
        return diff_list


if __name__ == "__main__":

    parser = optparse.OptionParser('Usage: %prog -c <path to clean image> -i <path to infected image> -p <profile> [options]')
    parser.add_option("-c", "--cleanimage", dest="clean_mem_image",help="path to clean memory image")
    parser.add_option("-i", "--infectedimage", dest="infected_mem_image",help="path to infected memory image")
    parser.add_option("-p", "--profile", dest="mem_image_profile",help="profile for the memory images")
    parser.add_option("-o", "--output", dest="output_filename", help="path to the output filename", default="final_report.txt")
    parser.add_option("-v", "--verbose", action="store_true", dest="is_verbose", help="perfoms verbose diff analysis (slow)",  default=False)

    (options, args) = parser.parse_args()

    clean_mem_image = options.clean_mem_image
    infected_mem_image = options.infected_mem_image
    mem_image_profile = options.mem_image_profile
    out_report_file = options.output_filename
    is_verbose = options.is_verbose

    if not python_path:
        print("Please update the variable 'python_path' with path to the python interpreter")
        sys.exit()

    if not vol_path:
        print("Please update the variable 'vol_path' with path to the Volatility (vol.py)")
        sys.exit()

    if not clean_mem_image:
        print("Please specify path to the clean memory image, type -h or --help for more information")
        sys.exit()
    if not infected_mem_image:
        print("Please specify path to the infected memory image, type -h or --help for more information")
        sys.exit()
    if not mem_image_profile:
        print("Please specify profile to use for the memory images, type -h or --help for more information")
        sys.exit()

    mem_image_profile = "--profile=" + mem_image_profile

    print "Starting Diff Analysis using Volatility"
    print "Please Wait: Getting Process Related Information, this may take a while"

    vol = MemDiff(python_path, vol_path, clean_mem_image, infected_mem_image, mem_image_profile)

    f = open(out_report_file, 'w')

    f.write("=======================[MEMORY DIFF ANALYSIS RESULTS]=======================\n\n")

    diff_pslist = vol.diff_pslist()
    diff_pslist = "\n".join(diff_pslist)
    print "DIFF_PSLIST"
    print "=========================================="
    print diff_pslist
    print "\n"
    f.write("DIFF_PSLIST\n")
    f.write("=======================================\n")
    f.write(diff_pslist)
    f.write("\n")
    f.write("\n")

    diff_psxview = vol.diff_psxview()
    diff_psxview = "\n".join(diff_psxview)
    print "DIFF_PSXVIEW"
    print "=========================================="
    print diff_psxview
    print "\n"
    f.write("DIFF_PSXVIEW\n")
    f.write("=======================================\n")
    f.write(diff_psxview)
    f.write("\n")
    f.write("\n")

    diff_pidhashtable = vol.diff_pidhashtable()
    diff_pidhashtable = "\n".join(diff_pidhashtable)
    print "DIFF_PIDHASHTABLE"
    print "=========================================="
    print diff_pidhashtable
    print "\n"
    f.write("DIFF_PIDHASHTABLE\n")
    f.write("=======================================\n")
    f.write(diff_pidhashtable)
    f.write("\n")
    f.write("\n")

    diff_netstat = vol.diff_netstat()
    diff_netstat = "\n".join(diff_netstat)
    print "DIFF_NETSTAT"
    print "=========================================="
    print diff_netstat
    print "\n"
    f.write("DIFF_NETSTAT\n")
    f.write("=======================================\n")
    f.write(diff_netstat)
    f.write("\n")
    f.write("\n")

    diff_ifconfig = vol.diff_ifconfig()
    diff_ifconfig = "\n".join(diff_ifconfig)
    print "DIFF_IFCONFIG"
    print "=========================================="
    print diff_ifconfig
    print "\n"
    f.write("DIFF_IFCONFIG\n")
    f.write("=======================================\n")
    f.write(diff_ifconfig)
    f.write("\n")
    f.write("\n")

    diff_raw_socks = vol.diff_list_raw()
    diff_raw_socks = "\n".join(diff_raw_socks)
    print "DIFF_RAW_SOCKETS"
    print "=========================================="
    print diff_raw_socks
    print "\n"
    f.write("DIFF_RAW_SOCKETS\n")
    f.write("=======================================\n")
    f.write(diff_raw_socks)
    f.write("\n")
    f.write("\n")

    diff_library_list = vol.diff_library_list()
    diff_library_list = "\n".join(diff_library_list)
    print "DIFF_LIBRARY_LIST"
    print "=========================================="
    print diff_library_list
    print "\n"
    f.write("DIFF_LIBRARY_LIST\n")
    f.write("=======================================\n")
    f.write(diff_library_list)
    f.write("\n")
    f.write("\n")

    diff_ldrmodules = vol.diff_ldrmodules()
    diff_ldrmodules = "\n".join(diff_ldrmodules)
    print "DIFF_LDRMODULES"
    print "=========================================="
    print diff_ldrmodules
    print "\n"
    f.write("DIFF_LDRMODULES\n")
    f.write("=======================================\n")
    f.write(diff_ldrmodules)
    f.write("\n")
    f.write("\n")

    diff_dmesg = vol.diff_dmesg()
    diff_dmesg = "\n".join(diff_dmesg)
    print "DIFF_DMESG"
    print "=========================================="
    print diff_dmesg
    print "\n"
    f.write("DIFF_DMESG\n")
    f.write("=======================================\n")
    f.write(diff_dmesg)
    f.write("\n")
    f.write("\n")

    diff_lsmod = vol.diff_lsmod()
    diff_lsmod = "\n".join(diff_lsmod)
    print "DIFF_LSMOD"
    print "=========================================="
    print diff_lsmod
    print "\n"
    f.write("DIFF_LSMOD\n")
    f.write("=======================================\n")
    f.write(diff_lsmod)
    f.write("\n")
    f.write("\n")

    diff_check_modules = vol.diff_check_modules()
    diff_check_modules = "\n".join(diff_check_modules)
    print "DIFF_CHECK_MODULES"
    print "=========================================="
    print diff_check_modules
    print "\n"
    f.write("DIFF_CHECK_MODULES\n")
    f.write("=======================================\n")
    f.write(diff_check_modules)
    f.write("\n")
    f.write("\n")

    diff_hidden_modules = vol.diff_hidden_modules()
    diff_hidden_modules = "\n".join(diff_hidden_modules)
    print "DIFF_HIDDEN_MODULES"
    print "=========================================="
    print diff_hidden_modules
    print "\n"
    f.write("DIFF_HIDDEN_MODULES\n")
    f.write("=======================================\n")
    f.write(diff_hidden_modules)
    f.write("\n")
    f.write("\n")

    diff_kernel_opened_files = vol.diff_kernel_opened_files()
    diff_kernel_opened_files = "\n".join(diff_kernel_opened_files)
    print "DIFF_KERNEL_OPENED_FILES"
    print "=========================================="
    print diff_kernel_opened_files
    print "\n"
    f.write("DIFF_KERNEL_OPENED_FILES\n")
    f.write("=======================================\n")
    f.write(diff_kernel_opened_files)
    f.write("\n")
    f.write("\n")

    diff_check_creds = vol.diff_check_creds()
    diff_check_creds = "\n".join(diff_check_creds)
    print "DIFF_CHECK_CREDS"
    print "=========================================="
    print diff_check_creds
    print "\n"
    f.write("DIFF_CHECK_CREDS\n")
    f.write("=======================================\n")
    f.write(diff_check_creds)
    f.write("\n")
    f.write("\n")

    diff_keyboard_notifiers = vol.diff_keyboard_notifiers()
    diff_keyboard_notifiers = "\n".join(diff_keyboard_notifiers)
    print "DIFF_KEYBOARD_NOTIFIERS"
    print "=========================================="
    print diff_keyboard_notifiers
    print "\n"
    f.write("DIFF_KEYBOARD_NOTIFIERS\n")
    f.write("=======================================\n")
    f.write(diff_keyboard_notifiers)
    f.write("\n")
    f.write("\n")

    diff_check_tty = vol.diff_check_tty()
    diff_check_tty = "\n".join(diff_check_tty)
    print "DIFF_CHECK_TTY"
    print "=========================================="
    print diff_check_tty
    print "\n"
    f.write("DIFF_CHECK_TTY\n")
    f.write("=======================================\n")
    f.write(diff_check_tty)
    f.write("\n")
    f.write("\n")

    diff_check_syscall = vol.diff_check_syscall()
    diff_check_syscall = "\n".join(diff_check_syscall)
    print "DIFF_CHECK_SYSCALL"
    print "=========================================="
    print diff_check_syscall
    print "\n"
    f.write("DIFF_CHECK_SYSCALL\n")
    f.write("=======================================\n")
    f.write(diff_check_syscall)
    f.write("\n")
    f.write("\n")

    diff_bash_history = vol.diff_bash_history()
    diff_bash_history = "\n".join(diff_bash_history)
    print "DIFF_BASH_HISTORY"
    print "=========================================="
    print diff_bash_history
    print "\n"
    f.write("DIFF_BASH_HISTORY\n")
    f.write("=======================================\n")
    f.write(diff_bash_history)
    f.write("\n")
    f.write("\n")


    diff_check_afinfo = vol.diff_check_afinfo()
    diff_check_afinfo = "\n".join(diff_check_afinfo)
    print "DIFF_CHECK_AFINFO"
    print "=========================================="
    print diff_check_afinfo
    print "\n"
    f.write("DIFF_CHECK_AFINFO\n")
    f.write("=======================================\n")
    f.write(diff_check_afinfo)
    f.write("\n")
    f.write("\n")

    diff_netfilter = vol.diff_netfilter()
    diff_netfilter = "\n".join(diff_netfilter)
    print "DIFF_NETFILTER"
    print "=========================================="
    print diff_netfilter
    print "\n"
    f.write("DIFF_NETFILTER\n")
    f.write("=======================================\n")
    f.write(diff_netfilter)
    f.write("\n")
    f.write("\n")

    diff_check_inline_kernel = vol.diff_check_inline_kernel()
    diff_check_inline_kernel = "\n".join(diff_check_inline_kernel)
    print "DIFF_CHECK_INLINE_KERNEL"
    print "=========================================="
    print diff_check_inline_kernel
    print "\n"
    f.write("DIFF_CHECK_INLINE_KERNEL\n")
    f.write("=======================================\n")
    f.write(diff_check_inline_kernel)
    f.write("\n")
    f.write("\n")

    diff_check_fop = vol.diff_check_fop()
    diff_check_fop = "\n".join(diff_check_fop)
    print "DIFF_CHECK_FOP"
    print "=========================================="
    print diff_check_fop
    print "\n"
    f.write("DIFF_CHECK_FOP\n")
    f.write("=======================================\n")
    f.write(diff_check_fop)
    f.write("\n")
    f.write("\n")

    if is_verbose:
        diff_plthook = vol.diff_plthook()
        diff_plthook = "\n".join(diff_plthook)
        print "DIFF_PLTHOOK"
        print "=========================================="
        print diff_plthook
        print "\n"
        f.write("DIFF_PLTHOOK\n")
        f.write("=======================================\n")
        f.write(diff_plthook)
        f.write("\n")
        f.write("\n")

        diff_apihooks = vol.diff_apihooks()
        diff_apihooks = "\n".join(diff_apihooks)
        print "DIFF_APIHOOKS"
        print "=========================================="
        print diff_apihooks
        print "\n"
        f.write("DIFF_APIHOOKS\n")
        f.write("=======================================\n")
        f.write(diff_apihooks)
        f.write("\n")
        f.write("\n")

    f.close()
    print "Final report is stored in %s" % out_report_file






