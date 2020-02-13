# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#
                 
"""
@author:        Pasquale Convertini
@license:       GNU General Public License 2.0
@contact:       pasqualeconvertini95@gmail.com
"""

import struct

import volatility.obj as obj
import volatility.utils as utils
import volatility.poolscan as poolscan
import volatility.debug as debug

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as pslist


######################################################
##                    UTILITY                       ##
######################################################
class nsproxy_struct(object):
    ''' Store info contained in each nsproxy 
        and metadata about the owner process '''   
    
    def __init__(self, pid, ppid, nmps, command, arguments):
        self.pid = pid
        self.ppid = ppid
        self.uts_ns = nmps[0]
        self.ipc_ns = nmps[1]
        self.mnt_ns = nmps[2]
        self.pid_ns = nmps[3]
        self.net_ns = nmps[4]
        self.cgroup_ns = nmps[5]
        self.user_ns = nmps[6]
        self.command = command
        self.arguments = arguments


######################################################
##                    UTILITY                       ##
######################################################
class ns_info(object):
    ''' Store summary info about a namespace
        plus the list of owning processes '''
    
    def __init__(self, addr, t, pid, inum=obj.NoneObject()):
        self.addr = addr
        self.t = t
        self.pids = []
        self.pids.append(pid)
        self.inum = inum

    def __str__(self):
        return "0x{0:x} {1:6s} {2:6s} {3:5s}".format(self.addr, self.t, str(len(self.pids)), str(self.get_ppid()))

    def add_pid(self, pid):
        self.pids.append(pid)

    def get_ppid(self):
        return sorted(self.pids)[0]

    def get_procs(self):
        return sorted(self.pids)
 

######################################################
##                  PLUGIN CLASS                    ##
######################################################
class lsns(pslist.linux_pslist):
    """ Scan memory for Linux namespaces """

    NUM_NS = 6 #7 namespaces from kernel v4.4
    POINTER_DIM = 8 #bytes
    namespaces = {}
    ns_structs = {}

    
    ################################################
    ##        INIT CLASS and CONFIG OPTIONS       ##
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('TABLE', short_option = 't', default = None, help = 'print in tabular format', action = 'store_true')
        self._config.add_option('INODE', short_option = 'i', default = None, help = 'print inode number instead of offset', action = 'store_true')
        self._config.add_option('PID', short_option = 'p', default = None, help = 'Operate on these Process IDs (comma-separated)', action = 'store', type="str")
        self._config.add_option('NS', short_option = 'n', default = None, help = 'Operate on these NameSpaces (comma-separated)', action = 'store', type="str")
    
    
    ###############################################
    ##        STARTING ENGINE OF THE CLASS       ##
    def calculate(self):
        linux_common.set_plugin_members(self)
        
        #check if architecture is 32: if yes change pointer dim to 4 bytes
        if self.addr_space.profile.get_symbol("init_cgroup_ns"):
            self.NUM_NS = 7
        
        # To enable if you want to give option PID to specify a pid list via cmd look at pslist.py
        for task in self.allprocs():
            yield task

    
    ################################################
    ##        PRINT dim BYTES FROM addr           ##
    def print_data(self, addr, dim):
        data = self.addr_space.read(addr, dim)
        for offset, hexchars, chars in utils.Hexdump(data, self.POINTER_DIM):
            print "{0:#010x}  {1:<48}  {2}".format(addr + offset, hexchars, ''.join(chars))

    
    ################################################
    ##     RETURN VIRTUAL OR PHYSICAL ADDR        ##
    def get_address(self, el):
        addr = None
        if hasattr(self, "wants_physical") and el.obj_vm.base:
            nsp = self.addr_space.vtop(el.obj_offset)
        if addr == None:
            addr = el.obj_offset
        return addr

    
    ################################################
    ##         FILL GLOBAL DICTIONARIES           ##
    def _get_task_values(self, task):
        
        if task.parent.is_valid():
            ppid = task.parent.pid
        else:
            ppid = "-"
        
        ## CHECK FOR NSPROXY EXISTENCE ##
        if task.nsproxy == None:
            return False
        else:
            # GET POINTER TO NSPROXY
            nsproxy_obj = obj.Object("nsproxy", vm=self.addr_space, offset=int(task.nsproxy))
           
            ## UTS_NS ##
            uts_ns = int(nsproxy_obj.uts_ns)
            uts_inum = self.get_inode("uts_namespace", uts_ns)
            if uts_ns in self.namespaces:
                self.namespaces[uts_ns].add_pid(task.pid)
            else:
                self.namespaces[uts_ns] = ns_info(uts_ns, "uts", task.pid, uts_inum)
            
            ## IPC_NS ##
            ipc_ns = int(nsproxy_obj.ipc_ns)
            ipc_inum = self.get_inode("ipc_namespace", ipc_ns)
            if ipc_ns in self.namespaces:
                self.namespaces[ipc_ns].add_pid(task.pid)
            else:
                self.namespaces[ipc_ns] = ns_info(ipc_ns, "ipc", task.pid, ipc_inum)
            
            ## MNT_NS ##
            mnt_ns = int(nsproxy_obj.mnt_ns)
            mnt_inum = self.get_inode("mnt_namespace", mnt_ns)
            if mnt_ns in self.namespaces:
                self.namespaces[mnt_ns].add_pid(task.pid)
            else:
                self.namespaces[mnt_ns] = ns_info(mnt_ns, "mnt", task.pid, mnt_inum)
            
            ## PID_NS_FOR_CHILDREN ##
            pid_ns = int(nsproxy_obj.pid_ns_for_children)
            pid_inum = self.get_inode("pid_namespace", pid_ns)
            if pid_ns in self.namespaces:
                self.namespaces[pid_ns].add_pid(task.pid)
            else:
                self.namespaces[pid_ns] = ns_info(pid_ns, "pid", task.pid, pid_inum)
            
            ## NET_NS ##
            net_ns = int(nsproxy_obj.net_ns)
            net_inum = self.get_inode("net", net_ns)
            if net_ns in self.namespaces:
                self.namespaces[net_ns].add_pid(task.pid)
            else:
                self.namespaces[net_ns] = ns_info(net_ns, "net", task.pid, net_inum)
            
            ## CGROUP_NS -> implemented only from kernel v4.4 ##
            if self.NUM_NS == 7:
                cgroup_ns = int(nsproxy_obj.cgroup_ns)
                cgroup_inum = self.get_inode("cgroup_namespace", cgroup_ns)
                if cgroup_ns in self.namespaces:
                    self.namespaces[cgroup_ns].add_pid(task.pid)
                else:
                    self.namespaces[cgroup_ns] = ns_info(cgroup_ns, "cgroup", task.pid, cgroup_inum)
            else:
                cgroup_ns = obj.NoneObject()
        
        ## CHECK FOR CRED STRUCT EXISTENCE ##
        if task.cred == None:
            user_ns = obj.NoneObject()
        else:
            # GET POINTER TO CERT
            nsproxy_obj = obj.Object("cred", vm=self.addr_space, offset=int(task.cred))
            
            ## USER_NS ##
            user_ns = int(nsproxy_obj.user_ns)
            user_inum = self.get_inode("user_namespace", user_ns)
            if user_ns in self.namespaces:
                self.namespaces[user_ns].add_pid(task.pid)
            else:
                self.namespaces[user_ns] = ns_info(user_ns, "user", task.pid, user_inum)
        
            self.ns_structs[task.pid] = nsproxy_struct(task.pid, ppid, [uts_ns, ipc_ns, mnt_ns, pid_ns, net_ns, cgroup_ns, user_ns], task.comm, task.get_commandline())
        return True


    ################################################
    ##             READ INODE VALUE               ##
    def get_inode(self, ns_name, offs):
        if self.addr_space.profile.has_type(ns_name):
            ns_struct = obj.Object(ns_name, vm=self.addr_space, offset=offs)
            if hasattr(ns_struct, 'ns'):
                ns_n = self.get_address(ns_struct.ns)
                ns_obj = obj.Object("ns_common", vm=self.addr_space, offset=ns_n)
                return int(ns_obj.inum)
        return obj.NoneObject()

    
    ################################################
    ##          PRINT CHUNK OF DATA               ##
    def print_data(self, addr, dim):
        data = self.addr_space.read(addr, dim)
        for offset, hexchars, chars in utils.Hexdump(data, self.POINTER_DIM):
            print hexchars
        print ""


    ################################################
    ##           READ POINTER VALUE               ##
    def read_pointer(self, addr, dim):
        #print addr
        data = self.addr_space.read(addr, dim)
        for offset, hexchars, chars in utils.Hexdump(data, dim):
            pointer = "0x"+"".join(hexchars.split()[::-1])
        return int(pointer, 16)

    
    ################################################
    ##    Print for each process all namespaces   ##
    ##              table format                  ##
    def table_format(self, outfd, data):

        if self._config.INODE:
            text = "10"
        else:
            text = "[addrpad]"

        self.table_header(outfd, [("PROCESS", "15"),
                                  ("PID", "5"),
                                  ("uts_ns", text),
                                  ("ipc_ns", text),
                                  ("mnt_ns", text),
                                  ("pid_ns", text),
                                  ("net_ns", text),
                                  ("cgroup_ns", text),
                                  ("user_ns", text)])
                                  
        for task in data:
            self._get_task_values(task)
        
        for key in sorted(self.ns_structs.keys()):
            c_p = self.ns_structs[key]
            if self._config.INODE:
                self.table_row(outfd, c_p.command, c_p.pid, self.namespaces[c_p.uts_ns].inum, self.namespaces[c_p.ipc_ns].inum, self.namespaces[c_p.mnt_ns].inum, self.namespaces[c_p.pid_ns].inum, self.namespaces[c_p.net_ns].inum, self.namespaces[c_p.cgroup_ns].inum, self.namespaces[c_p.user_ns].inum)
            else:
                self.table_row(outfd, c_p.command, c_p.pid, c_p.uts_ns, c_p.ipc_ns, c_p.mnt_ns, c_p.pid_ns, c_p.net_ns, c_p.cgroup_ns, c_p.user_ns)

    
    ################################################
    ##      lsns <namespace> PRINT FORMAT         ##
    def namespace_format(self, outfd, data):
        for task in data:
            self._get_task_values(task)
        
        nslist = self._config.NS
        if nslist:
            nslist = [int(s, 16) for s in self._config.NS.split(',')]
         
        ## For each namespace
        for ns in nslist: 
            ## List processes in tree format
            if ns in self.namespaces:
                outfd.write("\nNAMESPACE: {0:6s} (TYPE: {1})".format(hex(ns), self.namespaces[ns].t))
                if self.namespaces[ns].inum:
                    outfd.write(" (INODE: {0})".format(int(self.namespaces[ns].inum)))
                ## Write header
                outfd.write("\n{0:6s} {1:6s} {2:64s}\n".format("PID", "PPID", "COMMAND"))
                
                procs = [self.ns_structs[a] for a in self.namespaces[ns].get_procs()]
                pids = [x.pid for x in procs]
                
                hierarchy = {}
                for proc in sorted(procs, key=lambda x: x.pid):
                    if proc.ppid not in hierarchy and proc.ppid in pids:
                        hierarchy[proc.ppid] = []
                    elif proc.ppid not in hierarchy and proc.ppid not in pids:
                        hierarchy[proc.pid] = []
                    if proc.ppid in hierarchy:
                        hierarchy[proc.ppid].append(proc.pid)
                already_printed = []

                for key in sorted(hierarchy.keys()):
                    if (key not in already_printed):
                        already_printed = self.printTree(key, hierarchy, already_printed, outfd, ns)
   
    
    ################################################
    ##              print like a tree             ##
    def printTree(self, parent, tree, already_printed, outfd, ns, to_p = '', indent=''):
        outfd.write("{0:6s} {1:6s} {2:64s}\n".format(str(parent), str(self.ns_structs[parent].ppid), 
                                                     to_p+self.ns_structs[parent].arguments)) 
        if parent not in tree:
            already_printed.append(parent)
            return already_printed
        if tree[parent]:
            for child in tree[parent][:-1]:
                aa = indent + u'\u251C' + u'\u2500 '#|-
                already_printed = self.printTree(child, tree, already_printed, outfd, ns, aa, indent + u'\u2502  ')
            child = tree[parent][-1]
            aa = indent + u'\u2514' + u'\u2500 '#`-
            self.printTree(child, tree, already_printed, outfd, ns, aa, indent + '   '),
        already_printed.append(parent)
        return already_printed


    ################################################
    ##       lsns print for each PID FORMAT       ##
    def pid_format(self, outfd, data):
        for task in data:
            self._get_task_values(task)
            
        pidlist = self._config.PID
        if pidlist:
            pidlist = [a for a in self.ns_structs.keys() for p in self._config.PID.split(',') if int(p) == a]
        
        for pid in pidlist:
            if pid in self.ns_structs.keys():
                outfd.write("\nPID: {0:6s}\n".format(str(pid)))
                #Print header
                self.table_header(outfd, [("NS_offset", "[addrpad]"), ("NS", "10"),("TYPE", "6"), ("NSPROC", "6"), ("PID", "5"), ("COMMAND", "100")])
                
                #Print rows
                curr_pid = self.ns_structs[pid]
                ns = [curr_pid.uts_ns, curr_pid.ipc_ns, curr_pid.mnt_ns, curr_pid.pid_ns, curr_pid.net_ns, curr_pid.cgroup_ns, curr_pid.user_ns]
                for i_n in ns:
                    if i_n in self.namespaces:
                        n = self.namespaces[i_n]
                        self.table_row(outfd, n.addr, n.inum, n.t, str(len(n.get_procs())), str(n.get_ppid()), self.ns_structs[n.get_ppid()].arguments)

    
    ################################################
    ##        CLASSIC lsns PRINT FORMAT           ##
    def classic_format(self, outfd, data):
        for task in data:
            self._get_task_values(task)
        self.table_header(outfd, [("NSPACE_Offset", "[addrpad]"), ("NS", "10"), ("TYPE", "6"), ("NSPROC", "6"), ("PID", "5"), ("COMMAND", "15"), ("ARGUMENTS", "100")])

        for key in sorted(self.namespaces.keys(), reverse=True):
            curr_ns = self.namespaces[key]
            self.table_row(outfd, key, curr_ns.inum, curr_ns.t, len(curr_ns.get_procs()), curr_ns.get_ppid(), self.ns_structs[curr_ns.get_ppid()].command, self.ns_structs[curr_ns.get_ppid()].arguments)

    
    ######################################################
    ##                      OUTPUT                      ##
    ######################################################
    def render_text(self, outfd, data):
        if(self._config.TABLE):
            self.table_format(outfd, data)       
        elif(self._config.NS):
            self.namespace_format(outfd, data)
        elif(self._config.PID):
            self.pid_format(outfd, data)
        else:
            self.classic_format(outfd, data)

