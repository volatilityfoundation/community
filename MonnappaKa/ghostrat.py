'''
@author: Monnappa (monnappa22@gmail.com)
This is a volatility plugin to detect and decrypt Gh0stRat communication in memory
copy this script to the volatility plugins directory
'''

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.plugins.malware.malfind as malfind
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.taskmods as taskmods
from volatility.plugins.connections import Connections
from volatility.plugins.connscan import ConnScan
from volatility.plugins.netscan import Netscan
import struct
import zlib


try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

ghost_sig = {'ghostrat' : r'rule Gh0strat_encrypted_communication {strings: $any_variant = /[a-zA-z0-9:]{5,16}..\x00\x00..\x00\x00\x78\x9c/ condition: $any_variant}'
             }

class GhostRat(taskmods.DllList):
    """Detects and decrypts Gh0stRat communication"""

    def calculate(self):
        if not has_yara:
            debug.error("Please install Yara from code.google.com/p/yara-project")
        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources=ghost_sig)
        decrypted_data = None
        mal_proc = {}

        kdbg = tasks.get_kdbg(addr_space)
        start = kdbg.MmSystemRangeStart.dereference_as("Pointer")
        mods = dict((addr_space.address_mask(mod.DllBase), mod)
                        for mod in modules.lsmod(addr_space))
        mod_addrs = sorted(mods.keys())
        sessions = []
        for proc in tasks.pslist(addr_space):
                sid = proc.SessionId

                if sid == None or sid in sessions:
                    continue
                session_space = proc.get_process_address_space()
                if session_space == None:
                    continue
                sessions.append(sid)
                scanner = malfind.DiscontigYaraScanner(address_space = session_space,
                                               rules = rules)
                for hit, address in scanner.scan(start_offset = start):
                    module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(address))
                    content = session_space.zread(address,1024)
                    header_size = content.find("\x78\x9c")
                    magic_header_size = header_size - 8
                    magic_keyword = content[:magic_header_size]
                    comp_uncomp_size = content[magic_header_size:header_size]
                    s = struct.Struct("I I")
                    comp_size, uncomp_size = s.unpack(comp_uncomp_size)
                    enc_data = content[0:comp_size]
                    to_decrypt = content[header_size:comp_size]
                    dec_data = self.decrypt_communication(to_decrypt)
                    if not mal_proc:
                        self.get_ghost_process(magic_keyword, mal_proc, addr_space)
                        os_version = self.get_os_version(addr_space)
                    yield (mal_proc, address, magic_keyword, enc_data, dec_data, os_version)
                    

    def get_os_version(self, addr_space):
        profile = addr_space.profile
        os = profile.metadata.get('os', 'unknown')
        os_version = profile.metadata.get('major', 0)
        return os_version
        
                    
    def get_ghost_process(self, magic, mal_process, add_space):
        rule = "rule Gh0strat_process {strings: $any_variant = " + '"' + magic + '"'+ " condition: $any_variant}"
        ghost_proc_sig = {'ghostrat_process' : rule }
        rules = yara.compile(sources=ghost_proc_sig)
        for task in self.filter_tasks(tasks.pslist(add_space)):
            scanner = malfind.VadYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():
                if task.obj_name == "_EPROCESS":
                    process = str(task.ImageFileName)
                    pid = task.UniqueProcessId
                    mal_process[process] = pid
            
        
    def decrypt_communication(self, to_decrypt):
        index = 0
        data = ""
        decompressor = zlib.decompressobj()
        while True:
            block = to_decrypt[index:index+64]
            if not block:
                break
            decompressed = decompressor.decompress(block)
            if decompressed:
                data = data + decompressed
            else:
                pass
            index = index+64
        remaining = decompressor.flush()
        data = data + remaining
        return data 
        
        
    def render_text(self, outfd, data):
        mal_ids = []
        for mal_process, addr, magic_keyword, encrypted, decrypted, os_version in data:
            outfd.write("Gh0stRat Variant: {0}\n".format(magic_keyword))
            for proc in mal_process:
                outfd.write("Malicious Process: {0}(pid:{1})\n".format(proc, str(mal_process[proc])))
                mal_ids.append((proc,mal_process[proc]))
                 
            outfd.write("Gh0strat Encrypted Communicaton:\n")
            outfd.write("-" * 78 + "\n")
            outfd.write("".join(
                ["{0:#010x}  {1:<48}  {2}\n".format(addr + o, h,
                ''.join(c)) for o, h, c in
                utils.Hexdump(encrypted)]))
            outfd.write("\n")
             
            outfd.write("Decrypted Communication:\n")
            outfd.write("-" * 78 + "\n")
            outfd.write("".join(
                ["{0:#010x}  {1:<48}  {2}\n".format(o, h,
                ''.join(c)) for o, h, c in
                utils.Hexdump(decrypted)]))
            outfd.write("\n")

        for proc, pid in list(set(mal_ids)):
            if os_version == 5:
                outfd.write("connections - Network Connections of Malicious Process:\n")
                outfd.write("-" * 78 + "\n")
                net_con = Connections(self._config)
                net_connections = net_con.calculate()
                for tcp_obj in net_connections:
                    if tcp_obj.Pid == pid:
                        local = "{0}:{1}".format(tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
                        remote = "{0}:{1}".format(tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
                        outfd.write("{0}\t{1}\t{2}(pid:{3})\n".format(local, remote, proc, tcp_obj.Pid))
                outfd.write("\n")

                outfd.write("connscan - Network Connections of Malicious Process:\n")
                outfd.write("-" * 78 + "\n")
                net_scan = ConnScan(self._config)
                net_connscan = net_scan.calculate()
                for tcp_obj in net_connscan:
                    if tcp_obj.Pid == pid:
                        local = "{0}:{1}".format(tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
                        remote = "{0}:{1}".format(tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
                        outfd.write("{0}\t{1}\t{2}(pid:{3})\n".format(local, remote, proc, tcp_obj.Pid))
                outfd.write("\n")
                
            elif os_version == 6:
                outfd.write("netscan - Network Connections of Malicious Process({0} - pid:{1}):\n".format(proc,pid))
                outfd.write("-" * 78 + "\n")
                network = Netscan(self._config)
                net_data = network.calculate()
                outfd.write("{0:<10} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
                    "Offset(P)","Proto", "Local Address",
                    "Foreign Address","State", "Pid",
                    "Owner", "Created"))
                
                for net_object, proto, laddr, lport, raddr, rport, state in net_data:
                    if net_object.Owner.UniqueProcessId == pid:
                        lendpoint = "{0}:{1}".format(laddr, lport)
                        rendpoint = "{0}:{1}".format(raddr, rport)
                        print("{0:<#10x} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
                            net_object.obj_offset, proto, lendpoint,
                            rendpoint, state, net_object.Owner.UniqueProcessId,
                            net_object.Owner.ImageFileName,
                            str(net_object.CreateTime or '')
                            ))
                outfd.write("\n")

            outfd.write("DLL's Loaded by the Malicious Process:\n")
            outfd.write("-" * 78 + "\n")
            self._config.PID = str(pid)
            dl = taskmods.DllList(self._config)
            dldata = dl.calculate()   
            dl.render_text(outfd,dldata)
            

        
    
