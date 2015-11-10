# PlugX RAT detection and analysis for Volatility 2.0
#
# Version 1.2
#
# Author: Fabien Perigaud <fabien.perigaud@cassidian.com>
#
# This plugin is based on poisonivy.py by Andreas Schuster.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
from struct import unpack_from, calcsize
from socket import inet_ntoa
from collections import defaultdict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

# Simple rule:
#  - look for GULP signature at the beginning of a VAD (v1)
#  - look for /update?id=%8.8x
#  - look for (a push 0x2a0 or a "Proxy-Auth:" string) AND (use of a 0x713a8fc1 value or signature to identify v1 algorithm or signatures to identify newer algorithms)
# When scanning, also check that the VAD is RWX
signatures = {
    'namespace1': 'rule plugx { \
                       strings: \
                       $v1a = { 47 55 4C 50 00 00 00 00 } \
                       $v1b = "/update?id=%8.8x" \
                       $v1algoa = { BB 33 33 33 33 2B } \
                       $v1algob = { BB 44 44 44 44 2B } \
                       $v2a = "Proxy-Auth:" \
                       $v2b = { 68 A0 02 00 00 } \
                       $v2k = { C1 8F 3A 71 } \
                       $v21algo = {c1 e1 07 c1 ea 03 2b ca 8d 8c 31 } \
                       $v22algo = {81 c1 ?? ?? ?? ?? 8a d9 2a dd 89 4d 08 32 5d 0a 81 ea} \
                       $v23algo = {89 45 fc 32 5d fe 81 e9 ?? ?? ?? ?? 2a 5d ff 89 4d f8} \
                    condition: $v1a at 0 or $v1b or (($v2a or $v2b) and (($v1algoa and $v1algob) or $v2k or $v21algo or $v22algo or $v23algo)) }'
}

class PlugXScan(taskmods.DllList):
    """Detect processes infected with PlugX"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows')

    @staticmethod
    def get_vad_base(task, address):
        """ Get the VAD starting address """        
        for vad in task.VadRoot.traverse():
            if vad.End > address >= vad.Start:
                return vad.Start
        return None

    @staticmethod
    def get_vad_perms(task, address):
        """ Get the VAD permissions """        
        for vad in task.VadRoot.traverse():
            if vad.End > address >= vad.Start:
                return vad.u.VadFlags.Protection.v()
        return None

    def calculate(self):
        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)
        
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        
        rules = yara.compile(sources=signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():
                if self.get_vad_perms(task, address) == 6: # RWX vad
                    vad_base_addr = self.get_vad_base(task, address)
                    yield task, vad_base_addr

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Name", "20"),
                                  ("PID", "8"),
                                  ("Data VA", "[addrpad]")])
        found = []
        for task, start in data:
            if (task, start) not in found:
                self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, start)
                found.append((task, start))


class PlugXConfig(PlugXScan):
    """Locate and parse the PlugX configuration"""

    persistence = defaultdict(lambda: "Unknown", {0: "Service + Run Key", 1: "Service", 2: "Run key", 3: "None"})
    regs = defaultdict(lambda: "Unknown", {0x80000000: "HKEY_CLASSES_ROOT",
                                           0x80000001: "HKEY_CURRENT_USER",
                                           0x80000002: "HKEY_LOCAL_MACHINE",
                                           0x80000003: "HKEY_USERS",
                                           0x80000005: "HKEY_CURRENT_CONFIG" })

    @staticmethod
    def get_vad_end(task, address):
        """ Get the VAD end address """
        for vad in task.VadRoot.traverse():
            if address == vad.Start:
                return vad.End+1
        # This should never really happen
        return None

    @staticmethod
    def get_str_utf16le(buff):
        tstrend = buff.find("\x00\x00")
        tstr = buff[:tstrend + (tstrend & 1)]
        return tstr.decode('utf_16le')

    @staticmethod
    def get_proto(proto):
        ret = []
        if proto & 0x1:
            ret.append("TCP")
        if proto & 0x2:
            ret.append("HTTP")
        if proto & 0x4:
            ret.append("UDP")
        if proto & 0x8:
            ret.append("ICMP")
        if proto & 0x10:
            ret.append("DNS")
        if proto > 0x1f:
            ret.append("OTHER_UNKNOWN")
        return ' / '.join(ret)

    @staticmethod
    def get_proto2(proto):
        protos = ["???", "???", "????", "TCP", "HTTP", "DNS", "UDP", "ICMP", "RAW", "???", "???"]
        try:
            ret = protos[proto] + "(%d)" % proto
        except:
            ret = "UNKNOWN (%d)" % proto
        return ret

    def parse_config(self, cfg_blob, cfg_sz, outfd):
        if cfg_sz in (0xbe4, 0x150c, 0x1510, 0x170c, 0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
            if cfg_sz == 0x1510:
                cfg_blob = cfg_blob[12:]
            elif cfg_sz in (0x36a4, 0x4ea4):
                cfg_blob = cfg_blob
            else:
                cfg_blob = cfg_blob[8:]

            # Flags
            if cfg_sz == 0xbe4:
                desc = "<L"
            elif cfg_sz in (0x36a4, 0x4ea4):
                desc = "<10L"
            else:
                desc = "<11L"
            flags = unpack_from(desc, cfg_blob)
            cfg_blob = cfg_blob[calcsize(desc):]
            outfd.write("\tFlags: %s\n" % " ".join(["%r" % (k != 0) for k in flags]))

            # 2 timers
            timer = unpack_from("4B", cfg_blob)
            cfg_blob = cfg_blob[4:]
            timer_str = ""
            if timer[0] != 0:
                timer_str += "%d days, " % timer[0]
            if timer[1] != 0:
                timer_str += "%d hours, " % timer[1]
            if timer[2] != 0:
                timer_str += "%d mins, " % timer[2]
            timer_str += "%d secs" % timer[3]
            outfd.write("\tTimer 1: %s\n" % timer_str)
            timer = unpack_from("4B", cfg_blob)
            cfg_blob = cfg_blob[4:]
            timer_str = ""
            if timer[0] != 0:
                timer_str += "%d days, " % timer[0]
            if timer[1] != 0:
                timer_str += "%d hours, " % timer[1]
            if timer[2] != 0:
                timer_str += "%d mins, " % timer[2]
            timer_str += "%d secs" % timer[3]
            outfd.write("\tTimer 2: %s\n" % timer_str)

            # Timetable
            timetable = cfg_blob[:0x2a0]
            cfg_blob = cfg_blob[0x2a0:]
            space = False
            for k in xrange(len(timetable)):
                if timetable[k] != "\x01":
                    space = True
            if space:
                outfd.write("\tTimeTable: Custom\n")

            # Custom DNS
            (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob)
            custom_dns = cfg_blob[:0x10]
            cfg_blob = cfg_blob[0x10:]
            if dns1 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 1: %s\n" % inet_ntoa(custom_dns[:4]))
            if dns2 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 2: %s\n" % inet_ntoa(custom_dns[4:8]))
            if dns3 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 3: %s\n" % inet_ntoa(custom_dns[8:12]))
            if dns4 not in (0, 0xffffffff):
                outfd.write("\tCustom DNS 4: %s\n" % inet_ntoa(custom_dns[12:16]))

            # CC
            num_cc = 4 if cfg_sz not in (0x36a4, 0x4ea4) else 16
            get_proto = self.get_proto if cfg_sz not in (0x36a4, 0x4ea4) else self.get_proto2
            for k in xrange(num_cc):
                (proto, cc_port, cc_address) = unpack_from('<2H64s', cfg_blob)
                cfg_blob = cfg_blob[0x44:]
                proto = get_proto(proto)
                cc_address = cc_address.split('\x00')[0]
                if cc_address != "":
                    outfd.write("\tC&C Address: %s:%d (%s)\n" % (str(cc_address), cc_port, proto))

            # Additional URLs
            num_url = 4 if cfg_sz not in (0x36a4, 0x4ea4) else 16
            for k in xrange(num_url):
                url = cfg_blob[:0x80].split('\x00')[0]
                cfg_blob = cfg_blob[0x80:]
                if len(url) > 0 and str(url) != "HTTP://":
                    outfd.write("\tURL %d: %s\n" % ((k+1), str(url)))

            # Proxies
            for k in xrange(4):
                ptype, port, proxy, user, passwd = unpack_from('<2H64s64s64s', cfg_blob)
                cfg_blob = cfg_blob[calcsize('<2H64s64s64s'):]
                if proxy[0] != '\x00':
                    outfd.write("\tProxy: %s:%d\n" % (proxy.split('\x00')[0], port))
                    if user[0] != '\x00':
                        outfd.write("\tProxy credentials: %s / %s\n" % (user, passwd))

            str_sz = 0x80 if cfg_sz == 0xbe4 else 0x200

            # Persistence
            if cfg_sz in (0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                persistence_type = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                persistence = self.persistence[persistence_type]
                outfd.write("\tPersistence Type: %s\n" % persistence)
            install_dir = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tInstall Dir: %s\n" % install_dir)
            # Service
            service_name = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tService Name: %s\n" % service_name)
            service_disp = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tService Disp: %s\n" % service_disp)
            service_desc = self.get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            outfd.write("\tService Desc: %s\n" % service_desc)
            # Run key
            if cfg_sz in (0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                reg_hive = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                reg_key = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                reg_value = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tRegistry hive: %s\n" % self.regs[reg_hive])
                outfd.write("\tRegistry key: %s\n" % reg_key)
                outfd.write("\tRegistry value: %s\n" % reg_value)

            # Net injection
            if cfg_sz in (0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                inject = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                outfd.write("\tNet injection: %r\n" % (inject == 1))
                i = 4 if cfg_sz in (0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4) else 1
                for k in xrange(i):
                    inject_in = self.get_str_utf16le(cfg_blob[:str_sz])
                    cfg_blob = cfg_blob[str_sz:]
                    if inject_in != "":
                        outfd.write("\tNet injection process: %s\n" % inject_in)

            # Elevation injection
            if cfg_sz in (0x2d58, 0x36a4, 0x4ea4):
                inject = unpack_from('<L', cfg_blob)[0]
                cfg_blob = cfg_blob[4:]
                outfd.write("\tElevation injection: %r\n" % (inject == 1))
                for k in xrange(4):
                    inject_in = self.get_str_utf16le(cfg_blob[:str_sz])
                    cfg_blob = cfg_blob[str_sz:]
                    if inject_in != "":
                        outfd.write("\tElevation injection process: %s\n" % inject_in)

            # Memo / Pass / Mutex
            if cfg_sz in (0xbe4, 0x150c, 0x1510, 0x170c, 0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                online_pass = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tOnline Pass: %s\n" % online_pass)
                memo = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tMemo: %s\n" % memo)
            if cfg_sz in (0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                mutex = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tMutex: %s\n" % mutex)

            if cfg_sz in (0x170c,):
                app = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tApplication Name: %s\n" % app)

            # Screenshots
            if cfg_sz in (0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                (screenshots, freq, zoom, color, qual, days) = unpack_from('<6L', cfg_blob)
                cfg_blob = cfg_blob[calcsize('<6L'):]
                outfd.write("\tScreenshots: %r\n" % (screenshots != 0))
                outfd.write("\tScreenshots params: %d sec / Zoom %d / %d bits / Quality %d / Keep %d days\n" % (freq,
                                                                                                                zoom,
                                                                                                                color,
                                                                                                                qual,
                                                                                                                days))
                screen_path = self.get_str_utf16le(cfg_blob[:str_sz])
                cfg_blob = cfg_blob[str_sz:]
                outfd.write("\tScreenshots path: %s\n" % screen_path)
            
            # Lateral
            if cfg_sz in (0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                udp_enabled, udp_port, tcp_enabled, tcp_port = unpack_from('<4L', cfg_blob)
                if tcp_enabled == 1:
                    outfd.write("\tLateral movement TCP port: %d\n" % tcp_port)
                if udp_enabled == 1:
                    outfd.write("\tLateral movement UDP port: %d\n" % udp_port)
                cfg_blob = cfg_blob[calcsize('<4L'):]

            if cfg_sz in (0x254c, 0x2d58, 0x36a4, 0x4ea4):
                icmp_enabled, icmp_port = unpack_from('<2L', cfg_blob)
                if icmp_enabled == 1:
                    outfd.write("\tLateral movement ICMP port (?): %d\n" % icmp_port)
                cfg_blob = cfg_blob[calcsize('<2L'):]

            if cfg_sz in (0x36a4, 0x4ea4):
                protoff_enabled, protoff_port = unpack_from('<2L', cfg_blob)
                if protoff_enabled == 1:
                    outfd.write("\tLateral movement Protocol 0xff port (?): %d\n" % protoff_port)
                cfg_blob = cfg_blob[calcsize('<2L'):]

            if cfg_sz in (0x36a4, 0x4ea4):
                (p2p_scan,) = unpack_from('<L', cfg_blob)
                if p2p_scan != 0:
                    outfd.write("\tP2P Scan LAN range: %r\n" % True)
                cfg_blob = cfg_blob[calcsize('<L'):]
                p2p_start = cfg_blob[:4*calcsize('<L')]
                cfg_blob = cfg_blob[4*calcsize('<L'):]
                p2p_stop = cfg_blob[:4*calcsize('<L')]
                cfg_blob = cfg_blob[4*calcsize('<L'):]
                for i in xrange(4):
                    if p2p_start[i*calcsize('<L'):i*calcsize('<L')+calcsize('<L')] != "\0\0\0\0":
                        outfd.write("\tP2P Scan range %d start: %s\n" % (i,socket.inet_ntoa(p2p_start[i*calcsize('<L'):i*calcsize('<L')+calcsize('<L')])))
                        outfd.write("\tP2P Scan range %d stop: %s\n" % (i,socket.inet_ntoa(p2p_stop[i*calcsize('<L'):i*calcsize('<L')+calcsize('<L')])))

            if cfg_sz in (0x36a4, 0x4ea4):
                mac_addr = cfg_blob[:6]
                if mac_addr != "\0\0\0\0\0\0":
                    outfd.write("\tMac Address black list: %s\n" % '-'.join("%02x" % k for k in mac_addr))
                cfg_blob = cfg_blob[6:]

            if cfg_sz in (0x4ea4,):
                for k in xrange(8):
                    process_name = self.get_str_utf16le(cfg_blob[:0x100])
                    cfg_blob = cfg_blob[0x100:]
                    if process_name != "":
                        outfd.write("\tProcess black list %d: %s\n" % (k, process_name))
                for k in xrange(8):
                    file_name = self.get_str_utf16le(cfg_blob[:0x100])
                    cfg_blob = cfg_blob[0x100:]
                    if process_name != "":
                        outfd.write("\tFile black list %d: %s\n" % (k, file_name))
                for k in xrange(8):
                    reg_name = self.get_str_utf16le(cfg_blob[:0x100])
                    cfg_blob = cfg_blob[0x100:]
                    if process_name != "":
                        outfd.write("\tRegistry black list %d: %s\n" % (k, reg_name))

        else:
            outfd.write("Config size 0x%04x not supported\n" % cfg_sz)

    def render_text(self, outfd, data):
        delim = '-' * 80

        found = []
        for task, start in data:
            if (task, start) not in found:
                found.append((task, start))
                outfd.write("{0}\n".format(delim))
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(start, self.get_vad_end(task, start)-start)
                offset = data.find("\x68\xa0\x02\x00\x00")  # push 0x2a0

                if offset == -1:
                    continue
                while not (data[offset] == "\x68" and data[offset+5] == "\xe8") and offset > 0:
                    offset -= 1
                if data[offset] != "\x68":
                    continue
                
                # Now we're at:
                # push 0xxxxxx <- config address
                # call 0xxxxxx
                (config_addr, ) = unpack_from("=I", data, offset + 1)

                # Find previous push imm
                offset -= 1
                while not data[offset] == "\x68":
                    offset -= 1
                if data[offset] != "\x68":
                    continue

                (config_size, ) = unpack_from("=I", data, offset + 1)

                config_addr -= start
                config_blob = data[config_addr:config_addr+config_size]
                outfd.write("Process: %s (%d)\n\n" % (task.ImageFileName, task.UniqueProcessId))
                outfd.write("PlugX Config (0x%04x bytes):\n" % config_size)
                self.parse_config(config_blob, config_size, outfd)
