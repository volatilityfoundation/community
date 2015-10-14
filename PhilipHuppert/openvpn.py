#!/usr/bin/env python2
# coding=utf-8

"""Volatility plugin to extract OpenVPN credentials cached in memory."""

import struct
import string
import volatility.plugins.common as common
import volatility.obj as obj
import volatility.utils as utils
import volatility.win32.tasks as tasks

__author__ = "Philip Huppert"
__copyright__ = "Copyright 2014, Philip Huppert"
__license__ = "MIT"


USERNAME_CHARSET = string.ascii_letters + string.digits + "_-.@"


def valid_bool(x):
    return 0 <= x <= 1


def terminate_string(s):
    s, _, _ = s.partition("\0")
    return s


class OpenVPN(common.AbstractWindowsCommand):
    """Extract OpenVPN client credentials (username, password) cached in memory.

    This extractor supports OpenVPN 2.X.X on Windows. It was successfully tested with OpenVPN 2.2.2, 2.3.2 and 2.3.4
    on Windows XP (x86) and Windows 7 (x86 & x64). Credentials are available in memory if the client authenticated with
    a username & password or entered a password to unlock a private key. Furthermore, OpenVPN's --auth-nocache flag
    must not be set.
    """

    def calculate(self):
        """Search memory for credentials"""

        kernel_memory = utils.load_as(self._config)

        # Find all OpenVPN processes
        processes = tasks.pslist(kernel_memory)
        processes = filter(lambda p: str(p.ImageFileName).lower() == "openvpn.exe", processes)

        # Search for credentials in each process
        for process in processes:
            process_memory = process.get_process_address_space()

            # Get some basic process information
            pid = int(process.UniqueProcessId)
            image_base = process.Peb.ImageBaseAddress
            dos_header = obj.Object("_IMAGE_DOS_HEADER", offset=image_base, vm=process_memory)
            nt_header = dos_header.get_nt_header()

            # Find the .data and .bss sections
            sections = nt_header.get_sections(True)
            sections = filter(lambda s: str(s.Name) in [".data", ".bss"], sections)
            if len(sections) == 0:
                # Sections may be unavailable
                continue

            # Search each section for credentials
            for section in sections:
                # Determine dimensions of section
                sec_start = section.VirtualAddress + image_base
                sec_end = sec_start + section.Misc.VirtualSize
                sec_type = str(section.Name)

                # Search static user_pass struct
                # Assumptions:
                # - Struct is aligned on 16-byte boundary
                #  - Bool fields are 4 bytes long in 2.2.2
                #  - Bool fields are 2 bytes long in 2.3.2 and 2.3.4
                #  - Username and password buffers are 4096 bytes long
                for creds_start in xrange(sec_start, sec_end, 16):
                    creds = process_memory.read(creds_start, 16)
                    if not creds:
                        # Memory may be unavailable
                        continue

                    struct_layout = None
                    struct_length = None

                    # Detect the 2.2.2 struct
                    defined, nocache, username = struct.unpack("II8s", creds)
                    if sec_type == ".data" \
                            and valid_bool(defined) \
                            and valid_bool(nocache) \
                            and username[0] in USERNAME_CHARSET:
                        struct_layout = "II4096s4096s"
                        struct_length = 4 + 4 + 4096 + 4096

                    # Detect the 2.3.2/2.3.4 struct
                    defined, nocache, username = struct.unpack("BB14s", creds)
                    if sec_type == ".bss" \
                            and valid_bool(defined) \
                            and valid_bool(nocache) \
                            and username[0] in USERNAME_CHARSET:
                        struct_layout = "BB4096s4096s"
                        struct_length = 1 + 1 + 4096 + 4096

                    if struct_layout is not None:
                        # Read and parse detected structure
                        creds = process_memory.zread(creds_start, struct_length)

                        _, _, username, password = struct.unpack(struct_layout, creds)

                        # Terminate strings at null byte
                        username = terminate_string(username)
                        password = terminate_string(password)
                        yield (pid, username, password)

                        # Stop searching in current section
                        break

    def render_text(self, outfd, data):
        """Display credentials."""

        self.table_header(outfd, [
            ("Pid", "8"),
            ("Username", "32"),
            ("Password", "32")])

        for (pid, username, password) in data:
            self.table_row(outfd, pid, username, password)
