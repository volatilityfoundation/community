#!/usr/bin/python

'''
Copyright: Wavestone 2017 (c)
Author: Jean MARSAULT (@iansus)
Version: 1.0
Thanks: @gentilkiwi, @th3m4ks
Description:
    Volatility plugin to search for NotPetya AES keys in memory
    Report bugs to Jean MARSAULT (@iansus almost everywhere)
'''

import struct

import volatility.commands as commands
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


try:
    import pefile
    has_pefile = True
except ImportError:
    has_pefile = False


def read_bytes(address, a, length=4):
    return a.read(address, length)


def deref(address, a, length=4):
    try:
        d = struct.unpack("<I", a.read(address, length))[0]
        return d
    except struct.error:
        return None


# MAIN CLASS
class NotPetyaKeys(commands.Command):
    """ Searches for NotPetya AES keys in memory"""

    def __init__(self, config, *args):
        commands.Command.__init__(self, config, *args)
        self.__keys = []


    def fetch_config(self, config_ptr):
        pass


    def calculate(self):

        # Check imports and options
        if not has_yara:
            debug.error("You must install yara to use this plugin")

        # Load the address space
        addr_space = utils.load_as(self._config)
        # Compile yara signatures
        signature = { "AESKey" : "rule AESKey { strings: $struct =  { 0E 66 00 00 01 00 00 00 10 00 00 00 ?? ?? ?? ?? } condition: $struct }" }
        rules = yara.compile(sources=signature)

        # Search for RUNDLL32 task
        # On 32-bit, only one process with #1 in it
        # On 64-bit, two processes, but only one on WOW64

        selected_task = None
        for task in tasks.pslist(addr_space):
            if task.ImageFileName.lower() != 'rundll32.exe':
                continue

            if not task.Peb:
                continue

            if not "#1" in str(task.Peb.ProcessParameters.CommandLine):
                continue

            if task.IsWow64 or (selected_task is None and not task.IsWow64):
                selected_task = task

        if selected_task is None:
            debug.error("Could not find suitable process in memory, make sure system is infected")

        ranges = []
        for vad, process_space in selected_task.get_vads():
            ranges.append((vad.Start, vad.Start+vad.Length))

        # iterate through all VADs
        for vad, process_space in selected_task.get_vads():
            if vad.Length > 8*1024*1024*1024:
                continue

            # read the VAD content
            data = process_space.zread(vad.Start, vad.Length)

            # match yara rules
            matches = rules.match(data=data)

            # profit !
            if matches:
                for offset, _, match in matches[0].strings:

                    keyaddr = struct.unpack('<I', read_bytes(vad.Start + offset + 12, process_space))[0]

                    inRange = False
                    for start, end in ranges:
                        if start <= keyaddr and keyaddr < end:
                            inRange = True
                            break

                    if not inRange:
                        continue

                    key = read_bytes(keyaddr, process_space, 16)
                    self.__keys.append((keyaddr, key.encode('hex')))


    def render_text(self, outfd, data):

        outfd.write('\n')
        self.table_header(outfd, [
            ("Address", "[addrpad]"),
            ("AES Key", ""),
            ])

        for offset, key in self.__keys:
            self.table_row(outfd, offset, key)


