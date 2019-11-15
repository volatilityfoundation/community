# Volatility
# Copyright (c) 2019 Elmar Nabigaev <nabigaev@gmail.com>
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
import base64
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.taskmods as taskmods


try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


# Supported commands
VIX_COMMAND_START_PROGRAM = 185
VIX_COMMAND_DELETE_GUEST_FILE = 18
VIX_COMMAND_DELETE_GUEST_FILE_EX = 194
VIX_COMMAND_DELETE_GUEST_REGISTRY_KEY = 71
VIX_COMMAND_DELETE_GUEST_DIRECTORY = 72
VIX_COMMAND_DELETE_GUEST_EMPTY_DIRECTORY = 73
VIX_COMMAND_INITIATE_FILE_TRANSFER_TO_GUEST = 189
VIX_COMMAND_INITIATE_FILE_TRANSFER_FROM_GUEST = 188
VIX_COMMAND_CREATE_DIRECTORY = 77
VIX_COMMAND_CREATE_DIRECTORY_EX = 178
VIX_COMMAND_DELETE_GUEST_DIRECTORY_EX = 195
VIX_COMMAND_CREATE_TEMPORARY_FILE_EX = 181
VIX_COMMAND_CREATE_TEMPORARY_DIRECTORY = 182
VIX_COMMAND_CREATE_TEMPORARY_FILE = 74
VIX_COMMAND_LIST_FILES = 177
VIX_COMMAND_MOVE_GUEST_FILE = 76
VIX_COMMAND_MOVE_GUEST_FILE_EX = 179
VIX_COMMAND_MOVE_GUEST_DIRECTORY = 180
# Credential types which uses login and password struct
VIX_USER_CREDENTIAL_NAME_PASSWORD = 1
VIX_USER_CREDENTIAL_NAME_PASSWORD_OBFUSCATED = 4
VIX_USER_CREDENTIAL_NAMED_INTERACTIVE_USER = 8

opcodes = {
    185: "VIX_COMMAND_START_PROGRAM",
    194: "VIX_COMMAND_DELETE_GUEST_FILE_EX",
    18: "VIX_COMMAND_DELETE_GUEST_FILE",
    71: "VIX_COMMAND_DELETE_GUEST_REGISTRY_KEY",
    72: "VIX_COMMAND_DELETE_GUEST_DIRECTORY",
    73: "VIX_COMMAND_DELETE_GUEST_EMPTY_DIRECTORY",
    189: "VIX_COMMAND_INITIATE_FILE_TRANSFER_TO_GUEST",
    188: "VIX_COMMAND_INITIATE_FILE_TRANSFER_FROM_GUEST",
    77: "VIX_COMMAND_CREATE_DIRECTORY",
    178: "VIX_COMMAND_CREATE_DIRECTORY",
    195: "VIX_COMMAND_DELETE_GUEST_DIRECTORY_EX",
    74: "VIX_COMMAND_CREATE_TEMPORARY_FILE",
    182: "VIX_COMMAND_CREATE_TEMPORARY_DIRECTORY",
    181: "VIX_COMMAND_CREATE_TEMPORARY_FILE_EX",
    177: "VIX_COMMAND_LIST_FILES",
    179: "VIX_COMMAND_MOVE_GUEST_FILE_EX",
    76: "VIX_COMMAND_MOVE_GUEST_FILE",
    180: "VIX_COMMAND_MOVE_GUEST_DIRECTORY"
}


# helper function to print raw bytes
# useful when debugging zread
def print_raw_bytes(string):
    print(":".join("{:02x}".format(ord(c)) for c in string))


def parse_vm_commands(address, address_space):
    # VixMsgHeader + VixCommandRequestHeader
    vix_message = obj.Object("VixMessage",
                             offset=address,
                             vm=address_space)
    command_offset = address + vix_message.size()
    opcode = vix_message.OpCode
    credential_type = vix_message.UserCredentialType

    if opcode == VIX_COMMAND_START_PROGRAM:
        command = obj.Object("VixMsgStartProgramRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.ProgramPathLength + command.ArgumentsLength
    elif opcode in [
        VIX_COMMAND_DELETE_GUEST_EMPTY_DIRECTORY,
        VIX_COMMAND_DELETE_GUEST_DIRECTORY,
        VIX_COMMAND_DELETE_GUEST_FILE_EX,
        VIX_COMMAND_DELETE_GUEST_FILE,
        VIX_COMMAND_DELETE_GUEST_REGISTRY_KEY
    ]:

        command = obj.Object("VixMsgSimpleFileRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode == VIX_COMMAND_INITIATE_FILE_TRANSFER_TO_GUEST:
        command = obj.Object("VixCommandInitiateFileTransferToGuestRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode == VIX_COMMAND_INITIATE_FILE_TRANSFER_FROM_GUEST:
        command = obj.Object("VixMsgListFilesRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode == VIX_COMMAND_CREATE_DIRECTORY:
        command = obj.Object("VixMsgCreateFileRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode == VIX_COMMAND_CREATE_DIRECTORY_EX:
        command = obj.Object("VixMsgCreateFileRequestEx",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode == VIX_COMMAND_DELETE_GUEST_DIRECTORY_EX:
        command = obj.Object("VixMsgDeleteDirectoryRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode in [
        VIX_COMMAND_CREATE_TEMPORARY_DIRECTORY,
        VIX_COMMAND_CREATE_TEMPORARY_FILE,
        VIX_COMMAND_CREATE_TEMPORARY_FILE_EX
    ]:
        command = obj.Object("VixMsgCreateTempFileRequestEx",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.filePrefixLength + command.fileSuffixLength + command.directoryPathLength + command.propertyListLength + 2
    elif opcode == VIX_COMMAND_LIST_FILES:
        command = obj.Object("VixMsgListFilesRequest",
                             offset=command_offset,
                             vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.guestPathNameLength
    elif opcode in [
        VIX_COMMAND_MOVE_GUEST_DIRECTORY,
        VIX_COMMAND_MOVE_GUEST_FILE,
        VIX_COMMAND_MOVE_GUEST_FILE_EX
    ]:
        if opcode == VIX_COMMAND_MOVE_GUEST_FILE:
            command = obj.Object("VixCommandRenameFileRequest",
                                 offset=command_offset,
                                 vm=address_space)
        else:
            command = obj.Object("VixCommandRenameFileRequestEx",
                                 offset=command_offset,
                                 vm=address_space)
        data_offset = command_offset + command.size()
        cmd_data_size = command.oldPathNameLength + command.newPathNameLength + 1
    else:
        debug.error("Unsupported Vmware command")

    return data_offset, command, opcode, credential_type, cmd_data_size


def parse_vm_creds(credential_type, space, offset, cmd_data_size):
    try:
        if credential_type in [VIX_USER_CREDENTIAL_NAME_PASSWORD, VIX_USER_CREDENTIAL_NAME_PASSWORD_OBFUSCATED,
                               VIX_USER_CREDENTIAL_NAMED_INTERACTIVE_USER]:
            credentials = obj.Object("VixCommandNamePassword",
                                     offset=offset + cmd_data_size,
                                     vm=space)
            credential_offset = offset + cmd_data_size + credentials.size()
            last_byte = space.zread(credential_offset, 1)
            # sometimes we land on null termination of a previous command, so we need to move our offset
            while last_byte == "\x00":
                credential_offset += 1
                last_byte = space.zread(credential_offset, 1)
            creds_str = ""

            while last_byte != "\x00":
                creds_str += last_byte
                credential_offset += 1
                last_byte = space.zread(credential_offset, 1)

            decoded_creds = base64.b64decode(creds_str)
            clear_login, clear_password = decoded_creds.split("\x00")[:-1]  # we need to skip the last element because it's a null
            return clear_login, clear_password
        else:
            # I observed credentials passed from previous command stay in memory even if current
            # command is not using credentials, so we try to find them
            # we do so by skipping null bytes after commands and then trying to find password structure
            cmd_data = space.zread(offset, cmd_data_size)
            null_byte = cmd_data[-1]
            counter = 0

            while null_byte == "\x00":
                counter += 1
                cred_data = space.zread(offset, cmd_data_size + counter)
                null_byte = cred_data[-1]

            possible_credential_offset = offset + cmd_data_size + counter - 1  # -1 is to account for null termination of a string

            credentials = obj.Object("VixCommandNamePassword",
                                     offset=possible_credential_offset,
                                     vm=space)
            login_offset = possible_credential_offset + credentials.size()
            last_byte = space.zread(login_offset, 1)
            creds_str = ""
            while last_byte != "\x00":
                creds_str += last_byte
                login_offset += 1
                last_byte = space.zread(login_offset, 1)

            decoded_creds = base64.b64decode(creds_str)
            clear_login, clear_password = decoded_creds.split("\x00")[:-1]  # we need to skip the last element because it's a null
            debug.info("Found previously stored credentials in memory")
            return "*{}".format(clear_login), "*{}".format(clear_password)
    except (TypeError, ValueError):
        debug.info("Unable to find valid credentials")
        clear_login = ""
        clear_password = ""
        return clear_login, clear_password


class LinuxVmtoolsScanner(malfind.BaseYaraScanner):
    """A scanner over all memory regions of a process."""

    def __init__(self, task=None, **kwargs):
        """Scan the process address space through the VMAs.

        Args:
          task: The task_struct object for this task.
        """
        self.task = task
        malfind.BaseYaraScanner.__init__(self,
                                         address_space=task.get_process_address_space(),
                                         **kwargs)

    def scan(self, offset=0, maxlen=None):

        for vma in self.task.get_proc_maps():

            for hit, address in malfind.BaseYaraScanner.scan(self,
                                                             vma.vm_start,
                                                             vma.vm_end - vma.vm_start):

                data_offset, command, opcode, credential_type, cmd_data_size = parse_vm_commands(address,
                                                                                                 self.address_space)

                yield data_offset, command, opcode, credential_type, cmd_data_size


class WindowsVmtoolsScanner(malfind.VadYaraScanner):
    """A scanner over all memory regions of a process."""

    def scan(self, offset=0, maxlen=None):

        if maxlen == None:
            vads = self.task.get_vads(skip_max_commit=True)
        else:
            filter = lambda x: x.Length < maxlen
            vads = self.task.get_vads(vad_filter=filter,
                                      skip_max_commit=True)

        for vad, self.address_space in vads:
            for hit, address in malfind.BaseYaraScanner.scan(self, vad.Start, vad.Length):

                data_offset, command, opcode, credential_type, cmd_data_size = parse_vm_commands(address,
                                                                                                 self.address_space)
                yield data_offset, command, opcode, credential_type, cmd_data_size


class VmtoolsModification(obj.ProfileModification):
    """A modification for Vmtools"""

    conditions = {'os': lambda x: x in ['linux', 'windows']}

    def modification(self, profile):

        x86_vtypes = {
            'VixMessage': [51, {
                'Magic': [0, ['int']],
                'MessageVersion': [4, ['short']],
                'TotalMessageLength': [6, ['int']],
                'HeaderLength': [10, ['int']],
                'BodyLength': [14, ['int']],
                'CredentialLength': [18, ['int']],
                'CommonFlags': [22, ['char']],
                'OpCode': [23, ['int']],
                'RequestFlags': [27, ['int']],
                'Timeout': [31, ['int']],
                'Cookie': [35, ['int']],
                'ClientHandleId': [43, ['int']],
                'UserCredentialType': [47, ['int']],
            }],
            'VixMsgStartProgramRequest': [21, {
                'StartMinimized': [0, ['char']],
                'ProgramPathLength': [1, ['int']],
                'ArgumentsLength': [5, ['int']],
                'WorkingDirLength': [9, ['int']],
                'numEnvVars': [13, ['int']],
                'EnvVarLength': [17, ['int']],
            }],
            'VixCommandNamePassword': [8, {
                'nameLength': [0, ['int']],
                'passwordLength': [4, ['int']],
            }],
            'VixMsgSimpleFileRequest': [8, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
            }],
            'VixCommandInitiateFileTransferToGuestRequest': [9, {
                'options': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'overwrite': [8, ['char']],
            }],
            'VixMsgListFilesRequest': [28, {
                'options': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'patternLength': [8, ['int']],
                'index': [12, ['int']],
                'maxResults': [16, ['int']],
                'offset': [20, ['int']],
            }],
            'VixMsgCreateFileRequest': [12, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'filePropertiesLength': [8, ['int']],
            }],
            'VixMsgCreateFileRequestEx': [13, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'filePropertiesLength': [8, ['int']],
                'createParentDirectories': [12, ['char']],
            }],
            'VixMsgDeleteDirectoryRequest': [13, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'filePropertiesLength': [8, ['int']],
                'recursive': [12, ['char']],
            }],
            'VixMsgCreateTempFileRequestEx': [20, {
                'options': [0, ['int']],
                'filePrefixLength': [4, ['int']],
                'fileSuffixLength': [8, ['int']],
                'directoryPathLength': [12, ['int']],
                'propertyListLength': [16, ['int']],
            }],
            'VixCommandRenameFileRequest': [16, {
                'copyFileOptions': [0, ['int']],
                'oldPathNameLength': [4, ['int']],
                'newPathNameLength': [8, ['int']],
                'filePropertiesLength': [12, ['int']],
            }],
            'VixCommandRenameFileRequestEx': [17, {
                'copyFileOptions': [0, ['int']],
                'oldPathNameLength': [4, ['int']],
                'newPathNameLength': [8, ['int']],
                'filePropertiesLength': [12, ['int']],
                'overwrite': [16, ['char']],
            }],
        }
        x64_vtypes = {
            'VixMessage': [51, {
                'Magic': [0, ['int']],
                'MessageVersion': [4, ['short']],
                'TotalMessageLength': [6, ['int']],
                'HeaderLength': [10, ['int']],
                'BodyLength': [14, ['int']],
                'CredentialLength': [18, ['int']],
                'CommonFlags': [22, ['char']],
                'OpCode': [23, ['int']],
                'RequestFlags': [27, ['int']],
                'Timeout': [31, ['int']],
                'Cookie': [35, ['int']],
                'ClientHandleId': [43, ['int']],
                'UserCredentialType': [47, ['int']],
            }],
            'VixMsgStartProgramRequest': [21, {
                'StartMinimized': [0, ['char']],
                'ProgramPathLength': [1, ['int']],
                'ArgumentsLength': [5, ['int']],
                'WorkingDirLength': [9, ['int']],
                'numEnvVars': [13, ['int']],
                'EnvVarLength': [17, ['int']],
            }],
            'VixCommandNamePassword': [8, {
                'nameLength': [0, ['int']],
                'passwordLength': [4, ['int']],
            }],
            'VixMsgSimpleFileRequest': [8, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
            }],
            'VixCommandInitiateFileTransferToGuestRequest': [9, {
                'options': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'overwrite': [8, ['char']],
            }],
            'VixMsgListFilesRequest': [28, {
                'options': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'patternLength': [8, ['int']],
                'index': [12, ['int']],
                'maxResults': [16, ['int']],
                'offset': [20, ['int']],
            }],
            'VixMsgCreateFileRequest': [12, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'filePropertiesLength': [8, ['int']],
            }],
            'VixMsgCreateFileRequestEx': [13, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'filePropertiesLength': [8, ['int']],
                'createParentDirectories': [12, ['char']],
            }],
            'VixMsgDeleteDirectoryRequest': [13, {
                'fileOptions': [0, ['int']],
                'guestPathNameLength': [4, ['int']],
                'filePropertiesLength': [8, ['int']],
                'recursive': [12, ['char']],
            }],
            'VixMsgCreateTempFileRequestEx': [20, {
                'options': [0, ['int']],
                'filePrefixLength': [4, ['int']],
                'fileSuffixLength': [8, ['int']],
                'directoryPathLength': [12, ['int']],
                'propertyListLength': [16, ['int']],
            }],
            'VixCommandRenameFileRequest': [16, {
                'copyFileOptions': [0, ['int']],
                'oldPathNameLength': [4, ['int']],
                'newPathNameLength': [8, ['int']],
                'filePropertiesLength': [12, ['int']],
            }],
            'VixCommandRenameFileRequestEx': [17, {
                'copyFileOptions': [0, ['int']],
                'oldPathNameLength': [4, ['int']],
                'newPathNameLength': [8, ['int']],
                'filePropertiesLength': [12, ['int']],
                'overwrite': [16, ['char']],
            }],
        }

        bits = profile.metadata.get("memory_model", "32bit")

        if bits == "32bit":
            vtypes = x86_vtypes
        else:
            vtypes = x64_vtypes

        profile.vtypes.update(vtypes)


class linux_vmtools_command(linux_pslist.linux_pslist):
    """ Extract commands run via Vmware tools """

    def calculate(self):

        if not has_yara:
            debug.error("Please install Yara from https://plusvic.github.io/yara/")

        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            if str(task.comm) != "vmtoolsd":
                continue

            space = task.get_process_address_space()
            if not space:
                continue

            rules = yara.compile(sources={
                'vmware': 'rule vix_magic {strings: $vix = {01 00 0d d0 05 00} condition: $vix}'
            })

            scanner = LinuxVmtoolsScanner(task=task, rules=rules)

            for offset, command, opcode, credential_type, cmd_data_size in scanner.scan():
                cmd_data = space.zread(offset, cmd_data_size)

                clear_login, clear_password = parse_vm_creds(credential_type, space, offset, cmd_data_size)

                yield task, offset, opcode, clear_login, clear_password, cmd_data

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Process", "16"),
                                  ("Pid", "8"),
                                  ("Address", "[addrpad]"),
                                  ("Command", "50"),
                                  ("Login", "30"),
                                  ("Password", "30"),
                                  ("Command Data", "")])

        for (task, address, opcode, login, password, cmd_data) in data:

            command_type = opcodes.get(int(opcode))
            self.table_row(outfd, task.comm, task.pid, address, command_type, login, password, cmd_data)


class win_vmtools_command(taskmods.DllList):
    """Extract commands run via Vmware tools"""

    def calculate(self):

        if not has_yara:
            debug.error("Please install Yara from https://plusvic.github.io/yara/")

        for task in taskmods.DllList.calculate(self):

            if str(task.ImageFileName).lower() != "vmtoolsd.exe":
                continue

            space = task.get_process_address_space()
            if not space:
                continue

            rules = yara.compile(sources={
                'vmware': 'rule vix_magic {strings: $vix = {01 00 0d d0 05 00} condition: $vix}'
            })

            scanner = WindowsVmtoolsScanner(task=task, rules=rules)

            for offset, command, opcode, credential_type, cmd_data_size in scanner.scan():
                cmd_data = space.zread(offset, cmd_data_size)

                clear_login, clear_password = parse_vm_creds(credential_type, space, offset, cmd_data_size)

                yield task, offset, opcode, clear_login, clear_password, cmd_data

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Process", "16"),
                                  ("Pid", "8"),
                                  ("Address", "[addrpad]"),
                                  ("Command", "50"),
                                  ("Login", "30"),
                                  ("Password", "30"),
                                  ("Command Data", "")])

        for (task, address, opcode, login, password, cmd_data) in data:

            command_type = opcodes.get(int(opcode))
            self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, address, command_type, login, password, cmd_data)