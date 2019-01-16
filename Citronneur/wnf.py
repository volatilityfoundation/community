# Copyright (c) 2019, Sylvain Peyrefitte
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Authors: Sylvain Peyrefitte <citronneur@gmail.com>

# Date: 2019-01-15
# Version: 1.0
#
# Volatility Framework plugin to dump Structure associate with Windows Notification Facilities
#
# Usage:
# 1) Move wnf.py to volatility/plugins in the
#    Volatilty Framework path.
# 2) Run: python vol.py -f dump_from_windows_system.vmem
#    --profile=Selected_Profile wnf
#------------------------------------------------------------------------------------

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32
import volatility.obj as obj
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex, Bytes

WNF_types = {
    # Header of every WNF struct
    '_WNF_CONTEXT_HEADER':[0x4, {
        'NodeTypeCode':[0x0, ['unsigned short']],
        'NodeByteSize':[0x2, ['unsigned short']]
    }],

    '_WNF_PROCESS_CONTEXT':[0x88, {
        'Header': [0x0, ['_WNF_CONTEXT_HEADER']],
        'EProcess': [0x8, ['pointer64', ['_EPROCESS']]],
        'WnfContexts': [0x10, ['_LIST_ENTRY']],
        'Unk1ListHead': [0x40, ['_LIST_ENTRY']],
        'SubscriptionListHead': [0x58, ['_LIST_ENTRY']],
        'Unk2ListHead': [0x70, ['_LIST_ENTRY']],
        'Event': [0x80, ['pointer64', ['_KEVENT']]]
    }],

    '_WNF_SUBSCRIPTION_CONTEXT':[0x88, {
        'Header': [0x0, ['_WNF_CONTEXT_HEADER']],
        'SubscriptionContexts': [0x18, ['_LIST_ENTRY']],
        'EProcess': [0x28, ['pointer', ['_EPROCESS']]],
        'NameInstance': [0x30, ['pointer', ['_WNF_NAME_INSTANCE_CONTEXT']]],
        'WnfId': [0x38, ['unsigned long long']],
        'NameSubscriptionContexts': [0x40, ['_LIST_ENTRY']]
    }],

    '_WNF_NAME_INSTANCE_CONTEXT': [0xa8, {
        'Header': [0x0, ['_WNF_CONTEXT_HEADER']],
        'NameInstanceContexts': [0x10, ['_LIST_ENTRY']],
        'WnfId': [0x28, ['unsigned long long']],
        'ScopeInstance': [0x30, ['pointer', ['_WNF_SCOPE_INSTANCE_CONTEXT']]],
        'DataSize': [0x38, ['unsigned long long']], # Potential available data
        'WnfData': [0x58, ['pointer', ['_WNF_STATE_DATA']]],
        'NameSubscriptionContexts': [0x78, ['_LIST_ENTRY']], # List of subscription for this name
    }],

    '_WNF_SCOPE_INSTANCE_CONTEXT': [0x50, {
        'Header': [0x0, ['_WNF_CONTEXT_HEADER']],
        'Scope': [0x10, ['unsigned int']],
        'ScopeInstanceContexts': [0x20, ['_LIST_ENTRY']],
        'ScopeMapInstanceHead': [0x28, ['pointer', ['void']]],
        'RootNameInstance': [0x38, ['pointer', ['void']]] # Pointer to root name instance tree
    }],

    '_WNF_STATE_DATA': [None, {
        'Header': [0x0, ['_WNF_CONTEXT_HEADER']],
        'DataSize': [0x4, ['unsigned int']]
    }],

    '_WNF_SCOPE_MAP_CONTEXT':[0x90, {
        'Header': [0x0, ['_WNF_CONTEXT_HEADER']],
        'ScopeInstanceContextsHead': [0x8, ['pointer', ['_WNF_SCOPE_INSTANCE_CONTEXT']]],
        'ScopeInstanceContextsTail': [0x10, ['pointer', ['_WNF_SCOPE_INSTANCE_CONTEXT']]]
    }]
}
class _WNF_SCOPE_INSTANCE_CONTEXT(obj.CType):
    """
    Add some usefull function to access some importants elements
    """
    def get_root_name_context_instance(self):
        """
        This is because name instance is track over a tree
        :return: _WNF_NAME_INSTANCE_CONTEXT
        """
        return obj.Object(
            '_WNF_NAME_INSTANCE_CONTEXT',
            offset = self.RootNameInstance.dereference().obj_offset - 0x10,
            vm = self.obj_vm,
            parent = self.obj_parent,
            native_vm = self.obj_native_vm,
            name = '_WNF_NAME_INSTANCE_CONTEXT'
        )

    def get_scope_map_instance(self):
        """
        Track scope instance
        :return: _WNF_SCOPE_MAP_CONTEXT
        """
        return obj.Object(
            '_WNF_SCOPE_MAP_CONTEXT',
            offset=self.ScopeMapInstanceHead.dereference().obj_offset - 0x20,
            vm=self.obj_vm,
            parent=self.obj_parent,
            native_vm=self.obj_native_vm,
            name='_WNF_SCOPE_MAP_CONTEXT'
        )

class WnfObjectTypes(obj.ProfileModification):
    """
    Update profile with WNF types
    """
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.vtypes.update(WNF_types)
        profile.object_classes.update({
            '_WNF_SCOPE_INSTANCE_CONTEXT': _WNF_SCOPE_INSTANCE_CONTEXT
        })

class Wnf(common.AbstractWindowsCommand):
    """
    Dump WNF name ids for a particular process
    """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args)
        config.add_option('pid', short_option='p', default=None, type = "int",
                          help='PID of target process', action="store")

        config.add_option('wnfid', short_option='i', default=None, type="str",
                          help='ID of wnf name', action="store")

        config.add_option('scope', short_option='s', default=None, type="str",
                          help='WNF Scope address', action="store")

        config.add_option('map', short_option='m', default=None, type="str",
                          help='WNF Scope Map address', action="store")


    def calculate(self):
        """
        Walk through all or specific processes
        """
        addr_space = utils.load_as(self._config)
        for task in win32.tasks.pslist(addr_space):
            if self._config.pid is not None:
                if task.UniqueProcessId.v() == self._config.pid:
                    yield task
                    break
            else:
                yield task

    def unified_output(self, data):
        return TreeGrid([
            ("Subscriber", Address),
            ("pid", int),
            ("Process Name", str),
            ("WnfName", Address),
            ("WnfId", Hex),
            ("Version", int),
            ("LifeTime", int),
            ("DataScope", int),
            ("IsPermanent", int),
            ("ScopeMap", Address),
            ("Scope", Address),
            ("ScopeType", int),
            ("HasData", str),
            ("DataSize", int)
            ], self.generator(data))

    def generator(self, tasks):
        for task in tasks:
            wnf_process_context = task.WnfContext.dereference_as('_WNF_PROCESS_CONTEXT')
            for subscriber in wnf_process_context.SubscriptionListHead.list_of_type("_WNF_SUBSCRIPTION_CONTEXT", "SubscriptionContexts"):
                # case of subscriber head
                if subscriber.Header.NodeTypeCode != 0x905:
                    continue

                # sometimes reference a not in memory object (explorer.exe)
                # very strange...
                if subscriber.NameInstance.Header.NodeTypeCode != 0x903:
                    clear = subscriber.WnfId ^ 0x41C64E6DA3BC0074
                else:
                    clear = subscriber.NameInstance.WnfId ^ 0x41C64E6DA3BC0074

                if self._config.WNFID and int(self._config.wnfid, 16) != clear:
                    continue

                if self._config.Scope and int(self._config.scope, 16) != subscriber.NameInstance.ScopeInstance.v():
                    continue

                yield (0, [
                    Address(subscriber.v()),
                    task.UniqueProcessId.v(),
                    str(task.ImageFileName),
                    Address(subscriber.NameInstance),
                    Hex(clear),
                    int(clear & 0xf),
                    int(clear >> 4 & 0x3),
                    int(clear >> 6 & 0xf),
                    int(clear >> 0xa & 0x1),
                    Address(subscriber.NameInstance.ScopeInstance.get_scope_map_instance().v()),
                    Address(subscriber.NameInstance.ScopeInstance),
                    int(subscriber.NameInstance.ScopeInstance.Scope),
                    str(bool(subscriber.NameInstance.WnfData)),
                    int(subscriber.NameInstance.WnfData.DataSize)
                ])


def hexdump(src, length=16):
    """
    Dump string into hex format
    :param src: memory
    :param length: length of line
    :return: human readable stringand hex
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

class WnfData(common.AbstractWindowsCommand):
    """
    Dump WNF data Associate to a subscriber
    """

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args)

        config.add_option('subscriber', short_option='s', default=None, type="str",
                          help='Address of subsciber instance', action="store")

    def calculate(self):
        addr_space = utils.load_as(self._config)
        for task in win32.tasks.pslist(addr_space):
            wnf_process_context = task.WnfContext.dereference_as('_WNF_PROCESS_CONTEXT')
            for subscriber in wnf_process_context.SubscriptionListHead.list_of_type("_WNF_SUBSCRIPTION_CONTEXT", "SubscriptionContexts"):
                if subscriber == int(self._config.subscriber, 16) and bool(subscriber.NameInstance.WnfData):
                    return addr_space.read(subscriber.NameInstance.WnfData + 8, 4096)

    def render_text(self, outfd, data):
        print  hexdump(data)