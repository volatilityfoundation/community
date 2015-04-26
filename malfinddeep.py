# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2014 Dave Lassalle <dave@superponible.com>
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
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

#pylint: disable-msg=W0212

"""
@author:       Dave Lassalle (@superponible)
@license:      GNU General Public License 2.0 or later
@contact:      dave@superponible.com
@organization: N/A
"""

import os
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.taskmods as taskmods
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.overlays.windows.windows as windows
import volatility.constants as constants

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

try:
    import pydeep
    has_pydeep = True
except ImportError:
    has_pydeep = False

#--------------------------------------------------------------------------------
# Whitelist Rules
# The Sample is just a hash of random data and shouldn't match anything
# It's only meant as a reference for usage
#--------------------------------------------------------------------------------

whitelist_ssdeep = [
    ('Sample', '96:gd5l0eLAUpzGA73fBSu5yg7407l4WpE2eSHhhixk0EU0A:opLdpzL34u5dvZrp9/hwCA'),
]

#--------------------------------------------------------------------------------
# malfind
#--------------------------------------------------------------------------------

class MalfindDeep(malfind.Malfind):
    """Find hidden and injected code, whitelist with ssdeep hashes"""

    def __init__(self, config, *args, **kwargs):
        malfind.Malfind.__init__(self, config, *args, **kwargs)
        config.add_option("SSDEEP", short_option = 'S', default = True, action = 'store_false',
                        help = "Don't use SSDEEP hash whitelist")
        config.add_option('THRESHOLD', short_option = 'T', default = 25,
                          help = 'SSDEEP similarity threshold (0-100, 25 default)',
                          action = 'store', type = 'int')

    def render_text(self, outfd, data):

        if not has_distorm3:
            debug.warning("For best results please install distorm3")

        if self._config.DUMP_DIR and not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        for task in data:
            for vad, address_space in task.get_vads(vad_filter = task._injection_filter):

                if self._is_vad_empty(vad, address_space):
                    continue

                if self._config.SSDEEP and has_pydeep:
                    skip = False
                    # read the first page of the VAD then hash it
                    inject_buf = address_space.zread(vad.Start, 0x1000)
                    inject_hash = pydeep.hash_buf(inject_buf)
                    # loop through all the whitelist hashes and compare
                    for (whitelist_name, whitelist_hash) in whitelist_ssdeep:
                        alike = pydeep.compare(inject_hash, whitelist_hash)
                        # the comparison is greater than the threshold so display an informational message
                        # then skip the rest of the output in normal malfind
                        if alike > self._config.THRESHOLD:
                            outfd.write("Process: {0} Pid: {1} Address: {2:#x}\n".format(
                                task.ImageFileName, task.UniqueProcessId, vad.Start))
                            outfd.write("Injection is {0}% similar to whitelist hook {1}\n".format(alike, whitelist_name))
                            #outfd.write("  hook: {0}\n".format(inject_hash))
                            #outfd.write("  whitelist: {0}\n".format(whitelist_hash))
                            outfd.write("\n")
                            skip = True
                            continue
                    if skip:
                        continue

                content = address_space.zread(vad.Start, 64)

                outfd.write("Process: {0} Pid: {1} Address: {2:#x}\n".format(
                    task.ImageFileName, task.UniqueProcessId, vad.Start))

                outfd.write("Vad Tag: {0} Protection: {1}\n".format(
                    vad.Tag, vadinfo.PROTECT_FLAGS.get(vad.u.VadFlags.Protection.v(), "")))

                outfd.write("Flags: {0}\n".format(str(vad.u.VadFlags)))
                outfd.write("\n")

                outfd.write("{0}\n".format("\n".join(
                    ["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c))
                    for o, h, c in utils.Hexdump(content)
                    ])))

                outfd.write("\n")
                outfd.write("\n".join(
                    ["{0:#x} {1:<16} {2}".format(o, h, i)
                    for o, i, h in malfind.Disassemble(content, vad.Start)
                    ]))

                # Dump the data if --dump-dir was supplied
                if self._config.DUMP_DIR:

                    filename = os.path.join(self._config.DUMP_DIR,
                        "process.{0:#x}.{1:#x}.dmp".format(
                        task.obj_offset, vad.Start))

                    self.dump_vad(filename, vad, address_space)

                outfd.write("\n\n")
