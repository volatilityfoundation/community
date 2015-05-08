# Volatility
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

"""
@author:       Mariano `emdel` Graziano
@license:      GNU General Public License 2.0 or later
@contact:      graziano@eurecom.fr
@organization: Eurecom
"""

import volatility.utils as utils
import volatility.scan as scan
import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import struct, collections


'''
References: 
- A guide to kernel exploitation - pages 126-132
- https://jon.oberheide.org/blog/2010/11/29/exploiting-stack-overflows-in-the-linux-kernel/
- Robust Signatures for Kernel Data Structures - http://www.cc.gatech.edu/~brendan/ccs09_siggen.pdf
- Linux kernel source code
'''


SIZE_x32 = 0x04
KERNEL_BASE_x32 = 0xc0000000
KERNEL_MAX_x32 = 0xffffffff


class kstackps(linux_common.AbstractLinuxCommand):
    '''
    Walk the kernel pages to discover 'task_struct' data structures.
    We are interested in kernel stack pages and we leverage the 
    thread_info data structure, the first field is a pointer to the 
    task_struct owning the current kernel stack (see the references)
    This is just a POC.
    TODO: 
        * x64 support
        * Android support
        * stronger signature for the task_struct [DONE]
        * Find a way to distinguish between dead and hidden
          processes - Exit_state?
        * psscan like plugin (see the previous point)
        * Create a real Scanner
    '''
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        linux_common.set_plugin_members(self)
        for offset in xrange(KERNEL_BASE_x32, KERNEL_MAX_x32, 0x2000):
            try: thread_info_addr = struct.unpack('<I', self.addr_space.read(offset, SIZE_x32))[0]
            except: continue
            if thread_info_addr < KERNEL_BASE_x32 or thread_info_addr > KERNEL_MAX_x32: continue
            cur = obj.Object("task_struct", thread_info_addr, self.addr_space)
            # TODO: improve task_struct validation -- See moyix approach 
            if cur.se.v() > KERNEL_BASE_x32 and cur.se.v() < KERNEL_MAX_x32 and \
               cur.sched_info.v() > KERNEL_BASE_x32 and cur.sched_info.v() < KERNEL_MAX_x32 and \
               cur.stack > KERNEL_BASE_x32 and cur.stack < KERNEL_MAX_x32 and \
               cur.cred.v() > KERNEL_BASE_x32 and cur.cred.v() < KERNEL_MAX_x32 and \
               cur.thread.v() > KERNEL_BASE_x32 and cur.thread.v() < KERNEL_MAX_x32 and \
               cur.seccomp.v() > KERNEL_BASE_x32 and cur.seccomp.v() < KERNEL_MAX_x32 and \
               cur.pid >= 0 and cur.pid <= 0xffffffff and \
               cur.exit_state >= 0 and cur.exit_state <= 0xffffffff and \
               cur.state >= 0 and cur.state <= 0xffffffff and \
               cur.exit_code >= 0 and cur.exit_code <= 0xffffffff and \
               cur.signal > KERNEL_BASE_x32 and cur.signal < KERNEL_MAX_x32 and \
               cur.start_time.v() > KERNEL_BASE_x32 and cur.start_time.v() < KERNEL_MAX_x32 and \
               cur.se.cfs_rq > KERNEL_BASE_x32 and cur.se.cfs_rq < KERNEL_MAX_x32 and \
               cur.se.run_node.v() > KERNEL_BASE_x32 and cur.se.run_node.v() < KERNEL_MAX_x32 and \
               cur.se.statistics.v() > KERNEL_BASE_x32 and cur.se.statistics.v() < KERNEL_MAX_x32:
               yield cur
            
    def render_text(self, outfd, data):
        processes = {}
        proc_hits = {}
        for task in data:
           if task.pid not in processes:
                processes[task.pid] = task.comm
                proc_hits[task.pid] = 0
           else:
                proc_hits[task.pid] += 1
        procs = collections.OrderedDict(sorted(processes.items()))
        for k, v in procs.items():
            print "%d - %s" % (k, v)
        # Why some procs are so many times in memory? Cache?
        #for k, v in proc_hits.items():
        #    print k, v
