"""
@author:       Fabio Pagani (pagabuc)
@license:      GNU General Public License 2.0
@contact:      pagani@eurecom.fr
@organization: EURECOM
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_terminated_tasks(linux_pslist.linux_pslist):
    """Gathers terminated tasks by checking several fields which are not updated every time a task dies"""

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self.linux_threads = []

    def conditional_append(self, t):
        if (type(t) is not obj.NoneObject and
            t.pid > 0 and t.parent.pid > 0 and
            t not in self.linux_threads):

            self.linux_threads.append(t)

    def explore_task(self, t):
        # 1) last_wakee
        self.conditional_append(t.last_wakee.dereference())

        # 2) real_parent
        self.conditional_append(t.real_parent.dereference())

        # 3) tasks list - meaningful for threads
        t._vol_name = "task_struct"
        for t in t.tasks:
            self.conditional_append(t)

        if "signal_struct" in self.profile.types and t.signal:
            self.conditional_append(t.signal.curr_target.dereference())

    def get_linux_threads(self):
        tasks = linux_pslist.linux_pslist.calculate(self)
        return sum([t.threads() for t in tasks], [])

    def calculate(self):
        linux_common.set_plugin_members(self)
        self.linux_threads = self.get_linux_threads()

        tmp_threads = list(self.linux_threads)

        i = 0
        while i < len(self.linux_threads):
            t = self.linux_threads[i]
            self.explore_task(t)
            i += 1

        terminated = set(self.linux_threads) - set(tmp_threads)
        return sorted(terminated, key=lambda t: t.pid)
