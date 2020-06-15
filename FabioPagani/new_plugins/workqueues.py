"""
@author:       Fabio Pagani (pagabuc)
@license:      GNU General Public License 2.0
@contact:      pagani@eurecom.fr
@organization: EURECOM
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

# Note: another way to list worker_pools is to start from the global variable worker_pool_idr

class linux_workqueues(linux_pslist.linux_pslist):
    """Gather all the kernel workers"""

    def __init__(self, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)
        self.tasks = set()

    def get_workqueue_struct_name(self, wq):
        return "".join(str(c) for c in list(wq.name) if c != "\x00")

    def add_tasks_worker_pool(self, wp):
        for worker in wp.workers.list_of_type("worker", "node"):
            self.tasks.add(worker.task)

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = set()

        workqueues = obj.Object("list_head", offset = self.addr_space.profile.get_symbol("workqueues"),
                                vm = self.addr_space)

        for workqueue_struct in workqueues.list_of_type("workqueue_struct", "list"):
            if workqueue_struct.rescuer:
                self.tasks.add(workqueue_struct.rescuer.task)

            for pwqs in workqueue_struct.pwqs.list_of_type("pool_workqueue", "pwqs_node"):
                self.add_tasks_worker_pool(pwqs.pool) #worker_pool

        return sorted(self.tasks, key=lambda t: t.pid)
