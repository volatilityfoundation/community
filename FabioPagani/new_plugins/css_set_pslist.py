"""
@author:       Fabio Pagani (pagabuc)
@license:      GNU General Public License 2.0
@contact:      pagani@eurecom.fr
@organization: EURECOM
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_css_set_pslist(linux_pslist.linux_pslist):
    """Gathers active tasks by walking the css_set_table"""

    def __init__(self, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)
        self.tasks = set()

    def get_obj(self, ptr, sname, member):
        offset = self.profile.get_obj_offset(sname, member)
        addr   = ptr - offset
        return obj.Object(sname, offset = addr, vm = self.addr_space)

    def walk_ent(self, ent):
        while ent:
            css_set = self.get_obj(ent.v(), "css_set", "hlist")
            self.tasks.update(css_set.tasks.list_of_type("task_struct", "cg_list"))
            ent = ent.m("next")

    def calculate(self):
        linux_common.set_plugin_members(self)
        css_set_table = obj.Object(theType = "Array", offset = self.addr_space.profile.get_symbol("css_set_table"),
                                   vm = self.addr_space, targetType = "hlist_head", count = 128)

        for i in css_set_table:
            self.walk_ent(i.first)

        return sorted(self.tasks, key=lambda t: t.pid)
