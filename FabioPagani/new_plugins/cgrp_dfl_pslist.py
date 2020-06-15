"""
@author:       Fabio Pagani (pagabuc)
@license:      GNU General Public License 2.0
@contact:      pagani@eurecom.fr
@organization: EURECOM
"""

import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

# struct cgrp_cset_link {
#     /* the cgroup and css_set this link associates */
#     struct cgroup       *cgrp;
#     struct css_set      *cset;

#     /* list of cgrp_cset_links anchored at cgrp->cset_links */
#     struct list_head    cset_link;

#     /* list of cgrp_cset_links anchored at css_set->cgrp_links */
#     struct list_head    cgrp_link;
# };

cgrp_cset_link_vtype_64 = {
    'cgrp_cset_link' : [48,
        {
        'cgrp'       : [0,  ['pointer', ['cgroup']]],
        'cset'       : [8,  ['pointer', ['css_set']]],
        'cset_link'  : [16, ['list_head']],
        'cgrp_link'  : [32, ['list_head']],
        } ],
}

class LinuxCGRPTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["linux"]}

    def modification(self, profile):
        if profile.metadata.get('memory_model', '64bit') == "64bit":
            profile.vtypes.update(cgrp_cset_link_vtype_64)

# struct cgroup.cset_links -> struct cgrp_cset_link.cset_link

class linux_cgrp_dfl_pslist(linux_pslist.linux_pslist):

    def __init__(self, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)
        self.seen_cgroups = set()
        self.tasks = set()

    def get_obj(self, ptr, sname, member):
        offset = self.profile.get_obj_offset(sname, member)
        addr   = ptr - offset
        return obj.Object(sname, offset = addr, vm = self.addr_space)

    def walk_css_set(self, css_set):
        self.tasks.update(list(css_set.tasks.list_of_type("task_struct", "cg_list")))

    def walk_cgroup(self, cg):
        if cg.v() in self.seen_cgroups:
            return
        self.seen_cgroups.add(cg.v())

        for cgrp_cset_link in cg.cset_links.list_of_type("cgrp_cset_link", "cset_link"):
            css_set = cgrp_cset_link.cset
            self.walk_css_set(css_set)
            for cgrp_cset_link in css_set.cgrp_links.list_of_type("cgrp_cset_link", "cgrp_link"):
                self.walk_cgroup(cgrp_cset_link.cgrp)

    def calculate(self):
        linux_common.set_plugin_members(self)

        cgrp_dfl_root = obj.Object("cgroup_root", vm = self.addr_space,
                                   offset = self.addr_space.profile.get_symbol("cgrp_dfl_root"))
        root_cgroup = cgrp_dfl_root.cgrp
        self.walk_cgroup(root_cgroup)

        return sorted(self.tasks, key=lambda t: t.pid)
