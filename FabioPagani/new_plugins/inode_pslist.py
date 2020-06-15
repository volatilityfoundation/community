"""
@author:       Fabio Pagani (pagabuc)
@license:      GNU General Public License 2.0
@contact:      pagani@eurecom.fr
@organization: EURECOM
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist

class linux_inode_pslist(linux_pslist.linux_pslist):
    """Gather all the tasks with at least one mmap'ed file"""

    def __init__(self, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, *args, **kwargs)
        self.tasks = set()

    # container_of
    def get_obj(self, ptr, sname, member):
        offset = self.profile.get_obj_offset(sname, member)
        addr   = ptr - offset
        return obj.Object(sname, offset = addr, vm = self.addr_space)

    def _walk_rb(self, rb):
        if not rb.is_valid():
            return

        vm_area_struct = self.get_obj(rb, "vm_area_struct", "shared")

        yield vm_area_struct

        for vm_area_struct in self._walk_rb(rb.rb_left):
            yield vm_area_struct

        for vm_area_struct in self._walk_rb(rb.rb_right):
            yield vm_area_struct

    def _get_inode_hash_array(self):
        inode_hashtable_size = 1 << obj.Object("unsigned int", vm = self.addr_space, offset = self.addr_space.profile.get_symbol("i_hash_shift"))
        inode_hashtable_ptr = obj.Object("Pointer", vm = self.addr_space, offset = self.addr_space.profile.get_symbol("inode_hashtable"),)
        inode_hashtable = obj.Object(theType = 'Array', offset = inode_hashtable_ptr,
                                     vm = self.addr_space, targetType = 'hlist_head', count = inode_hashtable_size)
        return inode_hashtable

    def walk_hashtable(self, inode_hash):
        for hlist in inode_hash:
            ent = hlist.first
            while ent.v():
                inode = self.get_obj(ent, "inode", "i_hash")
                yield inode
                ent = ent.m("next")

    def calculate(self):
        linux_common.set_plugin_members(self)
        debug.info("It may take a while..")
        inode_hash = self._get_inode_hash_array()
        for inode in self.walk_hashtable(inode_hash):
            address_space = inode.i_data
            rb_root = address_space.i_mmap

            # Latest kernels: https://github.com/torvalds/linux/commit/cd9e61ed1eebbcd5dfad59475d41ec58d9b64b6a
            if rb_root.obj_type == "rb_root_cached":
                rb_root = rb_root.rb_root

            if rb_root.rb_node == 0:
                continue

            for vma in self._walk_rb(rb_root.rb_node):
                mm_struct = vma.vm_mm
                self.tasks.add(mm_struct.owner)

        return sorted(self.tasks, key=lambda t: t.pid)
