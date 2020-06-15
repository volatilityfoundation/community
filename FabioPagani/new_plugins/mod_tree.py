"""
@author:       Fabio Pagani (pagabuc)
@license:      GNU General Public License 2.0
@contact:      pagani@eurecom.fr
@organization: EURECOM
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

# type = struct latch_tree_node {
#     struct rb_node node[2];
# }

# type = struct mod_tree_node {
#     struct module *mod;
#     struct latch_tree_node node;
# }

latch_vtype_64 = {
    'latch_tree_node': [48 ,
        {
        'node[0]'    : [0,  ['rb_node']],
        'node[1]'    : [24,  ['rb_node']]
        } ],

    'mod_tree_node' : [24,
        {
        'mod'       : [0,  ['pointer', ['module']]],
        'node'      : [8,  ['latch_tree_node']]
        } ],
}

class LinuxLTRTypes(obj.ProfileModification):
    conditions = {"os" : lambda x : x in ["linux"]}

    def modification(self, profile):
        if profile.metadata.get('memory_model', '64bit') == "64bit":
            profile.vtypes.update(latch_vtype_64)

class linux_mod_tree(linux_common.AbstractLinuxCommand):
    """Gather loaded kernel modules by walking the modules tree"""
    def _walk_rb(self, rb, index):

        if not rb.is_valid():
            return

        # container_of
        off = self.addr_space.profile.get_obj_offset("latch_tree_node", "node[%d]" % index)
        off += self.addr_space.profile.get_obj_offset("mod_tree_node", "node")
        mod_tree_node = obj.Object("mod_tree_node", offset = rb - off, vm = self.addr_space)
        module =  mod_tree_node.mod

        yield module

        for module in self._walk_rb(rb.rb_left, index):
            yield module

        for module in self._walk_rb(rb.rb_right, index):
            yield module

    def calculate(self):
        linux_common.set_plugin_members(self)
        mod_tree_addr = self.addr_space.profile.get_symbol("mod_tree")
        latch_tree_root = obj.Object('latch_tree_root', offset = mod_tree_addr, vm = self.addr_space)
        index = 1
        rb_root = latch_tree_root.tree[index]
        for module in self._walk_rb(rb_root.rb_node, index):
            yield module

    def unified_output(self, data):
        return TreeGrid([("Address", Address),
                       ("Name", str)],
                        self.generator(data))

    def generator(self, data):
        for module in data:
            yield module


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "[addrpadd]"), ("Name", "20"), ("Size", "6")])

        for module in data:
            self.table_row(outfd, module.v(), str(module.name), module.core_size)
