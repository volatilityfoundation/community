"""
@author:       Thomas White
@license:      GNU General Public License 2.0
@contact:      thomas@tribalchicken.com.au
@organization:
"""

import volatility.obj as obj
import volatility.plugins.mac.pstasks as pstasks
import volatility.plugins.mac.common as common
import volatility.utils as utils


class mac_filevault2(pstasks.mac_tasks):
    """ Attempts to recover FileVault 2 Volume Master Keys """

    def calculate(self):
        common.set_plugin_members(self)
        procs = pstasks.mac_tasks.calculate(self)

        for proc in procs:
            if str(proc.p_comm) != "kernel_task":
                continue

            proc_as = proc.get_process_address_space()

            for map in proc.get_proc_maps():
                if not map.get_perms() == 'r--':
                    continue

                address = map.links.start

                Vmk1 = proc_as.read(address,16)
                Vmk2 = proc_as.read(address + 0x430,16) #Note: Vmk2 refers to our second instance of the VMK, not the tweak key.

                signature = obj.Object("unsigned int", offset = address, vm = proc_as)

                if not Vmk1 or signature == 0x0:
                    continue

                if Vmk1 == Vmk2:
                    yield address, Vmk1

    def unified_output(self, data):
        return TreeGrid([("Address", Address),
                         ("Volume Master Key", str)
                         ], self.generator(data))

    def generator(self, data):
        for (address, Vmk1) in data:
            vmk = []
            for o, h, c in utils.Hexdump(Cmp1):
                vmk.append(h)
            yield(0, [Address(address),str(''.join(vmk).replace(" ","")),])


    def render_text(self, outfd, data):
        self.table_header(outfd, [("Address", "#018x"),
                                  ("Volume Master Key", "32")])
        for (address, Vmk1) in data:
            vmk = []
            for o, h, c in utils.Hexdump(Vmk1):
                vmk.append(h)

            self.table_row(outfd,
                           address,
                           ''.join(vmk).replace(" ","")
                           )
