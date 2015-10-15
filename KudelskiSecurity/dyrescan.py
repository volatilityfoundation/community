# Dyre (Dyreza) configuration extractor - v 1.0
# Copyright (c) 2015 Nagravision SA
# Based on plugin by Author: Brian Baskin <brian@thebaskins.com> (Java RAT detection)
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

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.conf as conf
import string

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


YARA_SIGS = {
    'dyre_conf' : 'rule dyre_conf {strings: $a = /<serverlist>/ condition: $a}'
}

config = conf.ConfObject()
config.add_option('CONFSIZE', short_option='C', default=190000,
                           help='Config data size',
                           action='store', type='int')
config.add_option('YARAOFFSET', short_option='Y', default=0,
                           help='YARA start offset',
                           action='store', type='int')

class DyreScan(taskmods.PSList):
    """ Extract Dyre Configuration from processes """

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start
        return None

    def calculate(self): ### Not used here but kept if needed for improvements
        """ Required: Runs YARA search to find hits """
        if not HAS_YARA:
            debug.error('Yara must be installed for this plugin')

        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources=YARA_SIGS)
        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():
                vad_base_addr = self.get_vad_base(task, address)
                yield task, address

    def make_printable(self, input): ### Not used here but kept if needed for improvements
        """ Optional: Remove non-printable chars from a string """
        input = input.replace('\x09', '')  # string.printable doesn't remove backspaces
        return ''.join(filter(lambda x: x in string.printable, input))


    def render_text(self, outfd, data):
        """ Required: Parse data and display """
        config = None
        full_list = list()
        delim = '-=' * 39 + '-'
        rules = yara.compile(sources=YARA_SIGS)
        outfd.write('YARA rule: {0}\n'.format(YARA_SIGS))
        outfd.write('YARA offset: {0}\n'.format(self._config.YARAOFFSET))
        outfd.write('Configuration size: {0}\n'.format(self._config.CONFSIZE))
        for task, address in data:
            outfd.write('{0}\n'.format(delim))
            outfd.write('Configuration found in Process: {0} ({1})\n\n'.format(task.ImageFileName, task.UniqueProcessId))
            proc_addr_space = task.get_process_address_space()
            conf_data = proc_addr_space.read(address + self._config.YARAOFFSET, self._config.CONFSIZE)
            try:
                config = conf_data.splitlines()
            except:
                pass
            config_tag = ("<litem>", "</litem>", "srv_name", "</serverlist>", "<server>", "<serverlist>", "</server>", "<localitems>", ".reloc", "[nowait]")  # remove line not relevant
            if config is not None:
                for i in config:
                    if any(s in i for s in config_tag):
                        pass
                    else:
                        full_list.append(i)
        url_match = (".i2p", ".com", "/*", "www.", ".aspx", ".do", ".htm", ".jsp", ".cfm", ".co.uk")
        if full_list:
            for j in sorted(set(full_list)):
                if any(t in j for t in url_match):
                    outfd.write('\t{0}\n'.format(j))
                else:
                    pass
