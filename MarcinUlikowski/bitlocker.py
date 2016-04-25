# Volatility plugin: bitlocker
#
# Author:
# Marcin Ulikowski <marcin@ulikowski.pl>
#
# Based on the research by:
# Jesse Kornblum <research@jessekornblum.com>
#
# Special thanks:
# Piotr Chmylkowski <piotr.chmylkowski@gmail.com>
# Romain Coltel <romain.coltel@hsc.fr>
#
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this plugin.  If not, see <http://www.gnu.org/licenses/>.


import os
import volatility.plugins.common as common
import volatility.utils as utils 
import volatility.obj as obj
import volatility.poolscan as poolscan
import volatility.debug as debug


class bitlocker(common.AbstractWindowsCommand):
    '''Extracts BitLocker FVEK (Full Volume Encryption Key)'''

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', default = None, help = 'Directory in which to dump cipher ID + FVEK pair')

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('major', 0) == 6 and profile.metadata.get('minor', 0) in [0, 1])

    def calculate(self):
        POOLSIZE_X86_AESDIFF = 976
        POOLSIZE_X86_AESONLY = 504
        POOLSIZE_X64_AESDIFF = 1008
        POOLSIZE_X64_AESONLY = 528

        OFFSET_DB = {
          POOLSIZE_X86_AESDIFF: {
            'CID': 24,
            'FVEK1': 32,
            'FVEK2': 504
          }, 
          POOLSIZE_X86_AESONLY: {
            'CID': 24,
            'FVEK1': 32,
            'FVEK2': 336
          },
          POOLSIZE_X64_AESDIFF: {
            'CID': 44,
            'FVEK1': 48,
            'FVEK2': 528
          },
          POOLSIZE_X64_AESONLY: {
            'CID': 44,
            'FVEK1': 48,
            'FVEK2': 480
          },
        }

        addr_space = utils.load_as(self._config)

        scanner = poolscan.SinglePoolScanner()
        scanner.checks = [
          ('PoolTagCheck', dict(tag = 'FVEc')),
          ('CheckPoolSize', dict(condition = lambda x: x in list(OFFSET_DB.keys()))),
        ]

        for addr in scanner.scan(addr_space):
            pool = obj.Object('_POOL_HEADER', offset = addr, vm = addr_space) 

            pool_alignment = obj.VolMagic(pool.obj_vm).PoolAlignment.v()
            pool_size = int(pool.BlockSize * pool_alignment)

            cid = addr_space.zread(addr + OFFSET_DB[pool_size]['CID'], 2)
            fvek1 = addr_space.zread(addr + OFFSET_DB[pool_size]['FVEK1'], 32)
            fvek2 = addr_space.zread(addr + OFFSET_DB[pool_size]['FVEK2'], 32)

            if ord(cid[1]) == 0x80 and ord(cid[0]) <= 0x03:
                fvek = fvek1 + fvek2
                yield pool, cid, fvek

    def cipher(self, id):
        return {
          0x00: 'AES-128 + Elephant diffuser',
          0x01: 'AES-256 + Elephant diffuser',
          0x02: 'AES-128',
          0x03: 'AES-256'
        }.get(id, 'UNKNOWN')

    def render_text(self, outfd, data):
        for pool, cid, fvek in data:
            debug.debug('FVEc pool found @ {0:#010x}\n'.format(pool.obj_offset))

            outfd.write('\nCipher: {0} (0x{1:02x}{2:02x})\n'.format(self.cipher(ord(cid[0])), ord(cid[1]), ord(cid[0])))
            outfd.write('FVEK: {}\n'.format(''.join('{:02x}'.format(ord(i)) for i in fvek)))
            
            if self._config.DUMP_DIR:
                full_path = os.path.join(self._config.DUMP_DIR, '{0:#010x}.fvek'.format(pool.obj_offset))

                with open(full_path, "wb") as fvek_file:
                    fvek_file.write(cid + fvek)
                
                outfd.write('FVEK dumped to: {}\n'.format(full_path))
                
            outfd.write('\n')
