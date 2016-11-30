# Copyright (C) 2016 Bartosz Inglot (@BartInglot) <inglotbartosz@gmail_com>
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
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
#

"""
@author:       Bartosz Inglot (@BartInglot)
@license:      GNU General Public License 2.0 or later
@contact:      inglotbartosz@gmail_com
"""
import re, os, struct
from collections import namedtuple
import volatility.plugins.registry.lsadump as lsadump
import volatility.debug as debug
import volatility.cache as cache
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
import volatility.plugins.filescan as filescan
import volatility.plugins.dumpfiles as dumpfiles
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Bytes
try:
    from DPAPI.Core import *
except:
    debug.error('Please install DPAPIck library: ' + \
                'https://bitbucket.org/jmichel/dpapick')
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long


# Ensuring debug messages are only displayed
# the user enables Verbose information.
VERBOSE = False

def debug_error(msg):
    debug.error(msg)

def debug_info(msg):
    if VERBOSE:
        debug.info(msg)

def debug_warning(msg):
    if VERBOSE:
        debug.warning(msg)


class MasterKeyPool(masterkey.MasterKeyPool):
    """This class is the pivot for using DPAPIck. It manages all the DPAPI
    structures and contains all the decryption intelligence.

    """

    _guid_re = re.compile(r'^[a-z0-9-]{36}$', re.IGNORECASE)

    def addMasterKey(self, mkey):
        """Add a MasterKeyFile is the pool.

        mkey is a string representing the content of the file to add.

        """
        # It's a little hacky workaround to avoid crashing
        # MK Pool if one of the keys is invalid.
        if mkey:
            try:
                mkf = masterkey.MasterKeyFile(mkey)
                if mkf.decrypted: # seeing if it causes a crash
                    pass
                if self._guid_re.match(str(mkf.guid)):
                    if mkf:
                        self.keys[mkf.guid].append(mkf)
            except:
                pass


class PvkToPem:
	#
	# The class is based on https://github.com/kyrus/crypto-un-locker/blob/master/CryptoUnLocker.py
	#
    PUBLICKEYSTRUC_bytes = '\x07\x02\x00\x00\x00\xA4\x00\x00' # default for Win7
    VALID_ALG_IDs = (0xA400, 0x2400) # 0x2400 = CALG_RSA_SIGN, 0xA400 = CALG_RSA_KEYX

    PUBLICKEYSTRUC = namedtuple('PUBLICKEYSTRUC', 'bType bVersion reserved aiKeyAlg')
    RSAPUBKEY = namedtuple('RSAPUBKEY', 'magic bitlen pubexp')
    PRIVATEKEYBLOB = namedtuple('PRIVATEKEYBLOB', 'modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent')

    PUBLICKEYSTRUC_s = struct.Struct('<bbHI')
    RSAPUBKEY_s = struct.Struct('<4sII')


    def _reverse_bytes_to_long(self, s):
        return bytes_to_long(s[::-1])


    def _crypt_import_key(self, data):
        """
        The function turns Microsoft's PRIVATEKEYBLOB data structure into an RSA object.

        For details see https://msdn.microsoft.com/en-us/library/windows/desktop/aa375601(v=vs.85).aspx#priv_BLOB
        """
        publickeystruc = self.PUBLICKEYSTRUC._make(self.PUBLICKEYSTRUC_s.unpack_from(data))
        if publickeystruc.bType == 7 and publickeystruc.bVersion == 2 and publickeystruc.aiKeyAlg in self.VALID_ALG_IDs:
            rsapubkey = self.RSAPUBKEY._make(self.RSAPUBKEY_s.unpack_from(data[8:]))
            if rsapubkey.magic == 'RSA2':
                bitlen8 = rsapubkey.bitlen/8
                bitlen16 = rsapubkey.bitlen/16
                PRIVATEKEYBLOB_s = struct.Struct('%ds%ds%ds%ds%ds%ds%ds' % (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8))
                privatekey = self.PRIVATEKEYBLOB._make(map(self._reverse_bytes_to_long, PRIVATEKEYBLOB_s.unpack_from(data[20:])))
                r = RSA.construct((privatekey.modulus, long(rsapubkey.pubexp), privatekey.privateExponent,
                    privatekey.prime1, privatekey.prime2, privatekey.coefficient))
                return r


    def _prepare_the_key(self, data):
        """
        Based on experiments with Win7 and OpenSSL's MS_PRIVATEKEYBLOB module, there
        are some actions that need to be done to convert DPAPI decrypted blob into
        a standard PRIVATEKEYBLOB.
        """
        dword_to_int = lambda d, offset: struct.unpack_from('<I', d, offset)[0]
        # step 1 - add PUBLICKEYSTRUC if it's missing
        if data[:4] == 'RSA2':
            data = self.PUBLICKEYSTRUC_bytes + data
        # step 2 - check if we're dealing with the scrambled version
        modulus_len = dword_to_int(data, 12) - 8
        bitlen = dword_to_int(data, 16)
        bitlen8 = bitlen/8
        bitlen16 = bitlen/16
        if modulus_len != bitlen8 or bitlen % 512 != 0:
            return data
        # step 3 - fix _RSAPUBKEY as it has 2 extra DWORD's
        data = data[:12] + data[16:20] + data[24:]
        # step 4 - remove the padding
        offset = 20 # jump ahead _RSAPUBKEY
        for data_len in (bitlen8, bitlen16, bitlen16, bitlen16, bitlen16, bitlen16, bitlen8):
            bytes_to_remove = 4 if data_len == bitlen16 else 8
            offset += data_len
            data = data[:offset] + data[offset+bytes_to_remove:]
        # step 5 - remove the extra footer
        data = data[:-8] # sometimes there are 2 unknown trailing DWORDs
        while data[-4:] == '\x00\x00\x00\x00': # a long zero-pad
            data = data[:-4]
        return data


    def convert(self, data):
        data = self._prepare_the_key(data)
        if data:
            key = self._crypt_import_key(data)
            if key:
                pem = key.exportKey('PEM')
                if pem:
                    debug_info('[+] Converted to PEM')
                    return pem
        debug_warning('[-] Failed converting to PEM')


class RdpKeys(common.AbstractWindowsCommand):
    """Dump RDP keys from the registry and cache manager and DPAPI decode them"""

    REG_VALUE_PREFIX = r'L$HYDRAENCKEY_'
    DPAPI_BLOB_MARKER = '\x01\x00\x00\x00\xD0\x8C\x9D\xDF'
    SSL_KEY_MARKER = 'TSSecKeySet1'

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows')


    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                        help = 'Directory to save the files')
        config.add_option('PVK', short_option = 'K', default = False,
                        help = 'Save the original key blob (PVK) before converting to PEM',
                        action = 'store_true')
        #config.add_option('CRYPTO-CHECK', short_option = 'C', default = False,
                        #help = 'Checks the registry to see if Perfect Secrecy (DH) is enabled',
                        #action = 'store_true')
        self.addr_space = utils.load_as(self._config)


    def dpapi_decrypt(self, data, secrets, masterkeys):
        data_blob = blob.DPAPIBlob(data)
        dpapi_value = secrets.get('DPAPI_SYSTEM')
        if not dpapi_value:
            debug_error('[!] Unable to find DPAPI key in LSA Secrets')
        # This code is here because for some reason Volatility's LSA Secrets plug-in
        # returns 16 extra bytes compared to the code in DPAPIck.
        if len(dpapi_value) == 64:
            dpapi_value = dpapi_value[16:]
        # --
        mkp = MasterKeyPool()
        for filename, key in masterkeys:
            mkp.addMasterKey(key)
        mkp.addSystemCredential(dpapi_value)
        mkp.try_credential_hash(None, None)

        mks = mkp.getMasterKeys(data_blob.mkguid)

        for mk in mks:
            if mk.decrypted:
                data_blob.decrypt(mk.get_key())
                if data_blob.decrypted:
                    debug_info('[+] Successful DPAPI decryption')
                    return data_blob.cleartext
        debug_warning('[-] Failed DPAPI decryption, none of the recovered Master Keys matched.')


    filescan_cache = None
    def get_fileobj_offset(self, regex, cache=filescan_cache):
        file_re = re.compile(regex, re.IGNORECASE)
        if not cache:
            cache = dict()
            data = filescan.FileScan(self._config).calculate()
            for fileobj in data:
                if fileobj.file_name_with_device():
                    cache[fileobj.file_name_with_device()] = fileobj.obj_offset
        for fname, offset in cache.items():
            if file_re.search(fname):
                yield fname, offset


    def dump_files(self, offset):
        self._config.update('PHYSOFFSET', str(hex(offset)))
        self._config.update('NAME', True)
        #self._config.update('UNSAFE', True)
        df = dumpfiles.DumpFiles(self._config).calculate()
        for summaryinfo in df:
            obj_type = summaryinfo.get('type')
            if obj_type == 'DataSectionObject':
                for mdata in summaryinfo.get('present', []):
                    if len(mdata) < 3 or not mdata[0]:
                        continue
                    rdata = None
                    try:
                        rdata = self.addr_space.base.read(mdata[0], mdata[2])
                    except:
                        pass
                    if rdata:
                        filename = os.path.basename(summaryinfo['name'])
                        debug_info('[+] Extracted from Cache Manager: %s' % filename)
                        return filename, rdata
                debug_warning('[-] Failed to extract from Cache Manager')
            else:
                continue


    def get_masterkeys(self):
        debug_info('[*] Extracting DPAPI Master Keys...')
        files = list(self.get_fileobj_offset(r'\\System32\\Microsoft\\Protect\\.+\\.+-.+'))
        if not files:
            debug_error('[!] Unable to find Master Keys in Cache Manager')
        for name, offset in files:
            debug_info('[*] Found a Master Key: ' + name)
            mk = self.dump_files(offset)
            if mk:
                yield mk


    def get_machinekeys(self):
        debug_info('[*] Extracting Machine Keys to identify the private SSL key...')
        files = list(self.get_fileobj_offset(r'\\Microsoft\\Crypto\\RSA\\MachineKeys\\.'))
        if not files:
            debug_error('[!] Unable to find Machine Keys in Cache Manager')
        for name, offset in files:
            debug_info('[*] Found a SSL key: ' + name)
            key = self.dump_files(offset)
            if key:
                yield key


    def get_rcm_secrets(self):
        """Retrieves the secrets held in the service Terminal Server. They are
        RC4 keys that were DPAPI encrypted using a system's masterkey for "S-1-5-20".

        Returns a dictionary of secrets.
        """
        regapi = registryapi.RegistryApi(self._config)
        current_cs = regapi.reg_get_currentcontrolset()
        regapi.set_current('SYSTEM')
        rcm_key = r'%s\Control\Terminal Server\RCM\Secrets' % current_cs
        item = regapi.reg_get_key(None, rcm_key)
        return regapi.reg_yield_values(None, rcm_key, given_root = item)


    def extract_private_key(self, data):
        # Find where the DPAPI blob starts
        if not data or not self.SSL_KEY_MARKER in data:
            return
        private_key_offset = data.find(self.DPAPI_BLOB_MARKER)
        if private_key_offset < 0:
            debug_warning('[-] Could not find DPAPI header')
            return
        # Determine where the blob ends
        export_flag_offset = data.find(self.DPAPI_BLOB_MARKER, private_key_offset+1)
        if export_flag_offset < 0:
            debug_warning('[-] Could not find the end of DPAPI header')
            return
        # Voila!
        return data[private_key_offset:export_flag_offset]


    def save_to_file(self, data, file_name, file_ext):
        dst_file_name = os.path.join(self._config.DUMP_DIR, file_name + file_ext)
        with open(dst_file_name, 'wb') as o_file:
            o_file.write(data)
            debug_info('[+] Written to file: ' + dst_file_name)


    def export(self, key_name, data):
        if self._config.PVK:
            self.save_to_file(data, key_name, file_ext = '.pvk')
        pem_data = PvkToPem().convert(data)
        if pem_data:
            self.save_to_file(pem_data, key_name, '.pem')


    def calculate(self):
        if not self.is_valid_profile(self.addr_space.profile):
            debug_error('This command does not support the selected profile.')

        # If verbose, enable Info and Warning debug messages.
        if self._config.VERBOSE:
            global VERBOSE
            VERBOSE = True

        version = (self.addr_space.profile.metadata.get('major', 0),
                   self.addr_space.profile.metadata.get('minor', 0))

        # Extract LSA Secrets, necessary for DPAPI decryption.
        lsa_secrets = None
        try:
            debug_info('[*] Extracting LSA Secrets...')
            lsa_secrets = dict((str(k), v) for k, v in lsadump.LSADump(self._config).calculate().items())
            debug_info('[+] Done.')
        except:
            debug_error('[!] Unable to read LSA secrets from the registry')

        if version <= (5, 1):
            #
            # Pre-Vista the key is plaintext in LSA Secrets.
            #
            for name, data in lsa_secrets.items():
                if not name.startswith(self.REG_VALUE_PREFIX):
                    continue
                debug_info('[+] Found an RC4 key: ' + name)
                yield 'RC4', name, data
        else:
            #
            # In Vista+ there are 2 types of keys: 2x RC4 keys (short & long),
            # and a SSL key; both are DPAPI protected. The process has 3 steps:
            #
            # 1) DPAPI encryption keys from cache manager
            mk = list(self.get_masterkeys())
            if not mk:
                debug_error('[!] Unable to find MachineKeys in the Cache Manager')
            # 2) RC4 keys from the registry and DPAPI decrypt them
            for name, key_data in self.get_rcm_secrets():
                name = str(name)
                if not name.startswith(self.REG_VALUE_PREFIX):
                    continue
                debug_info('[*] Found an RC4 key: ' + name)
                decrypted_key = self.dpapi_decrypt(key_data, lsa_secrets, mk)
                if decrypted_key:
                    yield 'RC4', name, decrypted_key
            # 3) SSL key from Cache Manager and DPAPI decrypt it
            for name, key_data in self.get_machinekeys():
                private_ssl_key = self.extract_private_key(key_data)
                if not private_ssl_key:
                    continue
                decrypted_key = self.dpapi_decrypt(private_ssl_key, lsa_secrets, mk)
                if decrypted_key:
                    yield 'SSL', name, decrypted_key


    def render_text(self, outfd, data):
        if self._config.DUMP_DIR == None:
            debug_error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        self.table_header(outfd,
                          [("Type", "3"),
                           ("Length", ">5"),
                           ("Name", "")])

        for key_type, key_name, key in data:
            self.export(key_name, key)
            self.table_row(outfd,
                    key_type,
                    len(key),
                    key_name)


    def generator(self, data):
        for key_type, key_name, key in data:
            pem = PvkToPem().convert(key)
            yield (0,
                   [str(key_type),
                    str(key_name),
                    Bytes(key),
                    str(pem).replace('\n', '\\n')])


    def unified_output(self, data):
        return TreeGrid(
                        [("Key Type", str),
                         ("Key Name", str),
                         ("Key (Blob)", Bytes),
                         ("PEM", str)],
                        self.generator(data))
