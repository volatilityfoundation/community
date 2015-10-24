"""
Plugin to ssh keys within ssh-agent processes.  Currently only works on 64-bit
systems, and only with RSA keys.
"""
import os
import struct

from base64 import b64encode
from textwrap import wrap

try:
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    cryptography = False
else:
    cryptography = True

from volatility import obj as obj
from volatility.plugins.linux import common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid


openssl_vtypes_64 = {
    '_BIGNUM': [
        24,
        {
            # BaseObject has an instance method 'd'
            'd_': [0, ['pointer',
                       ['array', lambda x: x.dmax, ['unsigned long long']]]],
            'top': [8, ['int']],
            'dmax': [12, ['int']],
            'neg': [16, ['int']],
            'flags': [20, ['Enumeration',
                           dict(target='int', choices={
                               1: 'BN_FLG_MALLOCED',
                               2: 'BN_FLG_STATIC_DATA',
                               4: 'BN_FLG_CONSTTIME'
                           })]],
        }],
    '_RSA': [
        96,
        {
            'pad': [0, ['int']],
            '__ignore': [4, ['int']],  # GCC-introduced packing padding
            'version': [8, ['long long']],
            'meth': [16, ['pointer', ['void']]],
            'engine': [24, ['pointer', ['void']]],
            'n': [32, ['pointer', ['_BIGNUM']]],
            'e': [40, ['pointer', ['_BIGNUM']]],
            # BaseObject has an instance method 'd'
            'd_': [48, ['pointer', ['_BIGNUM']]],
            # These are all optimizations and ssh-agent may not set these
            'p': [56, ['pointer', ['_BIGNUM']]],
            'q': [64, ['pointer', ['_BIGNUM']]],
            'dmp1': [72, ['pointer', ['_BIGNUM']]],
            'dmq1': [80, ['pointer', ['_BIGNUM']]],
            'iqmp': [88, ['pointer', ['_BIGNUM']]]
            # We don't care about the rest
        }]
    }


openssh_vtypes_64 = {
    '_SSH_Agent_RSA_Key': [
        24,
        {
            'type': [0, ['Enumeration',
                         dict(target='int', choices={
                             # we only care about RSA
                             0: 'KEY_RSA1',
                             1: 'KEY_RSA',
                             2: 'KEY_DSA',
                             3: 'KEY_ECDSA',
                             4: 'KEY_RSA_CERT',
                             5: 'KEY_DSA_CERT',
                             6: 'KEY_ECDSA_CERT',
                             7: 'KEY_RSA_CERT_V00',
                             8: 'KEY_DSA_CERT_V00',
                             9: 'KEY_UNSPEC'
                         })]],
            'flags': [4, ['Enumeration',
                          dict(target='int', choices={
                              0: 'normal',
                              1: 'KEY_FLAG_EXT'
                          })]],
            'rsa': [8, ['pointer', ['_RSA']]],
            'dsa': [16, ['pointer', ['_RSA']]]
        }]
    }


class _BIGNUM(obj.CType):
    r"""
    in openssl/bn/bn.h

    struct bignum_st
        {
        BN_ULONG *d;    /* Pointer to an array of 'BN_BITS2' bit chunks. */
        int top;    /* Index of last used d +1. */
        /* The next are internal book keeping for bn_expand. */
        int dmax;   /* Size of the d array. */
        int neg;    /* one if the number is negative */
        int flags;
        };

    /* assuming long is 64bit - this is the DEC Alpha
    * unsigned long long is only 64 bits :-(, don't define
    * BN_LLONG for the DEC Alpha */
    #define BN_ULLONG   unsigned long long
    #define BN_BYTES    8
    #define BN_BITS2    64

    /* This is where the long long data type is 64 bits, but long is 32.
     * For machines where there are 64bit registers, this is the mode to use.
     * IRIX, on R4000 and above should use this mode, along with the relevant
     * assembler code :-).  Do NOT define BN_LLONG.
     */
    #define BN_ULONG    unsigned long long
    #define BN_BYTES    8
    #define BN_BITS2    64

    // 32-bit
    #define BN_ULONG    unsigned int
    #define BN_BYTES    4
    #define BN_BITS2    32

    #define BN_FLG_MALLOCED     0x01
    #define BN_FLG_STATIC_DATA  0x02
    #define BN_FLG_CONSTTIME    0x04
        /* avoid leaking exponent information through timing,
         * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
         * BN_div() will call BN_div_no_branch,
         * BN_mod_inverse() will call BN_mod_inverse_no_branch.
         */
    """
    def is_valid(self):
        return (self.d_.is_valid() and
                self.top >= 0 and self.top <= self.dmax and
                self.dmax >= 0 and
                self.neg in (0, 1) and
                self.flags.v() in self.flags.choices.keys() and
                len(list(self.d_.dereference())) == self.dmax)

    def v(self):
        r"""
        from openssl/bn/bn_lib.c

        /* ignore negative */
        int BN_bn2bin(const BIGNUM *a, unsigned char *to)
            {
            int n,i;
            BN_ULONG l;

            bn_check_top(a);
            n=i=BN_num_bytes(a);
            while (i--)
                {
                l=a->d[i/BN_BYTES];
                *(to++)=(unsigned char)(l>>(8*(i%BN_BYTES)))&0xff;
                }
            return(n);
            }

        from https://www.openssl.org/docs/manmaster/crypto/BN_bn2bin.html:

        "BN_bn2bin() converts the absolute value of a into big-endian form and
        stores it at to. to must point to BN_num_bytes(a) bytes of memory."


        So if we have an 3-array of 8-byte unsigned long long's, for example:

        | 0:  [ 0 1 2 3 4 5 6 7 ]
        | 1:  [ 0 1 2 3 4 5 6 7 ]
        | 2:  [ 0 1 2 3 4 5 6 7 ]

        That means that BN_bn2bin returns a byte array of:
        [(2,0), (2,1), (2,2), (2,3), (2,4), (2,5), (2,6), (2,7),
         (1,0), (1,1), (1,2), (1,3), (1,4), (1,5), (1,6), (1,7),
         (0,0), (0,1), (0,2), (0,3), (0,4), (0,5), (0,6), (0,7)]

        to be interpreted as a big-endian number.  Since Python longs are
        arbitrary precision, that means we can interpret the bignum as
        (long(2) * 2**128) + (long(1) * 2**64) + long(0)
        """
        unsigned = sum([num * (2 ** (64 * i))
                        for i, num in enumerate(self.d_.dereference())])
        if self.neg > 0:
            return unsigned * -1
        return unsigned


class _RSA(obj.CType):
    r"""
    From openssl/include/openssl/rsa.h

    struct rsa_st
        {
        int pad;
        long version;
        const RSA_METHOD *meth;
        /* functional reference if 'meth' is ENGINE-provided */
        ENGINE *engine;
        BIGNUM *n;              // public modulus
        BIGNUM *e;              // public exponent
        BIGNUM *d;              // private exponent
        BIGNUM *p;              // secret prime factor
        BIGNUM *q;              // secret prime factor
        BIGNUM *dmp1;           // d mod (p-1)
        BIGNUM *dmq1;           // d mod (q-1)
        BIGNUM *iqmp;           // q^-1 mod p  (coefficient)
        // ...
        };

    in openssl/include/openssl/ossl_typ.h, which is included in rsa.h:
    typedef struct rsa_st RSA;

    Some combination of (n, e, d), or (n, e, p, q), or (n, e, dmp1 dmq1, iqmp)
    must be needed for this to be a valid key.
    """
    _bignums = ('n', 'e', 'd_', 'p', 'q', 'dmp1', 'dmq1', 'iqmp')

    def is_valid(self):
        # Check the pointers
        if not all([getattr(self, ptr).is_valid() for ptr in self._bignums]):
            return False

        nums = {k: getattr(self, k).dereference() for k in self._bignums}

        if not all([num.is_valid() for num in nums.values()]):
            return False

        for k in nums:
            nums[k] = nums[k].v()

        # based on pyca/cryptography library:
        # cryptography.hazmat.primitives.asymmetric.rsa
        # (_check_private_key_components and _check_public_key_components)
        return (
            # everything must be less than the modulus
            all([nums[i] < nums['n'] for i in
                 ('e', 'd_', 'p', 'q', 'dmp1', 'dmq1', 'iqmp')]) and

            # public exponent, dmp1, and dmq1 must be odd
            all([nums[i] & 1 == 1 for i in ('e', 'dmp1', 'dmq1')]) and

            # modulus and public exponent must both be >=3, but public exponent
            # must be less than modulus
            3 <= nums['e'] < nums['n'] and

            # p*q must equal modulus
            nums['p'] * nums['q'] == nums['n']
        )

    def v(self):
        """
        Dump private key in PKCS#1 format.  Use cryptography to do this if
        possible, since that is much more likely to be correct.

        (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization)

        Otherwise, attempt to do it ourselves.

        PKCS#1 format is a DER sequence
        (https://msdn.microsoft.com/en-us/library/windows/desktop/bb648645(v=vs.85).aspx)
        of integers
        (https://msdn.microsoft.com/en-us/library/windows/desktop/bb540806(v=vs.85).aspx)
        """
        if cryptography:
            pn = rsa.RSAPrivateNumbers(
                p=self.p.dereference().v(),
                q=self.q.dereference().v(),
                d=self.d_.dereference().v(),
                dmp1=self.dmp1.dereference().v(),
                dmq1=self.dmq1.dereference().v(),
                iqmp=self.iqmp.dereference().v(),
                public_numbers=rsa.RSAPublicNumbers(
                    e=self.e.dereference().v(),
                    n=self.n.dereference().v()))
            return pn.private_key(backend).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

        order_of_numbers = ('n', 'e', 'd_', 'p', 'q', 'dmp1', 'dmq1', 'iqmp')
        hex_values = (
            [_hexify(0)] +  # version
            [_hexify(getattr(self, ptr).dereference().v())
             for ptr in order_of_numbers])

        integers = [_der_tlv_triplet(val, '02') for val in hex_values]
        der_sequence = _der_tlv_triplet("".join(integers), '30')

        pem = "\n".join(
            ["-----BEGIN RSA PRIVATE KEY-----"] +
            wrap(b64encode(bytearray.fromhex(der_sequence)), width=64) +
            ["-----END RSA PRIVATE KEY-----", ""]
        )
        return pem


def _hexify(value):
    """
    Turn the value (some number) into a even-lengthed hex string.
    """
    hexed = format(value, '02x')
    if len(hexed) & 1 == 1:
        return '0' + hexed
    return hexed


def _der_tlv_triplet(hex_value, hex_type, positive=True):
    """
    Given a value as a hex string and a type as a hex string, returns a
    hex string representing the TLV (type, length, value) triplet.

    As per DER integer encoding, if the integer is positive byt the leading
    bit is a 1, a 00 byte is prepended to the integer to indicate that the
    sign is positive

    (https://msdn.microsoft.com/en-us/library/windows/desktop/bb540806(v=vs.85).aspx)

    If the length of the value is >= 128, an extra byte specifying the
    length-of-length is inserted before the length field.  This value is 0b1<6
    bits>, the 6 bits represent the length (in bytes) of the length.

    (https://msdn.microsoft.com/en-us/library/windows/desktop/bb648641(v=vs.85).aspx)

    Not sure about negative numbers, but for ssh keys, hopefully all the values
    are positive.
    """
    if positive and int(hex_value[0], 16) >> 3 == 1:
        hex_value = '00' + hex_value

    _length = len(hex_value) / 2  # number of bytes the value is
    length = _hexify(_length)

    if _length < 128:
        return hex_type + length + hex_value

    # the length of length field's 7th bit is 1, and the next 6 bits are the
    # length of the length
    len_length = _hexify(2**7 + len(length) / 2)
    return hex_type + len_length + length + hex_value


class _SSH_Agent_Key(obj.CType):
    r"""
    in openssh/sshkey.h  (also typedef'ed as openssh/key.h Key)

    struct sshkey {
        int type;
        int flags;
        RSA *rsa;
        DSA *dsa;
    };

    enum types {
        KEY_RSA1,
        KEY_RSA,
        KEY_DSA,
        KEY_ECDSA,
        KEY_RSA_CERT,
        KEY_DSA_CERT,
        KEY_ECDSA_CERT,
        KEY_RSA_CERT_V00,
        KEY_DSA_CERT_V00,
        KEY_UNSPEC
    };

    /* key is stored in external hardware */
    #define KEY_FLAG_EXT        0x0001
    """
    def is_valid(self):
        """
        If it's an RSA key, it should be one of the RSA key types (or
        KEY_UNSPEC).  In which case the DSA pointer should be null, and
        the RSA pointer should point to an RSA object.

        The reverse should be true for DSA, but that is not supported yet.
        """
        return (self.type.v() in (0, 1, 4, 7, 9) and
                self.dsa.v() == 0 and
                self.rsa.is_valid() and
                self.rsa.dereference().is_valid())

    def v(self):
        """
        If RSA key (which it is if it's valid), return the PKCS#1 format of
        the RSA key.
        """
        return self.rsa.dereference().v()


class SSLSSHTypes(obj.ProfileModification):
    """
    Profile modifications for SSL and SSh types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        """
        SSL and SSH overlays to profile.
        """
        profile.vtypes.update(openssl_vtypes_64)
        profile.vtypes.update(openssh_vtypes_64)
        profile.object_classes.update({
            "_BIGNUM": _BIGNUM,
            "_RSA": _RSA,
            "_SSH_Agent_RSA_Key": _SSH_Agent_Key
        })


def find_ssh_key(task):
    """
    Attempt to find RSA ssh agent keys on the heap.  Since we are looking for
    RSA keys only, try to build an initial string to search for.  There will
    be a lot of matches, but this should be slightly faster than pure
    brute-force scanning.
    """
    possible_strings = [
        struct.pack('ii', key_type, 0)
        for key_type in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)]

    addr_space = task.get_process_address_space()

    for addr in task.search_process_memory(possible_strings):
        key = obj.Object("_SSH_Agent_RSA_Key", offset=addr, vm=addr_space)
        if key.is_valid():
            yield key


class linux_ssh_keys(linux_pslist.linux_pslist):
    """
    Get SSH keys from ssh-agent process heaps - will write all found keys to
    the specified dump directory (or /tmp, if no direcory is provided).
    """
    def __init__(self, config, *args, **kwargs):
        """
        Add a configuration for checking strings, basically a regex to check
        for.
        """
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'DUMP-DIR', default="/tmp", type='string',
            help='Output found keys to file(s) in this dump directory.')

    def calculate(self):
        """
        Find the tasks that are ssh-agent processes, then search for ssh keys.
        """
        if not os.path.isdir(os.path.expanduser(self._config.DUMP_DIR)):
            raise AssertionError(self._config.DUMP_DIR + " is not a directory")

        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)

        for task in tasks:
            counter = 0
            if 'ssh-agent' in str(task.comm):
                for key in find_ssh_key(task):
                    counter += 1
                    yield task, counter, key

    def unified_output(self, data):
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("Found-Key Filename", str)],
                        self.generator(data))

    def generator(self, data):
        for task, counter, key in data:
            filename = "{0}.{1}.{2}".format(task.pid, task.comm, counter)
            filename = os.path.expanduser(os.path.join(
                self._config.DUMP_DIR, filename))
            with open(filename, 'wb') as f:
                f.write(key.v())

            yield (0, [int(task.pid),
                       str(task.comm),
                       filename])

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "15"),
                                  ("Name", "20"),
                                  ("Found-Key Filename", "25")])
        for _, output in self.generator(data):
            self.table_row(outfd, str(output[0]), output[1], output[2])
