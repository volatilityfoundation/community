# pylint: disable=E0401,C0111,C0103,C0412,E0602
'''
    File name: dcfldd.py
    Author: Inaki Abadia
    Date created: 2/1/2017
    Date last modified: 9/4/2017
    Python Version: 2.7
'''

from __future__ import division
import hashlib
import math

MD5, SHA1, SHA256, CTPH = range(4)

class InvalidDcflddHashFunc(Exception):
    def __init__(self, msg):
        super(InvalidDcflddHashFunc, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr("<" + self.msg + "> is not a valid dcfldd hash function.")

class InvalidDcflddComparison(Exception):
    def __init__(self, msg):
        super(InvalidDcflddComparison, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr("Can't compare different hash functions: <" + self.msg + ">.")


def hash(data, blocks, hash_f):
    dcfldd_hash = ''
    # Data length
    bs = math.ceil(len(data) / blocks)
    bs = int(bs)

    # hash function
    if hash_f == MD5:
        hash_func = hashlib.md5
        dcfldd_hash = 'md5:'
    elif hash_f == SHA1:
        hash_func = hashlib.sha1
        dcfldd_hash = 'sha1:'
    elif hash_f == SHA256:
        hash_func = hashlib.sha256
        dcfldd_hash = 'sha256:'
    else:
        raise InvalidDcflddHashFunc(hash)

    # hash
    hash_array = [hash_func(data[i:i+bs]).hexdigest() for i in range(0, len(data), bs)]
    # Build hash str
    for h in hash_array:
        dcfldd_hash += h + ':'
    return dcfldd_hash[:-1]

def compare(h1, h2):
    score = 0
    h1_array = h1.split(':')
    h2_array = h2.split(':')

    if not h1_array[0] == h2_array[0]:
        raise InvalidDcflddComparison(h1_array[0] + ' + ' + h2_array[0])

    for i in range(1, len(h1_array)):
        if h1_array[i] == h2_array[i]:
            score = score + 1
    return score
