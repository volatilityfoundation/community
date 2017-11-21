# pylint: disable=E0401,C0111,C0103,C0412,E0602
'''
    File name: algorithms.py
    Author: Inaki Abadia
    Date created: 2/1/2017
    Date last modified: 9/11/2017
    Python Version: 2.7
'''

import ssdeep
import fuzzyhashlib as fhash
import tlsh
import volatility.debug as debug

import enumtypes as enum
import _exceptions as exc
import dcfldd

####################
# ALGORITHM CONFIG #
####################

# SUPERCLASS CONFIG
class AlghConfig(object):
    """AlghConfig"""

    def __init__(self, alghorithm, alghType):
        self.algh = alghorithm
        self.alghtype = alghType

# ALGORITHM TYPES CONFIG
class BBRConfig(AlghConfig):

    def __init__(self, algorithm):
        super(BBRConfig, self).__init__(algorithm, enum.AlgorithmTypes.BBR)

class BBHConfig(AlghConfig):

    def __init__(self, algorithm):
        super(BBHConfig, self).__init__(algorithm, enum.AlgorithmTypes.BBH)

class SIFConfig(AlghConfig):

    def __init__(self, algorithm):
        super(SIFConfig, self).__init__(algorithm, enum.AlgorithmTypes.SIF)

class LSHConfig(AlghConfig):

    def __init__(self, algorithm):
        super(LSHConfig, self).__init__(algorithm, enum.AlgorithmTypes.LSH)

class CTPHConfig(AlghConfig):

    def __init__(self, algorithm):
        super(CTPHConfig, self).__init__(algorithm, enum.AlgorithmTypes.CTPH)

# ALGORITHM CONFIG
class SDHashConfig(SIFConfig):

    def __init__(self):
        super(SDHashConfig, self).__init__(enum.Algorithm.SDHash)

class TLSHConfig(LSHConfig):

    def __init__(self):
        super(TLSHConfig, self).__init__(enum.Algorithm.TLSH)

class SSDeepConfig(CTPHConfig):

    def __init__(self):
        super(SSDeepConfig, self).__init__(enum.Algorithm.SSDeep)

class DcflddConfig(BBHConfig):

    def __init__(self):
        super(DcflddConfig, self).__init__(enum.Algorithm.dcfldd)

def get_alghconfig_instance(algh):
    if algh == enum.Algorithm.SDHash:
        return SDHashConfig()
    elif algh == enum.Algorithm.TLSH:
        return TLSHConfig()
    elif algh == enum.Algorithm.SSDeep:
        return SSDeepConfig()
    elif algh == enum.Algorithm.dcfldd:
        return DcflddConfig()
    else:
        raise exc.InvalidAlgorithm(algh)

##############
# ALGORITHMS #
##############

# Algorithm superclass
class HashAlgorithm(object):

    @staticmethod
    def hash(data, alghConfig):
        raise InvalidAlgorithm(__name__)

# Algorithm types
class BBRAlgorithm(HashAlgorithm):

    def hash(self, data, alghConfig):
        super(BBRAlgorithm, self).__init__(data, alghConfig)

class BBHAlgorithm(HashAlgorithm):

    def hash(self, data, alghConfig):
        super(BBHAlgorithm, self).__init__(data, alghConfig)

class SIFAlgorithm(HashAlgorithm):

    def hash(self, data, alghConfig):
        super(SIFAlgorithm, self).__init__(data, alghConfig)

class LSHAlgorithm(HashAlgorithm):

    def hash(self, data, alghConfig):
        super(LSHAlgorithm, self).__init__(data, alghConfig)

class CTPHAlgorithm(HashAlgorithm):

    def hash(self, data, alghConfig):
        super(CTPHAlgorithm, self).__init__(data, alghConfig)

# Algorithms
class SDHashAlgorithm(SIFAlgorithm):

    def hash(self, data, alghConfig):
        try:
            retdata = fhash.sdhash(data).hexdigest()
        except ValueError:
            retdata = '-'
            debug.warning("SDHash needs an input of at least 512 bytes. Too short: {!s}".format(len(data)))
        return retdata

    def compare(self, h1, h2):
        return fhash.sdhash(hash=h1)-fhash.sdhash(hash=h2)

class TLSHAlgorithm(LSHAlgorithm):

    def hash(self, data, alghConfig):
        retdata = tlsh.hash(data)
        if not retdata:
            debug.warning("TLSH generated empty hash")
            retdata = '-'
        return retdata

    def compare(self, h1, h2):
        return tlsh.diffxlen(h1, h2)

class SSDeepAlgorithm(CTPHAlgorithm):

    def hash(self, data, alghConfig):
        return ssdeep.hash(data)

    def compare(self, h1, h2):
        return ssdeep.compare(str(h1), str(h2))

class DcflddAlgorithm(BBHAlgorithm):

    def hash(self, data, alghConfig):
        return dcfldd.hash(data, 100, dcfldd.MD5)

    def compare(self, h1, h2):
        return dcfldd.compare(str(h1), str(h2))

def get_algh_instance(algh):
    if algh == enum.Algorithm.SDHash:
        return SDHashAlgorithm()
    elif algh == enum.Algorithm.TLSH:
        return TLSHAlgorithm()
    elif algh == enum.Algorithm.SSDeep:
        return SSDeepAlgorithm()
    elif algh == enum.Algorithm.dcfldd:
        return DcflddAlgorithm()
    else:
        raise exc.InvalidAlgorithm(algh)
