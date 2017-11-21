# pylint: disable=E0401,C0111,C0103,C0412,E0602
'''
    File name: enumtypes.py
    Author: Inaki Abadia
    Date created: 2/1/2017
    Date last modified: 9/11/2017
    Python Version: 2.7
'''

import _exceptions as exc

class Algorithm(object):
    SDHash, TLSH, SSDeep, dcfldd = range(4)
    def name(self, algh):
        if algh == self.SDHash:
            return 'SDHash'
        elif algh == self.TLSH:
            return 'TLSH'
        elif algh == self.SSDeep:
            return 'SSDeep'
        elif algh == self.dcfldd:
            return 'dcfldd'
        else:
            raise exc.InvalidAlgorithm(algh)

    def resolve(self, algh):
        if algh.lower() == "sdhash":
            return self.SDHash
        elif algh.lower() == "tlsh":
            return self.TLSH
        elif algh.lower() == "ssdeep":
            return self.SSDeep
        elif algh.lower() == "dcfldd":
            return self.dcfldd
        else:
            raise exc.InvalidAlgorithm(algh)

class AlgorithmTypes(object):
    BBR, BBH, SIF, LSH, CTPH = range(5)
