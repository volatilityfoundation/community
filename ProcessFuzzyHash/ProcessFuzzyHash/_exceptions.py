# pylint: disable=E0401,C0111,C0103,C0412,E0602
'''
    File name: _exceptions.py
    Author: Inaki Abadia
    Date created: 2/1/2017
    Date last modified: 9/11/2017
    Python Version: 2.7
'''

class InvalidAlgorithm(Exception):
    def __init__(self, msg):
        super(InvalidAlgorithm, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr("<" + self.msg + "> is not a valid Algorithm.")

class NoPE(Exception):
    def __init__(self, msg):
        super(NoPE, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr("<" + self.msg + "> PDump doesn't contain a PE.")

class NoSection(Exception):
    def __init__(self):
        super(NoSection, self).__init__()

    def __str__(self):
        return repr("Please specify at least one section (-h for help).")

class InvalidPEHeader(Exception):
    def __init__(self, msg):
        super(InvalidPEHeader, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr("PE doesn't contain <" + self.msg + "> header.")

class FullProcessAndPE(Exception):
    def __init__(self, msg):
        super(FullProcessAndPE, self).__init__(msg)
        self.msg = msg

    def __str__(self):
        return repr("Can't hash full process and PE/PE sections at the same time: {!s}".format(self.msg))
