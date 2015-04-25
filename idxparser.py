#Volatility plugin code:
#Copyright [2014] [Dave Lassalle (@superponible) <dave@superponible.comn>]
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
#IDX parsing code based on Brian Baskin's IDX Parser https://github.com/Rurik/Java_IDX_Parser/
#Copyright [2013] Brian Baskin
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#
#

"""
@author:       Dave Lassalle (@superponible)
@license:      Apache License 2.0
@contact:      dave@superponible.com
"""

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import struct
import binascii
import time
import zlib
__602BUFFER__ = 2 # If script fails to parse your 6.02 files, adjust this. It accounts for a dead space in the data

class IDXScanner(scan.BaseScanner):
    checks = [ ] 

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

##########################################################
#    Section two contains all download history data
##########################################################
def sec2_parse(idx_buff):
    sec2 = {}
    # first set of fields is the length of the URL and the URL the file was downloaded from
    csv_body = ''
    start = 128
    try:
        len_URL = struct.unpack(">l", idx_buff[start:start+4])[0]
    except struct.error as e:
        print "ERROR:", e
        return -1
    start += 4
    data_URL = idx_buff[start:start+len_URL]
    start += len_URL
    sec2["data_URL"] = data_URL
    if len(data_URL) == 0:
        return -1

    # second set of fields is the length of the IP address and the IP address
    try:
        len_IP = struct.unpack(">l", idx_buff[start:start+4])[0]
    except struct.error as e:
        print "ERROR:", e
        return -1
    start += 4
    data_IP = idx_buff[start:start+len_IP]
    start += len_IP
    sec2["data_IP"] = data_IP

    # next field is the number of additional fields that will follow
    try:
        sec2_fields = struct.unpack(">l", idx_buff[start:start+4])[0]
    except struct.error as e:
        print "ERROR: struct error"
        print "ERROR:", e
        print "ERROR: start:", start
        print "ERROR: len IP:", len_IP
        print "ERROR:", start, idx_buff[start:start+4], binascii.b2a_hex(idx_buff[start:start+4])
        print "ERROR:", binascii.b2a_hex(idx_buff[128:140])
        return -1
    start += 4
    sec2["fields"] = sec2_fields

    # parse out the number of fields speified, each set contains a length then the field itself
    # store them into the dictionary with their field number as key
    for i in range(0, sec2_fields):
        current_field = {}
        len_field = struct.unpack(">h", idx_buff[start:start+2])[0]
        start += 2
        field = idx_buff[start:start+len_field]
        start += len_field
        len_value = struct.unpack(">h", idx_buff[start:start+2])[0]
        start += 2
        value = idx_buff[start:start+len_value]
        start += len_value
        current_field["field"] = field
        current_field["value"] = value
        sec2[i] = current_field
    return sec2

#############################################################
#    Section two contains all download history data, for 6.02
#    Cache 6.02 files do NOT store IP addresses
#############################################################
def sec2_parse_old(idx_buff):
    sec2 = {}

    # first set of fields is the length of the URL and the URL the file was downloaded from
    start = 32
    len_URL = struct.unpack("b", idx_buff[start])[0]
    start += 1
    data_URL = idx_buff[start:start+len_URL]
    sec2["data_URL"] = data_URL

    # next field is the number of additional fields that will follow
    start += len_URL
    buf = idx_buff[start:start+__602BUFFER__]
    start += __602BUFFER__
    sec2_fields = struct.unpack(">l", idx_buff[start:start+4])[0]
    start += 4
    sec2["fields"] = sec2_fields

    # parse out the number of fields speified, each set contains a length then the field itself
    # store them into the dictionary with their field number as key
    for i in range(0, sec2_fields):
        current_field = {}
        len_field = struct.unpack(">h", idx_buff[start:start+2])[0]
        start += 2
        field = idx_buff[start:start+len_field]
        start += len_field
        len_value = struct.unpack(">h", idx_buff[start:start+2])[0]
        start += 2
        value = idx_buff[start:start+len_value]
        start += len_value
        current_field["field"] = field
        current_field["value"] = value
        sec2[i] = current_field

    # See if section 3 exists, if so the first field will be that magic and version
    sec3 = {}
    sec3_magic = ""
    sec3["exists"] = False
    if start+3 < len(idx_buff):
        sec3_magic, sec3_ver = struct.unpack(">HH", idx_buff[start:start+4])
        start += 4
        sec3["exists"] = True
        sec3["magic"] = sec3_magic
        sec3["ver"] = sec3_ver

    # parse section 3 if magic was right
    if sec3_magic == 0xACED:
        sec3_type = struct.unpack("b", idx_buff[start])[0]
        sec3["type"] = sec3_type
        start += 1
        if sec3_type == 0x77: #Data block
            # extract length of data, then extract the data.
            # if the field has GZIP data, unzip it
            start += 1
            block_len = struct.unpack(">l", idx_buff[start:start+4])[0]
            start += 4
            block_raw = idx_buff[start:start+block_len]
            start += block_len
            sec["block_raw"] = block_raw
            if block_raw[0:3] == "\x1F\x8B\x08": # Valid GZIP header
                try:
                    sec3_unc = zlib.decompress(block_raw, 15+32) # Trick to force bitwindow size
                    sec3["unc"]
                except zlib.error as e:
                    print e
    return (sec2, sec3)

##########################################################
#    Section three contains a copy of the JAR manifest
##########################################################
def sec3_parse(idx_buff, sec2_len, sec3_len):
    start = 128 + sec2_len
    # extract the specified length of section 3
    sec3_data = idx_buff[start:start+sec3_len]

    # if the data starts with a GZIP header, unzip it and return
    if sec3_data[0:3] == "\x1F\x8B\x08": # Valid GZIP header
        try:
            sec3_unc = zlib.decompress(sec3_data, 15+32) # Trick to force bitwindow size
            return sec3_unc.strip()
        except zlib.error as e:
            return "error unzipping"

##########################################################
#    Section four contains Code Signer details
#    Written from docs at:
#    http://docs.oracle.com/javase/6/docs/platform/serialization/spec/protocol.html
##########################################################
def sec4_parse(idx_buff, sec2_len, sec3_len, sec4_len):
    sec4 = {}

    # extract the magic and version in the first field 
    unknowns = 0
    start = 128 + sec2_len + sec3_len
    sec4_start = start
    if len(idx_buff[start:start+2]) < 2:
        return -1
    sec4_magic, sec4_ver = struct.unpack(">HH", idx_buff[start:start+4])
    sec4["magic"] = sec4_magic
    sec4["ver"] = sec4_ver
    start += 4

    # only continue if the magic value was correct
    if sec4_magic == 0xACED: # Magic number for Java serialized data, version always appears to be 5
        # counter for number of fields to parse when printing
        fields = 0
        sec4["fields"] = fields
        while not start >= len(idx_buff) and sec4_len > (start - sec4_start): # If current offset isn't at end of file yet
            if unknowns > 5:
                sec4[fields] = "Too many unrecognized bytes. Exiting."
                sec4["fields"] += 1
                return sec4

            # get the type of the current field
            sec4_type = struct.unpack("B", idx_buff[start])[0]
            start += 1
            if sec4_type == 0x77: #Data block ..
                                  #This _should_ parse for 0x78 (ENDDATABLOCK) but Oracle didn't follow their own specs for IDX files.
                sec4[fields] = "[*] Found: Data block. "
                # dump the contents of the data block and either unzip and print or just print
                block_len = struct.unpack("b", idx_buff[start])[0]
                start += 1
                block_raw = idx_buff[start:start+block_len]
                start += block_len
                if block_raw[0:3] == "\x1F\x8B\x08": # Valid GZIP header
                    try:
                        sec4_unc = zlib.decompress(block_raw, 15+32) # Trick to force bitwindow size
                        sec4[fields] += sec4_unc.encode("hex")
                    except zlib.error as e:
                        sec4_unc = "error unzipping"
                        sec4[fields] += sec4_unc
                else:
                    sec4[fields] += "Length: {0:<2d}\nData: {1:<10s}\tHex: {2:s}".format(block_len, block_raw.strip(), block_raw.encode("hex"))
            elif sec4_type == 0x73: #Object
                sec4[fields] = "[*] Found: Object"
            elif sec4_type == 0x72: #Class Description
                sec4[fields] = "[*] Found: Class Description:"
                block_len = struct.unpack(">h", idx_buff[start:start+2])[0]
                start += 2
                block_raw = idx_buff[start:start+block_len]
                start += block_len
                sec4[fields] += block_raw
            else:
                sec4[fields] = "Unknown serialization opcode found: 0x{0:X}".format(sec4_type)
            fields += 1
            sec4["fields"] += 1
    return sec4

class IDXParser(common.AbstractWindowsCommand):
    """ Scans for and parses Java IDX files """
    #@staticmethod
    #def is_valid_profile(profile):
        #return (profile.metadata.get('os', 'unknown') == 'windows' and
                #(profile.metadata.get('major') == 5 or
                 #profile.metadata.get('major') == 6))

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(address_space.profile):
            debug.error("This command does not support the selected profile.")

        # Needles represent version number (602, 603, 604, 605).  606 commented out for now
        scanner = IDXScanner(needles = ['\x00\x00\x00\x00\x02\x5a\x00',
                                        '\x00\x00\x00\x00\x02\x5b\x00',
                                        '\x00\x00\x00\x00\x02\x5c\x00',
                                        '\x00\x00\x00\x00\x02\x5d\x00',
                                        #'\x00\x00\x00\x00\x02\x5e\x00',
                                       ])
        idx_files = []
        print "Scanning for IDX files, this can take a while............."
        print "-" * 80
        for offset in scanner.scan(address_space):
            # create a dictionary to hold IDX info
            idx = {}
            idx_buff = address_space.read(offset, 4096)

            # extract version number
            version = struct.unpack(">I",idx_buff[2:6])[0]
            idx["version"] = version

            # this should always be true because the needles will only find these versions
            if version in [602,603,604,605]:
                sec1 = {}

                # start parsing at a different location based on the version number
                if version in [602,603,604]:
                    start = 8
                elif version in [605]:
                    start = 6
                start += 1

                # sanity check on the Content length field
                content_len = struct.unpack(">l", idx_buff[start:start+4])[0]
                sec1["content_len"] = content_len
                if content_len<=0 or content_len > 50000000:
                    continue
                start += 4

                # timestamps are 8 byte fields representing epoch time
                last_mod = struct.unpack(">q", idx_buff[start:start+8])[0]/1000
                sec1["last_mod"] = last_mod
                start += 8
                expiration = struct.unpack(">q", idx_buff[start:start+8])[0]/1000
                sec1["expiration"] = expiration
                start += 8
                validation = struct.unpack(">q", idx_buff[start:start+8])[0]/1000
                sec1["validation"] = validation
                start += 8

                # sanity checks on timestamps (no later than year 2020)
                if last_mod > 1577836800 or expiration > 1577836800 or validation > 1577836800 or last_mod < 0 or expiration < 0 or validation < 0:
                    continue

                # get lengths for other sections. version 602 only has section 2
                if version == 602:
                    sec2_len = 1
                    sec3_len = 0
                    sec4_len = 0
                    sec5_len = 0
                    sec1["sec2_len"] = sec2_len
                    sec1["sec3_len"] = sec3_len
                    sec1["sec4_len"] = sec4_len
                    sec1["sec5_len"] = sec5_len
                elif version in [603, 604, 605]:
                    known_to_be_signed = idx_buff[start]
                    start += 1
                    sec2_len = struct.unpack(">i", idx_buff[start:start+4])[0]
                    start += 4
                    sec3_len = struct.unpack(">i", idx_buff[start:start+4])[0]
                    start += 4
                    sec4_len = struct.unpack(">i", idx_buff[start:start+4])[0]
                    start += 4
                    sec5_len = struct.unpack(">i", idx_buff[start:start+4])[0]
                    start += 4
                    sec1["sec2_len"] = sec2_len
                    sec1["sec3_len"] = sec3_len
                    sec1["sec4_len"] = sec4_len
                    sec1["sec5_len"] = sec5_len

                    # versions 603, 604, 605 have some additional timestmaps and other fields
                    blacklist_timestamp = struct.unpack(">q", idx_buff[start:start+8])[0]/1000
                    sec1["blacklist_timestamp"] = blacklist_timestamp
                    start += 8
                    cert_expiration_date = struct.unpack(">q", idx_buff[start:start+8])[0]/1000
                    sec1["cert_expiration_date"] = cert_expiration_date
                    start += 8
                    class_verification_status = idx_buff[start]
                    sec1["class_verification_status"] = class_verification_status
                    start += 1
                    reduced_manifest_length = struct.unpack(">l", idx_buff[start:start+4])[0]
                    sec1["reduced_manifest_length"] = reduced_manifest_length
                    start += 4

            else:
                print "ERROR: Current file version, {}, is not supported at this time.".format(version)
                continue

            # parse section 2
            if sec2_len:
                if version == 602: 
                    (sec2, sec3) = sec2_parse_old(idx_buff)
                    if sec2 == -1:
                        continue
                    idx["sec2"] = sec2
                    idx["sec3"] = sec3
                else: 
                    idx["sec2"] = sec2_parse(idx_buff)
                    if idx["sec2"] == -1:
                        continue

            # parse section 3
            if sec3_len:
                idx["sec3"] = sec3_parse(idx_buff, sec2_len, sec3_len)
                #if idx["sec3"] == "error unzipping":
                    #sec4_len = 0
                    #sec1["sec4_len"] = 0
                    #sec5_len = 0
                    #sec1["sec5_len"] = 0

            # parse section 4
            if sec4_len:
                idx["sec4"] = sec4_parse(idx_buff, sec2_len, sec3_len, sec4_len)

            idx["sec1"] = sec1

            yield idx

    def render_text(self, outfd, data):
        for idx in data:
            print "\n[*] Section 1 (Metadata) found:"
            print "Content length: {}".format(idx["sec1"]["content_len"])
            print "Last modified date: {0:s} (epoch: {1:d})".format(time.strftime("%a, %d %b %Y %X GMT", time.gmtime(idx["sec1"]["last_mod"])), idx["sec1"]["last_mod"])
            if idx["sec1"]["expiration"]:
                print "Expiration date: {0:s} (epoch: {1:d})".format(time.strftime("%a, %d %b %Y %X GMT", time.gmtime(idx["sec1"]["expiration"])), idx["sec1"]["expiration"])
            if idx["sec1"]["validation"] and idx["version"] > 602: #While 6.02 technically supports this, every sample I've seen just has 3 null bytes and skips to Section 2
                print "Validation date: {0:s} (epoch: {1:d})".format(time.strftime("%a, %d %b %Y %X GMT", time.gmtime(idx["sec1"]["validation"])), idx["sec1"]["validation"])


            if idx["sec1"]["sec2_len"]:
                if idx["version"] == 602: 
                    # Version 602
                    print "\n[*] Section 2 (Download History) found:"
                    print "URL: {}".format(idx["sec2"]["data_URL"])
                    for i in range(0, idx["sec2"]["fields"]):
                        print "{}: {}".format(idx["sec2"][i]["field"], idx["sec2"][i]["value"])
                    if idx["sec3"]["exists"] == True:
                        print "\n[*] Section 3 (Additional Data) found:"
                        if idx["sec3"]["magic"] == 0xACED:
                            print "[*] Serialized data found of type:",
                            if idx["sec3"]["type"] == 0x77:
                                print "Data Block"
                                if idx["sec3"]["block_raw"][0:3] == "\x1F\x8B\x08":
                                    print "[*] Compressed data found"
                                    print idx["sec3"]["unc"]
                            else:
                                print "Unknown serialization opcode found: 0x{0:X}".format(sec4_type)
                else:
                    # Versions > 602
                    print "Section 2 length: {}".format(idx["sec1"]["sec2_len"])
                    if idx["sec1"]["sec3_len"]: print "Section 3 length: {}".format(idx["sec1"]["sec3_len"])
                    if idx["sec1"]["sec4_len"]: print "Section 4 length: {}".format(idx["sec1"]["sec4_len"])
                    if idx["sec1"]["sec5_len"]: print "Section 5 length: {}".format(idx["sec1"]["sec5_len"])
        
                    if idx["sec1"]["expiration"]:
                        try:
                            print "Blacklist Expiration date: {0:s} (epoch: {1:d})".format(time.strftime("%a, %d %b %Y %X GMT", time.gmtime(idx["sec1"]["blacklist_timestamp"])), idx["sec1"]["blacklist_timestamp"])
                        except ValueError as e:
                            print "Blacklist Expiration date out of range (epoch: {0:d})".format(idx["sec1"]["blacklist_timestamp"])
                    if idx["sec1"]["cert_expiration_date"]:
                        try:
                            print "Certificate Expiration date: {0:s} (epoch: {1:d})".format(time.strftime("%a, %d %b %Y %X GMT", time.gmtime(idx["sec1"]["cert_expiration_date"])), idx["sec1"]["cert_expiration_date"])
                        except ValueError as e:
                            print "Certificate Expiration date out of range (epoch: {0:d})".format(idx["sec1"]["cert_expiration_date"])

                    print "\n[*] Section 2 (Download History) found:"
                    print "URL: {}".format(idx["sec2"]["data_URL"])
                    print "IP: {}".format(idx["sec2"]["data_IP"])
                    for i in range(0, idx["sec2"]["fields"]):
                        print "{}: {}".format(idx["sec2"][i]["field"], idx["sec2"][i]["value"])

            if idx["sec1"]["sec3_len"]:
                print "\n[*] Section 3 (Jar Manifest) found:"
                print idx["sec3"]

            if idx["sec1"]["sec4_len"] and idx["sec4"] != -1:
                print "\n[*] Section 4 (Code Signer) found:"
                if idx["sec4"] == -1:
                    print "Section 4 not available"
                elif idx["sec4"]["magic"] == 0xACED:
                    for i in range(0, idx["sec4"]["fields"]):
                        if not idx["sec4"][i].startswith("Unknown"):
                            print idx["sec4"][i]

            if idx["sec1"]["sec5_len"]:
                print "\n[*] Section 5 found (offset 0x{0:X}, length {1:d} bytes)".format(128 + idx["sec1"]["sec2_len"] + idx["sec1"]["sec3_len"] + idx["sec1"]["sec4_len"], idx["sec1"]["sec5_len"])

            print "-" * 80

