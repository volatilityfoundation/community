# Copyright (C) 2014 Dave Lassalle (@superponible) <dave@superponible.com>
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
@author:       Dave Lassalle (@superponible)
@license:      GNU General Public License 2.0 or later
@contact:      dave@superponible.com
"""

# The following links are useful for understanding SQL record format
# - http://www.evolane.com/support/manuals/shared/manuals/tcltk/sqlite/fileformat.html
# - http://forensicsfromthesausagefactory.blogspot.com/2011/04/carving-sqlite-databases-from.html
# - http://forensicsfromthesausagefactory.blogspot.in/2011/05/analysis-of-record-structure-within.html

# The following links are useful for information on decrypting cookies
# - http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
# - https://gist.github.com/DakuTree/98c8362fb424351b803e
# - https://stackoverflow.com/questions/23153159/decrypting-chrome-iums-cookies/23727331#23727331

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import binascii
import sqlite_help
import csv
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

FORWARD = sqlite_help.FORWARD
BACKWARD = sqlite_help.BACKWARD

# Function to get rid of padding
def clean(x): 
    """Strip the padding from the end of the AES decrypted string"""
    return x[:-ord(x[-1])]

def decrypt_cookie_value(x, key):
    """Decrypts a cookie using the key provided"""
    encrypted_value = x

    # Trim off the 'v10' that Chrome/ium prepends
    encrypted_value = encrypted_value[3:]

    # Default values used by both Chrome and Chromium in OSX and Linux
    iv = b' ' * 16

    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    if len(encrypted_value) % 16:
        return "INVALID_ENCRYPTED_LENGTH"
    decrypted = cipher.decrypt(encrypted_value)
    return clean(decrypted)

# The visits table has a 32 bit integer with different bits representing different page transitions
# details at https://github.com/jedesah/Chromium/blob/master/content/public/common/page_transition_types.h
# or https://developer.chrome.com/extensions/history
def map_transition(t):
    """Map the 32-bit integer transition t to the multiple transition types it represents"""
    transition = ""
    if (t & 0xFF) == 0:
        transition += "LINK;"
    if (t & 0xFF) == 1:
        transition += "TYPED;"
    if (t & 0xFF) == 2:
        transition += "BOOKMARK;"
    if (t & 0xFF) == 3:
        transition += "AUTO_SUBFRAME;"
    if (t & 0xFF) == 4:
        transition += "MANUAL_SUBFRAME;"
    if (t & 0xFF) == 5:
        transition += "GENERATED;"
    if (t & 0xFF) == 6:
        transition += "START_PAGE;"
    if (t & 0xFF) == 7:
        transition += "FORM_SUBMIT;"
    if (t & 0xFF) == 8:
        transition += "RELOAD-RESTORE-UNDO_CLOSE;"
    if (t & 0xFF) == 9:
        transition += "KEYWORD;"
    if (t & 0xFF) == 10:
        transition += "KEYWORD_GENERATED;"

    if (t & 0x03000000) == 0x03000000:
        transition += "FORWARD_BACK_FROM_ADDRESS_BAR;"
    elif (t & 0x03000000) == 0x01000000:
        transition += "FORWARD_BACK;"
    elif (t & 0x03000000) == 0x02000000:
        transition += "FROM_ADDRESS_BAR;"

    if (t & 0x04000000) == 0x04000000:
        transition += "HOME_PAGE;"

    if (t & 0x30000000) == 0x30000000:
        transition += "CHAIN_START_END;"
    elif (t & 0x30000000) == 0x10000000:
        transition += "CHAIN_START;"
    elif (t & 0x30000000) == 0x20000000:
        transition += "CHAIN_END;"

    if (t & 0xC0000000) == 0xC0000000:
        transition += "CLIENT_SERVER_REDIRECT;"
    elif (t & 0xC0000000) == 0x40000000:
        transition += "CLIENT_REDIRECT;"
    elif (t & 0xC0000000) == 0x80000000:
        transition += "SERVER_REDIRECT;"

    return transition



class ChromeScanner(scan.BaseScanner):
    checks = [ ] 

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset



class ChromeSearchTerms(common.AbstractWindowsCommand):
    """ Scans for and parses potential Chrome keyword search terms"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = ChromeScanner(needles = ['\x05\x01',
                                           '\x05\x02',
                                           '\x07\x01',
                                           '\x07\x02',
                                          ])
        keywords = {}
        for offset in scanner.scan(address_space):
            chrome_buff = address_space.read(offset-8, 800)
            start = 8

            # value after 2 needles should be 1, 2, or 3
            if (ord(chrome_buff[start+2]) not in (1,2,3)):
                continue

            # size of the first needle is determined by the varint starting at the 4th byte, which should be equal to the next varint as well
            if ((chrome_buff[start] == "\x05" and 13 < ord(chrome_buff[start+3]) < 128 and chrome_buff[start+3] == chrome_buff[start+4]) or 
                (chrome_buff[start] == "\x07" and ord(chrome_buff[start+3]) > 128 and chrome_buff[start+3:start+5] == chrome_buff[start+5:start+7])):

                # row_id is before the needles
                start -= 1
                (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
                # can't have a negative row_id (index)
                if row_id < 0:
                    continue

                # payload_length is length of sqlite record and the first item
                start -= varint_len
                if start < 0:
                    continue
                (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

                # payload_length should be much longer than this, but this is a safe minimum
                if payload_length < 6:
                    continue

                # jump back to the needles, the next 3 bytes are the needle matches
                payload_header_length = ord(chrome_buff[8])
                keyword_id_length = ord(chrome_buff[9])
                url_id_length = ord(chrome_buff[10])
                start = 11

                # lower_term_length follows the needles
                (lower_term_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                lower_term_length = sqlite_help.varint_to_text_length(lower_term_length)
                if lower_term_length < 0 or lower_term_length > 800:
                    continue
                start += varint_len

                # term_length follows lower_term_length
                (term_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                term_length = sqlite_help.varint_to_text_length(term_length)
                if term_length < 0 or term_length > 800:
                    continue
                start += varint_len

                # keyword_id is first field
                keyword_id = sqlite_help.sql_unpack(chrome_buff[start:start+keyword_id_length])
                if keyword_id < 0:
                    continue
                start += keyword_id_length

                # url_id is the second field
                url_id = sqlite_help.sql_unpack(chrome_buff[start:start+url_id_length])
                if url_id < 0:
                    continue
                start += url_id_length

                # lower_term is the next field
                lower_term = chrome_buff[start:start+lower_term_length]
                start += lower_term_length

                # term is the last field
                term = chrome_buff[start:start+term_length]

                # the two term fields should be the same if both are made lowercase
                if lower_term != term.lower():
                    continue

                if lower_term == "":
                    continue

                # store a tuple of all values in a dictionary so we only print each unique record once
                keywords_tuple = (row_id, keyword_id, url_id, lower_term, term)
                if not keywords.get(keywords_tuple):
                    keywords[keywords_tuple] = keywords.get(keywords_tuple, 0) + 1
                    yield keywords_tuple

            continue

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Row ID", "6"), ("Keyword ID", "10"), ("URL ID", "6"), ("Lowercase", "64"), ("Entered Text", "64")])
        for row_id, keyword_id, url_id, lower_term, term in data:
            self.table_row(outfd, row_id, keyword_id, url_id, lower_term, term)

    def render_csv(self, outfd, data):
        outfd.write('"id","keyword_id","url_id","lower_term","term"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)



class ChromeDownloads(common.AbstractWindowsCommand):
    """ Scans for and parses potential Chrome download records"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = ChromeScanner(needles = ['\x01\x01\x01',
                                          ])
        downloads = {}
        for offset in scanner.scan(address_space):
            chrome_buff = address_space.read(offset-16, 3000)
            start = 16
            if ord(chrome_buff[19]) not in (1, 6) and ord(chrome_buff[20]) != 1:
                continue

            good = False

            # get all of the single byte lengths around the needle
            (start_time_length, start_time) = sqlite_help.varint_type_to_length(ord(chrome_buff[start-3]))
            (received_bytes_length, received_bytes) = sqlite_help.varint_type_to_length(ord(chrome_buff[start-2]))
            (total_bytes_length, total_bytes) = sqlite_help.varint_type_to_length(ord(chrome_buff[start-1]))
            (state_length, state) = sqlite_help.varint_type_to_length(ord(chrome_buff[start]))
            (danger_type_length, danger_type) = sqlite_help.varint_type_to_length(ord(chrome_buff[start+1]))
            (interrupt_reason_length, intterupt_reason) = sqlite_help.varint_type_to_length(ord(chrome_buff[start+2]))
            (end_time_length, end_time) = sqlite_help.varint_type_to_length(ord(chrome_buff[start+3]))
            (opened_length, opened) = sqlite_help.varint_type_to_length(ord(chrome_buff[start+4]))

            # go backwards from needle first
            start -= 4

            # times should be 8 bytes, might be 1 byte if time is empty, including 6 bytes just in case
            if start_time_length not in (1, 6, 8) or end_time_length not in (1, 6, 8):
                continue

            if received_bytes_length not in range (0,7) or total_bytes_length not in range (0, 7):
                continue

            (target_path_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            target_path_length = sqlite_help.varint_to_text_length(target_path_length)
            if target_path_length < 0 or target_path_length > 1024:
                continue
            start -= varint_len

            (current_path_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            current_path_length = sqlite_help.varint_to_text_length(current_path_length)
            if current_path_length < 0 or current_path_length > 1024:
                continue
            start -= varint_len

            (id_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            if id_length < 0 or id_length > 1024000:
                continue
            start -= varint_len

            (payload_header_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            if payload_header_length < 0 or payload_header_length > 1024000:
                continue
            start -= varint_len
            payload_header_start = start + 1

            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            start -= varint_len

            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            start -= varint_len

            # jump to after opened_length needle match and go forward
            start = 21

            (referrer_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
            referrer_length = sqlite_help.varint_to_text_length(referrer_length)
            start += varint_len

            # check that the full record length is still longer than the total of some of the longer fields
            if payload_length < payload_header_length + current_path_length + target_path_length + referrer_length:
                continue

            # For the next 6 fields:
            #   if the last fields in the record are null, the fields are sometimes not included at all
            #   so check if the current position (start) minus the start of the header is greater
            #   than the size specifed in payload_header_length
            if start - payload_header_start >= payload_header_length:
                by_ext_id_length = 0
            else:
                (by_ext_id_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                by_ext_id_length = sqlite_help.varint_to_text_length(by_ext_id_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                by_ext_name_length = 0
            else:
                (by_ext_name_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                by_ext_name_length = sqlite_help.varint_to_text_length(by_ext_name_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                etag_length = 0
            else:
                (etag_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                etag_length = sqlite_help.varint_to_text_length(etag_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                last_modified_length = 0
            else:
                (last_modified_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                last_modified_length = sqlite_help.varint_to_text_length(last_modified_length)
                start += varint_len

            # the mime_type related fields are new to chrome 37, but can be handled the same way
            if start - payload_header_start >= payload_header_length:
                mime_type_length = 0
            else:
                (mime_type_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                mime_type_length = sqlite_help.varint_to_text_length(mime_type_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                original_mime_type_length = 0
            else:
                (original_mime_type_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                original_mime_type_length = sqlite_help.varint_to_text_length(original_mime_type_length)
                start += varint_len

            # end of the payload header.  check that the length found matches the value in the length field
            payload_header_end = start
            if payload_header_length != payload_header_end - payload_header_start:
                continue

            # id field is 0 because it is actually stored in row_id above
            start += id_length

            current_path = chrome_buff[start:start+current_path_length]
            start += current_path_length

            target_path = chrome_buff[start:start+target_path_length]
            start += target_path_length

            # extract the time, unpack it to an integer, convert microseconds to string
            start_time = chrome_buff[start:start+start_time_length]
            start_time = sqlite_help.sql_unpack(start_time)
            if start_time < 11900000000000000 or start_time > 17000000000000000:
                continue
            start_time = sqlite_help.get_wintime_from_msec(start_time)
            start += start_time_length

            received_bytes = chrome_buff[start:start+received_bytes_length]
            received_bytes = sqlite_help.sql_unpack(received_bytes)
            start += received_bytes_length

            total_bytes = chrome_buff[start:start+total_bytes_length]
            total_bytes = sqlite_help.sql_unpack(total_bytes)
            start += total_bytes_length

            state = ord(chrome_buff[start:start+state_length])
            start += state_length

            danger_type = ord(chrome_buff[start:start+danger_type_length])
            start += danger_type_length

            interrupt_reason = ord(chrome_buff[start:start+interrupt_reason_length])
            start += interrupt_reason_length

            # extract the time, unpack it to an integer, convert microseconds to string
            end_time = chrome_buff[start:start+end_time_length]
            end_time = sqlite_help.sql_unpack(end_time)
            end_time = sqlite_help.get_wintime_from_msec(end_time)
            start += end_time_length

            opened = ord(chrome_buff[start:start+opened_length])
            start += opened_length

            referrer = chrome_buff[start:start+referrer_length]
            start += referrer_length

            by_ext_id = ""
            if by_ext_id_length:
                by_ext_id = ord(chrome_buff[start:start+by_ext_id_length])
            start += by_ext_id_length

            by_ext_name = ""
            if by_ext_name_length:
                by_ext_name = chrome_buff[start:start+by_ext_name_length]
            start += by_ext_name_length

            etag = ""
            if etag_length:
                etag = chrome_buff[start:start+etag_length]
            start += etag_length

            last_modified = ""
            if last_modified_length:
                last_modified = chrome_buff[start:start+last_modified_length]
            start += last_modified_length

            mime_type = ""
            if mime_type_length:
                mime_type = chrome_buff[start:start+mime_type_length]
            start += mime_type_length

            original_mime_type = ""
            if original_mime_type_length:
                original_mime_type = chrome_buff[start:start+original_mime_type_length]
            start += original_mime_type_length

            # add all values as a tuple to the dictionary so we only print each unique record once
            downloads_tuple = (row_id, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, end_time, opened, referrer, by_ext_id, by_ext_name, etag, last_modified, mime_type, original_mime_type)
            if not downloads.get(downloads_tuple):
                downloads[downloads_tuple] = downloads.get(downloads_tuple, 0) + 1
                yield downloads_tuple

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Row Id", "6"), ("Current Path", "80"), ("Target Path", "80"), ("Start Time", "26"), ("Received", "12"), ("Total Bytes", "12"), ("State", "5"), ("Danger", "6"), ("Interrupt", "9"), ("End Time", "26"), ("Opened", "6"), ("Referer", "64"), ("By Ext ID", "9"), ("By Ext Name", "10"), ("ETag", "24"), ("Last Modified", "30"), ("MIME Type", "32"), ("Original MIME Type", "32")])
        for row_id, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, end_time, opened, referrer, by_ext_id, by_ext_name, etag, last_modified, mime_type, orignal_mime_type in data:
            self.table_row(outfd, row_id, current_path, target_path, str(start_time), received_bytes, total_bytes, state, danger_type, interrupt_reason, str(end_time), opened, referrer, by_ext_id, by_ext_name, etag, last_modified, mime_type, orignal_mime_type)

    def render_csv(self, outfd, data):
        outfd.write('"id","current_path","target_path","start_time","received_bytes","total_bytes","state","danger","interrupt","end_time","opened","referer","by_ext_id","by_ext_name","etag","last_modified","mime_type","original_mime_type"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)

    def render_body(self, outfd, data):
        for row_id, current_path, target_path, start_time, received_bytes, total_bytes, state, danger_type, interrupt_reason, end_time, opened, referrer, by_ext_id, by_ext_name, etag, last_modified, mime_type, orignal_mime_type in data:
            start = sqlite_help.unix_time(start_time)
            end = sqlite_help.unix_time(end_time)
            download = referrer + " -> " + target_path + " (" + str(total_bytes) + " bytes"
            download = download.replace("|","\\")
            d = (0, "[CHROMEDOWNLOADS] " + download, 0, "---------------", 0, 0, 0, end, end, end, start)
            csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE).writerow(d)



class ChromeDownloadChains(common.AbstractWindowsCommand):
    """ Scans for and parses potential Chrome download chain records"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = ChromeScanner(needles = ['\x04\x01\x01',
                                           '\x04\x02\x01',
                                           '\x05\x01\x01',
                                           '\x05\x02\x01',
                                          ])
        download_chains = {}
        for offset in scanner.scan(address_space):
            chrome_buff = address_space.read(offset-8, 2100)
            start = 8
            # if the first needle (header_length) is 4; the varint is < 128, if it's 5, the varint is > 128
            if (chrome_buff[start] == "\x04" and 13 < ord(chrome_buff[start+3]) < 128) or (chrome_buff[start] == "\x05" and ord(chrome_buff[start+3]) > 128):

                    good = False

                    # row_id is before the needles
                    start -= 1
                    (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
                    # can't have a negative row_id (index)
                    if row_id < 0:
                        continue

                    # payload_length is length of sqlite record and the first item
                    start -= varint_len
                    if start < 0:
                        continue
                    (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

                    # payload_length should be much longer than this, but this is a safe minimum
                    if payload_length < 6:
                        continue

                    # the next 3 bytes are the needle matches
                    payload_header_length = ord(chrome_buff[8])
                    chain_id_length = ord(chrome_buff[9])
                    chain_index_length = ord(chrome_buff[10])
                    start = 11
                    
                    # url_length follows the needles
                    (url_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                    url_length = sqlite_help.varint_to_text_length(url_length)
                    if url_length < 0 or url_length > 2100:
                        continue

                    # chain_id is first field
                    start += varint_len
                    chain_id = sqlite_help.sql_unpack(chrome_buff[start:start+chain_id_length])
                    if chain_id < 0:
                        continue

                    # chain index is the second field
                    start += chain_id_length
                    chain_index = sqlite_help.sql_unpack(chrome_buff[start:start+chain_index_length])
                    if chain_index < 0:
                        continue

                    # url is the last field
                    start += chain_index_length
                    url = chrome_buff[start:start+url_length]
                    
                    if url[0:4] == "http" or url[0:3] == "ftp" or url[0:4] == "file" or url[0:6] == "chrome" or url[0:4] == "data" or url[0:5] == "about":
                        # add the values as a tuple to a dictionary so we only print each unique record once
                        chain_tuple = (row_id, chain_id, chain_index, url)
                        if not download_chains.get(chain_tuple):
                            download_chains[chain_tuple] = download_chains.get(chain_tuple, 0) + 1
                            yield chain_tuple
            continue    

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Row ID", "6"), ("Chain ID", "11"), ("Chain Index", "11"), ("URL", "120")])
        for row_id, chain_id, chain_index, url in data:
            self.table_row(outfd, row_id, chain_id, chain_index, url)

    def render_csv(self, outfd, data):
        outfd.write('"id","chain_id","chain_index","url"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)



class ChromeHistory(common.AbstractWindowsCommand):
    """ Scans for and parses potential Chrome url history"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('NULLTIME', short_option = 'N', default = True,
                          help = "Don't print entries with null timestamps",
                          action = "store_false")

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        # URLs
        scanner = ChromeScanner(needles = ['\x01\x01http',
                                           '\x01\x01file',
                                           '\x01\x01ftp',
                                           '\x01\x01chrome',
                                           '\x01\x01data',
                                           '\x01\x01about',
                                          ])
        urls = {}
        for offset in scanner.scan(address_space):
            chrome_buff = address_space.read(offset-15, 4500)
            start = 15

            # start before the needle match and work backwards, do sanity checks on some values before proceeding
            if ord(chrome_buff[start-1]) not in (1,6):
                continue
            start -= 1
            (last_visit_time_length, last_visit_time) = sqlite_help.varint_type_to_length(ord(chrome_buff[start]))

            if not (0 < ord(chrome_buff[start-1]) < 4):
                continue
            start -= 1
            typed_count_length = ord(chrome_buff[start])

            if not (0 < ord(chrome_buff[start-1]) < 4):
                continue
            start -= 1
            visit_count_length = ord(chrome_buff[start])

            start -= 1
            (title_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            title_length = sqlite_help.varint_to_text_length(title_length)

            start -= varint_len
            (url_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            url_length = sqlite_help.varint_to_text_length(url_length)
            
            start -= varint_len
            url_id_length = ord(chrome_buff[start])

            start -= 1
            payload_header_length = ord(chrome_buff[start])

            start -= 1
            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            # can't have a negative row_id (index)
            if row_id < 0:
                continue

            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

            # payload_length should be much longer than this, but this is a safe minimum
            if payload_length < 6:
                continue

            # jump back to the index of the needle match
            (hidden_length, hidden) = sqlite_help.varint_type_to_length(ord(chrome_buff[15]))
            (favicon_id_length, favicon_id) = sqlite_help.varint_type_to_length(ord(chrome_buff[16]))
            start = 17

            url_id = sqlite_help.sql_unpack(chrome_buff[start:start+url_id_length])

            start += url_id_length
            url = chrome_buff[start:start+url_length]

            start += url_length
            title = chrome_buff[start:start+title_length]

            start += title_length
            visit_count = sqlite_help.sql_unpack(chrome_buff[start:start+visit_count_length])

            start += visit_count_length
            typed_count = sqlite_help.sql_unpack(chrome_buff[start:start+typed_count_length])

            # extract the time, unpack it to an integer, convert microseconds to string
            start += typed_count_length
            last_visit_time = chrome_buff[start:start+last_visit_time_length]
            last_visit_time = sqlite_help.sql_unpack(last_visit_time)
            if type(last_visit_time) is str:
                continue
            last_visit_time = sqlite_help.get_wintime_from_msec(last_visit_time)
            if last_visit_time.year == 1601 and self._config.NULLTIME == False:
                continue

            start += last_visit_time_length
            hidden = sqlite_help.sql_unpack(chrome_buff[start:start+hidden_length])

            start += hidden_length
            favicon_id = sqlite_help.sql_unpack(chrome_buff[start:start+favicon_id_length])

            # store the values as a tuple in a dictionary so we only print each unique record once
            url_tuple = (row_id, url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id) 
            if not urls.get(url_tuple):
                urls[url_tuple] = urls.get(url_tuple, 0) + 1
                yield url_tuple

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Index", "6"), ("URL", "80"), ("Title", "80"), ("Visits", "6"), ("Typed", "5"), ("Last Visit Time", "26"), ("Hidden", "6"), ("Favicon ID", "10")])
        for index, url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id in data:
            self.table_row(outfd, index, url, title, visit_count, typed_count, str(last_visit_time), hidden, favicon_id)

    def render_csv(self, outfd, data):
        outfd.write('"index","url","title","visits","typed","last_visit_time","hidden","favicon_id"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)

    def render_body(self, outfd, data):
        for index, url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id in data:
            end = sqlite_help.unix_time(last_visit_time)
            name = url + " -- " + title
            name = name.replace("|", "-")
            d = (0, "[CHROMEHISTORY] " + name, 0, "---------------", 0, 0, 0, end, end, end, end)
            csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)



class ChromeCookies(common.AbstractWindowsCommand):
    """Scans for and parses potential Chrome cookie data"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('KEY', short_option = 'K', default = False,
                          help = "Password to generate PBKDF key to decrypt cookies",
                          action = "store")
        config.add_option('OS', short_option = 'O', default = False,
                          help = "Manually specify OS, rather than obtaining from profile",
                          choices = ('mac','linux','windows'),
                          action = "store")

        self.key = False
        if self._config.OS:
            os = self._config.OS
        else:
            addr_space = utils.load_as(self._config)
            os = addr_space.profile.metadata.get('os', 'unknown')
        if os == 'mac' and self._config.KEY:
            salt = b'saltysalt'
            length = 16
            iterations = 1003
            self.key = PBKDF2(self._config.KEY, salt, length, iterations)
        elif os == 'linux':
            salt = b'saltysalt'
            length = 16
            iterations = 1
            self.key = PBKDF2(b'peanuts', salt, length, iterations)

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' or
                profile.metadata.get('os', 'unknown') == 'mac' or
                profile.metadata.get('os', 'unknown') == 'linux')

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = ChromeScanner(needles = ['\x01\x01\x01\x06\x01\x01\x01',
                                           '\x06\x01\x01\x06\x01\x01\x01',
                                          ])
        cookies = {}
        for offset in scanner.scan(address_space):
            chrome_buff = address_space.read(offset-20, 4096)
            start = 20

            # start from before the needle match and go backwards
            start -= 1
            (path_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            path_length = sqlite_help.varint_to_text_length(path_length)

            start -= varint_len
            (value_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            value_length = sqlite_help.varint_to_text_length(value_length)

            start -= varint_len
            (name_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            name_length = sqlite_help.varint_to_text_length(name_length)

            start -= varint_len
            (host_key_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            host_key_length = sqlite_help.varint_to_text_length(host_key_length)

            start -= varint_len
            (creation_utc_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

            start -= varint_len
            (payload_header_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            start -= varint_len
            # mark the start of the payload_headers
            payload_header_start = start + 1

            # creation_utc is the primary key and is stored in row_id
            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            creation_utc = row_id

            start -= varint_len
            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

            # jump back to the needle match and set each length from the byte value
            (expires_utc_length, expires_utc) = sqlite_help.varint_type_to_length(ord(chrome_buff[20]))
            (secure_length, secure) = sqlite_help.varint_type_to_length(ord(chrome_buff[21]))
            (httponly_length, httponly) = sqlite_help.varint_type_to_length(ord(chrome_buff[22]))
            (last_access_utc_length, last_access_utc) = sqlite_help.varint_type_to_length(ord(chrome_buff[23]))
            (has_expires_length, has_expires) = sqlite_help.varint_type_to_length(ord(chrome_buff[24]))
            (persistent_length, persistent) = sqlite_help.varint_type_to_length(ord(chrome_buff[25]))
            (priority_length, priority) = sqlite_help.varint_type_to_length(ord(chrome_buff[26]))
            start = 27

            # only one more header after the needles, the encrypted_value_length
            encrypted_value_length = 0
            encrypted_value = ""
            if start - payload_header_start >= payload_header_length:
                encrypted_value_length = 0
                encrypted_value = "n/a"
            else:
                (encrypted_value_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                encrypted_value_length = sqlite_help.varint_to_blob_length(encrypted_value_length)
                start += varint_len

            if creation_utc_length > 0:
                creation_utc = sqlite_help.sql_unpack(chrome_buff[start:start+creation_utc_length])
            if creation_utc < 11900000000000000 or creation_utc > 17000000000000000:
                continue
            creation_utc = sqlite_help.get_wintime_from_msec(creation_utc)
            start += creation_utc_length

            host_key = chrome_buff[start:start+host_key_length]
            start += host_key_length

            name = chrome_buff[start:start+name_length]
            start += name_length

            value = chrome_buff[start:start+value_length]
            start += value_length

            path = chrome_buff[start:start+path_length]
            start += path_length

            # get the date the cookie expires to set it to "Never Expires"
            expires_utc = sqlite_help.sql_unpack(chrome_buff[start:start+expires_utc_length])
            if type(expires_utc) != int:
                continue
            if expires_utc > 0:
                expires_utc = sqlite_help.get_wintime_from_msec(expires_utc)
            elif expires_utc == 0:
                expires_utc = "Never Expires"
            start += expires_utc_length

            secure = sqlite_help.sql_unpack(chrome_buff[start:start+secure_length])
            start += secure_length

            httponly = sqlite_help.sql_unpack(chrome_buff[start:start+httponly_length])
            start += httponly_length

            last_access_utc = sqlite_help.sql_unpack(chrome_buff[start:start+last_access_utc_length])
            last_access_utc = sqlite_help.get_wintime_from_msec(last_access_utc)
            start += last_access_utc_length

            has_expires = sqlite_help.sql_unpack(chrome_buff[start:start+has_expires_length])
            start += has_expires_length

            persistent = sqlite_help.sql_unpack(chrome_buff[start:start+persistent_length])
            start += persistent_length

            priority = sqlite_help.sql_unpack(chrome_buff[start:start+priority_length])
            start += priority_length

            if encrypted_value_length > 0:
                encrypted_value = chrome_buff[start:start+encrypted_value_length]
                if encrypted_value[:3] == b'v10' and self.key:
                    value = decrypt_cookie_value(encrypted_value, self.key)
                encrypted_value = binascii.b2a_hex(encrypted_value)
                start += encrypted_value_length

            # store the values as a tuple in a dictionary so we only print each record once
            cookie_tuple = (creation_utc, host_key, name, value, path, expires_utc, secure, httponly, last_access_utc, has_expires, persistent, priority, encrypted_value)
            if not cookies.get(cookie_tuple):
                yield cookie_tuple
                cookies[cookie_tuple] = cookies.get(cookie_tuple, 0) + 1

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Creation Time", "26"), ("Host Key", "32"), ("Name", "16"), ("Value", "80"), ("Path", "24"), ("Expires Time", "26"), ("Secure", "6"), ("HttpOnly", "8"), ("Last Access Time", "26"), ("Expires", "7"), ("Persistent", "10"), ("Priority", "10"), ("Encrypted Value", "80")])
        for creation_utc, host_key, name, value, path, expires_utc, secure, httponly, last_access_utc, has_expires, persistent, priority, encrypted_value in data:
            self.table_row(outfd, str(creation_utc), host_key, name, value, path, str(expires_utc), secure, httponly, str(last_access_utc), has_expires, persistent, priority, encrypted_value)

    def render_csv(self, outfd, data):
        outfd.write('"creation_time","host_key","name","value","path","expires_time","secure","http_only","last_access_time","expires","persistent","priority","encrypted_value"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)

    def render_body(self, outfd, data):
        for creation_utc, host_key, name, value, path, expires_utc, secure, httponly, last_access_utc, has_expires, persistent, priority, encrypted_value in data:
            create = sqlite_help.unix_time(creation_utc)
            access = sqlite_help.unix_time(last_access_utc)
            cookie = host_key + " " + path + " " + name + " = " + value
            cookie = cookie.replace("|", "-")
            d = (0, "[CHROMECOOKIES] " + cookie, 0, "---------------", 0, 0, 0, access, create, access, create)
            csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)



class ChromeVisits(common.AbstractWindowsCommand):
    """ Scans for and parses potential Chrome url visits data -- VERY SLOW, see -Q option"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('QUICK', short_option = 'Q', default = False,
                          help = "Don't correlate Visits table with History table (faster)",
                          action = "store_true")

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        scanner = ChromeScanner(needles = ['\x08\x00\x01\x06',
                                           '\x08\x00\x02\x06',
                                           '\x08\x00\x03\x06',
                                           '\x09\x00\x01\x06',
                                           '\x09\x00\x02\x06',
                                           '\x09\x00\x03\x06',
                                          ])

        history = {}
        if not self._config.QUICK:
            for h in ChromeHistory(self._config,).calculate():
                if history.get(h[0], 0) == 0 or h[5].year > 1601:
                    history[h[0]] = h[1:]

        visits = {}
        #print "Scanning for Chrome files, this can take a while............."
        for offset in scanner.scan(address_space):
            chrome_buff = address_space.read(offset-13, 150)

            # sanity checks on a few other values
            if ord(chrome_buff[17]) not in (1, 2, 3):
                continue;
            if ord(chrome_buff[18]) not in (4, 5):
                continue;
            if ord(chrome_buff[19]) not in (1, 2, 3):
                continue;

            # get the bytes around the needles, then work backwards
            payload_header_length = ord(chrome_buff[13])
            (visit_id_length, visit_id) = sqlite_help.varint_type_to_length(ord(chrome_buff[14]))
            (url_length, url) = sqlite_help.varint_type_to_length(ord(chrome_buff[15]))

            # row_id is before the payload_header_length
            start = 12
            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            # can't have a negative row_id (index)
            if row_id < 0:
                continue

            # payload_length is length of sqlite record and the first item
            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

            # payload_length should be much longer than this, but this is a safe minimum
            if payload_length < 6:
                continue

            # get the remaining needle match and the next few single byte values
            (visit_time_length, visit_time) = sqlite_help.varint_type_to_length(ord(chrome_buff[16]))
            (from_visit_length, from_visit) = sqlite_help.varint_type_to_length(ord(chrome_buff[17]))
            (transition_length, transition) = sqlite_help.varint_type_to_length(ord(chrome_buff[18]))
            (segment_id_length, segment_id) = sqlite_help.varint_type_to_length(ord(chrome_buff[19]))

            # older versions of chrome don't have the is_indexed field
            if payload_header_length == 9:
                (is_indexed_length, is_indexed) = sqlite_help.varint_type_to_length(ord(chrome_buff[20]))
                (visit_duration_length, visit_duration) = sqlite_help.varint_type_to_length(ord(chrome_buff[21]))
                start = 22
            elif payload_header_length == 8:
                (visit_duration_length, visit_duration) = sqlite_help.varint_type_to_length(ord(chrome_buff[20]))
                start = 21
            else:
                continue
            
            # visit_id INTEGER
            visit_id = sqlite_help.sql_unpack(chrome_buff[start:start+visit_id_length])

            # url INTEGER (an id into the urls table)
            start += visit_id_length
            url = sqlite_help.sql_unpack(chrome_buff[start:start+url_length])

            # visit_time INTEGER
            start += url_length
            visit_time = sqlite_help.sql_unpack(chrome_buff[start:start+visit_time_length])
            visit_time = sqlite_help.get_wintime_from_msec(visit_time)
            if visit_time.year == 1601:
                continue

            # from_visit INTEGER
            start += visit_time_length
            from_visit = sqlite_help.sql_unpack(chrome_buff[start:start+from_visit_length])

            # transition INTEGER
            start += from_visit_length
            transition = sqlite_help.sql_unpack(chrome_buff[start:start+transition_length])

            # segment_id INTEGER
            start += transition_length
            segment_id = sqlite_help.sql_unpack(chrome_buff[start:start+segment_id_length])

            # is_index INTEGER
            start += segment_id_length
            if payload_header_length == 9:
                is_indexed = sqlite_help.sql_unpack(chrome_buff[start:start+is_indexed_length])

                # visit_duration INTEGER
                start += is_indexed_length
            if visit_duration_length:
                visit_duration = sqlite_help.sql_unpack(chrome_buff[start:start+visit_duration_length])

            # store all the fields as a tuple to eliminate printing duplicates
            if payload_header_length == 9:
                visit_tuple = (row_id, url, visit_time, from_visit, map_transition(transition), segment_id, is_indexed, visit_duration)
            else:
                visit_tuple = (row_id, url, visit_time, from_visit, map_transition(transition), segment_id, "n/a", visit_duration)
            if not visits.get(visit_tuple):
                yield visit_tuple, history.get(url,"")
                visits[visit_tuple] = visits.get(visit_tuple, 0) + 1

    def render_text(self, outfd, data):
        if self._config.QUICK:
            self.table_header(outfd, [("Visit ID", "8"), ("URL ID", "6"), ("Visit Time", "26"), ("From Visit", "10"), ("Transition", "60"), ("Segment ID", "10"), ("Is Indexed", "10"), ("Visit Duration", "13")])
        else:
            self.table_header(outfd, [("Visit ID", "8"), ("URL ID", "6"), ("Visit Time", "26"), ("From Visit", "10"), ("Transition", "60"), ("Segment ID", "10"), ("Is Indexed", "10"), ("Visit Duration", "13"), ("URL", "80"), ("Title", "80"), ("Visits", "6"), ("Typed", "5"), ("Last Visit Time", "26"), ("Hidden", "6"), ("Favicon ID", "10")])

        # the length of the two tuples will be 15 if the history records were searched as well
        # the length will be 8 if the QUICK option was used
        for v_data, h_data in data:
            if len(v_data) + len(h_data) == 15:
                (visit_id, url_id, visit_time, from_visit, transition, segment_id, is_indexed, visit_duration) = v_data
                (url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id) = h_data
                self.table_row(outfd, visit_id, url_id, str(visit_time), from_visit, transition, segment_id, is_indexed, visit_duration, url, title, visit_count, typed_count, str(last_visit_time), hidden, favicon_id)
            elif len(v_data) + len(h_data) == 8:
                (visit_id, url_id, visit_time, from_visit, transition, segment_id, is_indexed, visit_duration) = v_data
                self.table_row(outfd, visit_id, url_id, str(visit_time), from_visit, transition, segment_id, is_indexed, visit_duration)

    def render_csv(self, outfd, data):
        if self._config.QUICK:
            outfd.write('"id","url_id","visit_time","from_visit","transition","segment_id","is_indexed","visit_duration"\n')
        else:
            outfd.write('"id","url_id","visit_time","from_visit","transition","segment_id","is_indexed","visit_duration","url","title","visits","typed","last_visit_time","hidden","favicon_id"\n')
        for h_d, v_d in data:
            if len(v_d) == 7:
                csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(h_d + v_d)
            else:
                csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(h_d)

    def render_body(self, outfd, data):
        for v_data, h_data in data:
            if len(v_data) + len(h_data) == 15:
                (visit_id, url_id, visit_time, from_visit, transition, segment_id, is_indexed, visit_duration) = v_data
                (url, title, visit_count, typed_count, last_visit_time, hidden, favicon_id) = h_data
                visit_t = sqlite_help.unix_time(visit_time)
                last_visit = sqlite_help.unix_time(last_visit_time)
                if last_visit < 0:
                    last_visit = 0
                visit = url + " -- " + title + " -- " + transition
                visit = visit.replace("|", "-")
                d = (0, "[CHROMEVISITS] " + visit, 0, "---------------", 0, 0, 0, last_visit, 0, 0, visit_t)
                csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)
            elif len(v_data) + len(h_data) == 8:
                (visit_id, url_id, visit_time, from_visit, transition, segment_id, is_indexed, visit_duration) = v_data
                visit_t = sqlite_help.unix_time(visit_time)
                visit = str(url_id) + " -- " + transition
                visit = visit.replace("|", "-")
                d = (0, "[CHROMEVISITS] " + visit, 0, "---------------", 0, 0, 0, 0, 0, 0, visit_t)
                csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)
