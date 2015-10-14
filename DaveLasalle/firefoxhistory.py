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

import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import binascii
import sqlite_help
import csv
from datetime import datetime

FORWARD = sqlite_help.FORWARD
BACKWARD = sqlite_help.BACKWARD

class FirefoxScanner(scan.BaseScanner):
    checks = [ ] 

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset



class FirefoxDownloads(common.AbstractWindowsCommand):
    """ Scans for and parses potential Firefox download records -- downloads.sqlite moz_downloads table pre FF26 only"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        # definite values in Downloads records
        scanner = FirefoxScanner(needles = ['\x06\x06\x08',
                                            '\x06\x06\x09',
                                          ])
        downloads = {}
        for offset in scanner.scan(address_space):
            ff_buff = address_space.read(offset-16, 3000)
            start = 16

            good = False

            start -= 1
            (tempPath_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            tempPath_length = sqlite_help.varint_to_text_length(tempPath_length)

            # work backward from the start of the needle to the first field payload_length
            start -= varint_len
            (target_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            target_length = sqlite_help.varint_to_text_length(target_length)

            start -= varint_len
            (source_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            source_length = sqlite_help.varint_to_text_length(source_length)

            start -= varint_len
            (name_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            name_length = sqlite_help.varint_to_text_length(name_length)

            start -= varint_len
            (id_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (payload_header_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (row_id, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (payload_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            # jump back to the needle, startTime_length
            start = 16

            # get all of the single byte lengths around the needle
            (startTime_length, startTime) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
            (endTime_length, endTime) = sqlite_help.varint_type_to_length(ord(ff_buff[start+1]))
            (state_length, state) = sqlite_help.varint_type_to_length(ord(ff_buff[start+2]))

            # get the rest of the fields in the row moving forward
            start = 19
            (referrer_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            referrer_length = sqlite_help.varint_to_text_length(referrer_length)
            start += varint_len

            (entityID_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            entityID_length = sqlite_help.varint_to_text_length(entityID_length)
            start += varint_len

            (currBytes_length, currBytes) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
            (maxBytes_length, maxBytes) = sqlite_help.varint_type_to_length(ord(ff_buff[start+1]))

            start += 2

            (mimeType_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            mimeType_length = sqlite_help.varint_to_text_length(mimeType_length)
            start += varint_len

            (preferredApplication_length, varint_len) = sqlite_help.find_varint(ff_buff, start, FORWARD)
            preferredApplication_length = sqlite_help.varint_to_text_length(preferredApplication_length)
            start += varint_len

            (preferredAction_length, preferredAction) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
            (autoResume_length, autoResume) = sqlite_help.varint_type_to_length(ord(ff_buff[start+1]))

            start += 2
            
            name = ff_buff[start:start+name_length]
            start += name_length

            source = ff_buff[start:start+source_length]
            start += source_length

            target = ff_buff[start:start+target_length]
            start += target_length

            tempPath = ff_buff[start:start+tempPath_length]
            start += tempPath_length

            # do some checks on the startTime/endTime to make sure they are valid
            startTime = ff_buff[start:start+startTime_length]
            startTime = sqlite_help.sql_unpack(startTime)
            if startTime > 0 and startTime:
                startTime = sqlite_help.get_nixtime_from_msec(startTime)
            if type(startTime) is not datetime:
                continue
            start += startTime_length

            endTime = ff_buff[start:start+endTime_length]
            endTime = sqlite_help.sql_unpack(endTime)
            if endTime > 0 and startTime:
                endTime = sqlite_help.get_nixtime_from_msec(endTime)
            if type(endTime) is not datetime:
                continue
            start += endTime_length

            # if both dates are 1970, it's probably a bad record and not very useful, so skip
            # if only 1 is 1970, print it because it may be an old record with one valid date
            if startTime.year == 1970 and endTime.year == 1970:
                continue

            if state_length > 0:
                state = sqlite_help.sql_unpack(ff_buff[start:start+state_length])
            start += state_length

            referrer = ff_buff[start:start+referrer_length]
            start += referrer_length

            entityID = ff_buff[start:start+entityID_length]
            start += entityID_length

            currBytes = ff_buff[start:start+currBytes_length]
            currBytes = sqlite_help.sql_unpack(currBytes)
            # skip if negative or greater than 1TB
            if currBytes < 0 or currBytes > 1000000000000:
                continue
            start += currBytes_length

            maxBytes = ff_buff[start:start+maxBytes_length]
            maxBytes = sqlite_help.sql_unpack(maxBytes)
            # skip if negative or greater than 1TB
            if maxBytes < 0 or maxBytes > 1000000000000:
                continue
            start += maxBytes_length

            mimeType = ff_buff[start:start+mimeType_length]
            start += mimeType_length

            preferredApplication = ff_buff[start:start+preferredApplication_length]
            start += preferredApplication_length

            # these fields can have a value 0x8 or 0x9 in the length field
            # in that case, the "data" portion is not there, and the value is impled 
            # to be 0 or 1, respectively
            if preferredAction_length > 0:
                preferredAction = ff_buff[start:start+preferredAction_length]
                preferredAction = sqlite_help.sql_unpack(preferredAction)
            start += preferredAction_length
                
            if autoResume_length > 0:
                autoResume = ff_buff[start:start+autoResume_length]
                autoResume = sqlite_help.sql_unpack(autoResume)
            start += autoResume_length

            # add all the fields to a tuple so we only print a unique record once
            downloads_tuple = (row_id, name, source, target, tempPath, startTime, endTime, state, referrer, entityID, currBytes, maxBytes, mimeType, preferredApplication, preferredAction, autoResume)
            if not downloads.get(downloads_tuple):
                downloads[downloads_tuple] = downloads.get(downloads_tuple, 0) + 1
                yield downloads_tuple

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Row Id", "6"), ("Name", "32"), ("Source", "80"), ("Target", "60"), ("Temp Path", "32"), ("Start Time", "26"), ("End Time", "26"), ("State", "5"), ("Referrer", "60"), ("Entity ID", "9"), ("Current Bytes", "12"), ("Max Bytes", "12"), ("MIME Type", "20"), ("Prefer App", "16"), ("Prefer Action", "13"), ("Auto Resume", "11")])
        for row_id, name, source, target, tempPath, startTime, endTime, state, referrer, entityID, currBytes, maxBytes, mimeType, preferredApplication, preferredAction, autoResume in data:
            self.table_row(outfd, row_id, name, source, target, tempPath, str(startTime), str(endTime), state, referrer, entityID, currBytes, maxBytes, mimeType, preferredApplication, preferredAction, autoResume)

    def render_csv(self, outfd, data):
        outfd.write('"id","name","source","target","temp_path","start_time","end_time","state","referrer","entity_id","current_bytes","max_bytes","mime_type","prefer_app","prefer_action","auto_resume"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)

    def render_body(self, outfd, data):
        for row_id, name, source, target, tempPath, startTime, endTime, state, referrer, entityID, currBytes, maxBytes, mimeType, preferredApplication, preferredAction, autoResume in data:
            start = sqlite_help.unix_time(startTime)
            end = sqlite_help.unix_time(endTime)
            download = source + " -> " + target + " (" + str(maxBytes) + " bytes)"
            download = download.replace("|", "-")
            d = (0, "[FIREFOXDOWNLOADS] " + download, 0, "---------------", 0, 0, 0, 0, end, 0, start)
            csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)



class FirefoxCookies(common.AbstractWindowsCommand):
    """ Scans for and parses potential Firefox cookies (cookies.sqlite moz_cookies table"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        # definite values in Cookie records
        scanner = FirefoxScanner(needles = ['\x04\x06\x06\x08',
                                            '\x04\x06\x06\x09',
                                            '\x05\x06\x06\x08',
                                            '\x05\x06\x06\x09',
                                          ])
        cookies = {}
        for offset in scanner.scan(address_space):
            ff_buff = address_space.read(offset-16, 4200)
            start = 16
            if (ord(ff_buff[start+4]) in (8,9)):
                good = False
            
                # start before the needle match and work backwards to the first record payload length
                start -= 1
                (path_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
                path_length = sqlite_help.varint_to_text_length(path_length)

                start -= varint_len
                (host_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
                host_length = sqlite_help.varint_to_text_length(host_length)

                start -= varint_len
                (value_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
                value_length = sqlite_help.varint_to_text_length(value_length)

                start -= varint_len
                (name_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
                name_length = sqlite_help.varint_to_text_length(name_length)
                start -= varint_len

                # newer versions add appId and inBrowserElement, they are INTEGER type 
                # so if they exist, they will both have length values less than 12
                inBrowserElement_length = 0
                inBrowserElement = "n/a"
                appId_length = 0
                appId = "n/a"
                # if they don't exist, the previous value is a var int and could be something
                # like 0x81 0x10, so wee need to check both bytes
                if 0 < ord(ff_buff[start]) < 12 and 0 < ord(ff_buff[start-1]) < 12:
                    (inBrowserElement_length, inBrowserElement) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
                    (appId_length, appId) = sqlite_help.varint_type_to_length(ord(ff_buff[start-1]))
                    start -= 2

                (baseDomain_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
                baseDomain_length = sqlite_help.varint_to_text_length(baseDomain_length)

                start -= varint_len
                (cookie_id_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

                start -= varint_len
                (payload_header_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

                start -= varint_len
                (row_id, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

                start -= varint_len
                (payload_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

                # start of record reached, so jump back to the needle, then work forward
                start = 16

                (expiry_length, expiry) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
                (lastAccessed_length, lastAccessed) = sqlite_help.varint_type_to_length(ord(ff_buff[start+1]))
                (creationTime_length, creationTime) = sqlite_help.varint_type_to_length(ord(ff_buff[start+2]))
                (isSecure_length, isSecure) = sqlite_help.varint_type_to_length(ord(ff_buff[start+3]))
                (isHttpOnly_length, isHttpOnly) = sqlite_help.varint_type_to_length(ord(ff_buff[start+4]))

                start += 5

                cookie_id = ff_buff[start:start+cookie_id_length]
                cookie_id = sqlite_help.sql_unpack(cookie_id)

                baseDomain = ff_buff[start:start+baseDomain_length]
                start += baseDomain_length

                # if the length is > 0, it will need to be set
                # if it == 0, it was already set in the call earlier
                # otherwise, the value should be "n/a" from initialization because it's an older version
                if inBrowserElement_length > 0:
                    inBrowserElement = ff_buff[start:start+inBrowserElement_length]
                    inBrowserElement = sqlite_help.sql_unpack(inBrowserElement)
                start += inBrowserElement_length
                    
                if appId_length > 0:
                    appID = ff_buff[start:start+appId_length]
                    appId = sqlite_help.sql_unpack(appId)
                start += appId_length

                name = ff_buff[start:start+name_length]
                start += name_length

                value = ff_buff[start:start+value_length]
                start += value_length

                host = ff_buff[start:start+host_length]
                start += host_length

                path = ff_buff[start:start+path_length]
                start += path_length

                # get the 3 time fields and do a check that a valid date is returned
                expiry = ff_buff[start:start+expiry_length]
                expiry = sqlite_help.sql_unpack(expiry)
                if expiry > 0 and expiry:
                    expiry = sqlite_help.get_nixtime_from_sec(expiry)
                if type(expiry) is not datetime:
                    continue
                start += expiry_length

                lastAccessed = ff_buff[start:start+lastAccessed_length]
                lastAccessed = sqlite_help.sql_unpack(lastAccessed)
                if lastAccessed > 0 and lastAccessed:
                    lastAccessed = sqlite_help.get_nixtime_from_msec(lastAccessed)
                if type(lastAccessed) is not datetime:
                    continue
                start += lastAccessed_length

                creationTime = ff_buff[start:start+creationTime_length]
                creationTime = sqlite_help.sql_unpack(creationTime)
                if creationTime > 0 and creationTime:
                    creationTime = sqlite_help.get_nixtime_from_msec(creationTime)
                if type(creationTime) is not datetime:
                    continue
                start += creationTime_length

                # if all 3 dates are 1970, it's likely a garbage record, so skip
                # if any of them are real dates, it could be an old or partially overwritten record, so print
                if expiry.year == 1970 and lastAccessed.year == 1970 and creationTime.year ==1970:
                    continue

                if isSecure_length > 0:
                    isSecure = ff_buff[start:start+isSecure_length]
                    isSecure = sqlite_help.sql_unpack(isSecure)
                start += isSecure_length
                
                if isHttpOnly_length > 0:
                    isHttpOnly = ff_buff[start:start+isHttpOnly_length]
                    isHttpOnly = sqlite_help.sql_unpack(isHttpOnly)
                start += isHttpOnly_length
                    
                # add all fields to the tuple so we only print unique records once
                cookie_tuple = (row_id, baseDomain, appId, inBrowserElement, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly)
                if not cookies.get(cookie_tuple):
                    cookies[cookie_tuple] = cookies.get(cookie_tuple, 0) + 1
                    yield cookie_tuple

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Row ID", "6"), ("Base Domain", "28"), ("App Id","6"), ("InBrowserElement", "16"), ("Name", "24"), ("Value", "32"), ("Host", "32"), ("Path", "32"), ("Expiry", "20"), ("Last Accessed", "26"), ("Creation Time", "26"), ("Secure", "6"), ("HttpOnly", "6")])
        for row_id, baseDomain, appId, inBrowserElement, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly in data:
            self.table_row(outfd, row_id, baseDomain, appId, inBrowserElement, name, value, host, path, str(expiry), str(lastAccessed), str(creationTime), isSecure, isHttpOnly)

    def render_csv(self, outfd, data):
        outfd.write('"id","base_domain","app_id","inbrowserelement","name","value","host","path","expiry","last_accessed","creation_time","secure","httponly"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)

    def render_body(self, outfd, data):
        for row_id, baseDomain, appId, inBrowserElement, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly in data:
            start = sqlite_help.unix_time(creationTime)
            end = sqlite_help.unix_time(lastAccessed)
            cookie = host + " " + path + " " + name + " = " + value
            cookie = cookie.replace("|", "-")
            d = (0, "[FIREFOXCOOKIES] " + cookie, 0, "---------------", 0, 0, 0, 0, end, 0, start)
            csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)



class FirefoxHistory(common.AbstractWindowsCommand):
    """ Scans for and parses potential Firefox url history (places.sqlite moz_places table)"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        # definite values in History records
        scanner = FirefoxScanner(needles = ['\x06\x25',
                                            '\x00\x25',
                                           ])
        urls = {}
        for offset in scanner.scan(address_space):
            ff_buff = address_space.read(offset-21, 3000)
            start = 21

            # start before the needle match and work backwards
            if ord(ff_buff[start-1]) in (1, 2, 8, 9):
                start -= 1
                (frecency_length, frecency) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
            else:
                continue

            if ord(ff_buff[start-1]) in (0, 1, 8, 9):
                start -= 1
                (favicon_id_length, favicon_id) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
            else:
                continue

            if ord(ff_buff[start-1]) not in (8, 9):
                continue
            start -= 1
            (typed_length, typed) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))

            if ord(ff_buff[start-1]) not in (8, 9):
                continue
            start -= 1
            (hidden_length, hidden) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))

            if ord(ff_buff[start-1]) in (1, 8, 9):
                start -= 1
                (visit_count_length, visit_count) = sqlite_help.varint_type_to_length(ord(ff_buff[start]))
            else:
                continue

            start -= 1
            (rev_host_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            rev_host_length = sqlite_help.varint_to_text_length(rev_host_length)

            start -= varint_len
            (title_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            title_length = sqlite_help.varint_to_text_length(title_length)
            
            start -= varint_len
            (url_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            url_length = sqlite_help.varint_to_text_length(url_length)
            
            start -= varint_len
            url_id_length = ord(ff_buff[start])

            start -= 1
            payload_header_length = ord(ff_buff[start])

            start -= 1
            (row_id, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)
            # can't have a negative row_id (index)
            if row_id < 0:
                continue

            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = sqlite_help.find_varint(ff_buff, start, BACKWARD)

            # payload_length should be much longer than this, but this is a safe minimum
            if payload_length < 6:
                continue

            # go back to the needle match and start processing forward
            (last_visit_date_length, last_visit_date) = sqlite_help.varint_type_to_length(ord(ff_buff[21]))
            (guid_length, varint_len) = sqlite_help.find_varint(ff_buff, 22, FORWARD)
            guid_length = sqlite_help.varint_to_text_length(guid_length)
            start = 22 + varint_len

            url_id = sqlite_help.sql_unpack(ff_buff[start:start+url_id_length])

            start += url_id_length
            url = ff_buff[start:start+url_length]

            start += url_length
            title = ff_buff[start:start+title_length]

            start += title_length
            rev_host = ff_buff[start:start+rev_host_length]

            start += rev_host_length
            if visit_count_length > 0:
                visit_count = sqlite_help.sql_unpack(ff_buff[start:start+visit_count_length])

            start += visit_count_length
            if hidden_length > 0:
                hidden = sqlite_help.sql_unpack(ff_buff[start:start+hidden_length])

            start += hidden_length
            if typed_length > 0:
                typed = sqlite_help.sql_unpack(ff_buff[start:start+typed_length])

            start += typed_length
            favicon_id = ""
            if favicon_id_length > 0:
                favicon_id = sqlite_help.sql_unpack(ff_buff[start:start+favicon_id_length])

            start += favicon_id_length
            if frecency_length > 0:
                frecency = sqlite_help.sql_unpack(ff_buff[start:start+frecency_length])

            # extract the time, unpack it to an integer, convert microseconds to string
            start += frecency_length
            last_visit_date = ff_buff[start:start+last_visit_date_length]
            last_visit_date = sqlite_help.sql_unpack(last_visit_date)
            if last_visit_date_length == 8 and last_visit_date < 0:
                continue
            if last_visit_date > 1 and last_visit_date:
                last_visit_date = sqlite_help.get_nixtime_from_msec(last_visit_date)
            if last_visit_date_length == 8 and type(last_visit_date) is datetime and last_visit_date.year == 1970:
                continue

            start += last_visit_date_length
            guid = ff_buff[start:start+guid_length]

            start += guid_length

            # save the values as a tuple in a dictionary so we only print one unique row
            url_tuple = (row_id, url, title, rev_host, visit_count, hidden, typed, favicon_id, frecency, last_visit_date, guid) 
            if not urls.get(url_tuple):
                urls[url_tuple] = urls.get(url_tuple, 0) + 1
                yield url_tuple

    def render_text(self, outfd, data):
        self.table_header(outfd, [("ID", "6"), ("URL", "80"), ("Title", "80"), ("Rev Host", "32"), ("Visits", "6"), ("Hidden", "6"), ("Typed", "5"), ("Favicon ID", "10"), ("Frecency", "8"), ("Last Visit Date", "26"), ("GUID", "12")])
        for row_id, url, title, rev_host, visit_count, hidden, typed, favicon_id, frecency, last_visit_date, guid in data:
            self.table_row(outfd, row_id, url, title, rev_host, visit_count, hidden, typed, favicon_id, frecency, str(last_visit_date), guid)

    def render_csv(self, outfd, data):
        outfd.write('"id","url","title","rev_host","visit_count","hidden","typed","favicon_id","frecency","last_visit_date","guid"\n')
        for d in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(d)

    def render_body(self, outfd, data):
        for row_id, url, title, rev_host, visit_count, hidden, typed, favicon_id, frecency, last_visit_date, guid in data:
            if type(last_visit_date) is str:
                end = 0
            else:
                end = sqlite_help.unix_time(last_visit_date)
            history = url + " -- " + title
            history = history.replace("|", "-")
            d = (0, "[FIREFOXHISTORY] " + history, 0, "---------------", 0, 0, 0, 0, end, 0, 0)
            csv.writer(outfd,delimiter="|",quoting=csv.QUOTE_NONE,escapechar="\\").writerow(d)
