# Copyright (C) 2014 Ngo Quoc Dat (@datquoc93) <datquoc93@gmail.com>
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
@author:       Ngo Quoc Dat (@datquoc93)
@license:      GNU General Public License 2.0 or later
@contact:      datquoc93@gmail.com
"""

import volatility.plugins.linux.common as linux_common
import volatility.utils as utils
import volatility.scan as scan
import csv
import struct
import datetime
import math


class TimeConvert():
	""" 
		Convert time from miniseconds or second to datetime format 
			Since 01/01/1970 
			Readmore in: http://www.forensicswiki.org/wiki/Mozilla_Firefox
	"""
	def get_time_from_sec(self, sec):
		return self.get_time_from_msec(sec*1000000)

	def get_time_from_msec(self, msec):
		seconds, msec= divmod(msec, 1000000)
		days, seconds = divmod(seconds, 86400)
		if days > 20000 or days < 9000:
			days = seconds = msec = 0
		return datetime.datetime(1970, 1, 1) + datetime.timedelta(days, seconds, msec)

class SQLite_parse():
	"""
		Finding length of varint and 
	convert varint to length of each field
	"""
	def stc_to_length(self, varint):
		"""	This is table Serial Type Codes Of The Record Format
			Readmore in https://www.sqlite.org/fileformat2.html
		"""
		if varint == 5:
			return (6, "")
		elif varint == 6 or varint == 7:
			return (8, "")
		elif varint == 8:
			return (0,0)
		elif varint == 9:
			return (0,1)
		else:
			return (varint, "")

	def find_varint(self, buff, start):
		""" 
			Finding varint using Most Significant Bit and 
			convert it to twos-complement integer
		"""
		varint_len = 1
		varint_buff = ""
		begin = 0
		if start == 0:
			begin = 0
		else:
			if start >= 9:
				stop = start - 9
			else:
				stop = 0
			for i in range(start, stop, -1):
				if ord(buff[i-1]) < 128:
					break
				if i > stop + 1:
					varint_len += 1
			begin = start - varint_len + 1
		num_buff = buff[begin:begin+varint_len]
		if num_buff == "":
       			return (-1, 0)
    	
		bin_str = ""
		for i in range(0,varint_len):
			if i == 8 and varint_len == 9:
				bin_str += bin(ord(num_buff[i]))[2:].zfill(8)
			else:
				bin_str += bin(ord(num_buff[i]))[2:].zfill(8)[1:]
		if len(bin_str) == 64 and bin_str[0] == '1':
			convert = ""
			for i in bin_str:
				if i == '0':
					convert += '1'
				if i == '1':
					convert += '0'
			value = -(int(convert, 2) + 1)
		else:
			value = int(bin_str, 2)
		return (value, varint_len)

	def varint_to_text_length(self, length):
		""" 
			Text field Length (N - 13)/2
		"""
		if length == 0:
			return 0
		else:
			return (length - 13) / 2

class HEXunpack():
	"""
		Convert array of hex value to integers
		Readmore in: https://docs.python.org/2/library/struct.html
	"""
	def unpack(self, buff):
		size = len(buff)
		value = ""
		if size == 1:
			value = struct.unpack(">B", buff)[0]
		elif size == 2:
			value = struct.unpack(">H", buff)[0]
		elif size == 3:
			buff = "\x00" + buff
			value = struct.unpack(">L", buff)[0]
		elif size == 4:
			value = struct.unpack(">L", buff)[0]
		elif size == 6:
			buff = "\x00\x00" + buff
			value = struct.unpack(">Q", buff)[0]
		elif size == 8:
			value = struct.unpack(">Q", buff)[0]
		return value

class FFScanMachine(scan.BaseScanner):
	"""
		Scan sign Using MultiStringFinderCheck with sign is needles
	"""
	checks = []
	def __init__(self, needles = None):
		self.needles = needles
		self.checks = [("MultiStringFinderCheck",{'needles':needles})]
		scan.BaseScanner.__init__(self)
	def scan(self, address_space, offset = 0, maxlen = None):
		for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
			yield offset 

class Linux_FFHis(linux_common.AbstractLinuxCommand):
	"""Listing History of FireFox Browser"""
	
	def __init__(self,config, *args, **kwargs):
		linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)	

	def calculate(self):
		address_space = utils.load_as(self._config, astype = 'physical')		
		row_avaiable = []	
		needles = ['\x06\x25\x08', '\x06\x25\x09', 
			'\x00\x25\x08', '\x00\x25\x09']	
		time_convert = TimeConvert()
		sqlite_parse = SQLite_parse()
		hex_unpack = HEXunpack()
		scanner = FFScanMachine(needles)
		
		for offset in scanner.scan(address_space):
			ff_buffer = address_space.read(offset-30,3000)
			ptr_fw = ptr_bw = 30
			# Forward from last_visit_date_length field to end of payload_header
			(last_visit_date_length, last_visit_date) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
           		
			ptr_fw += 1
			guid_length = hex_unpack.unpack(ff_buffer[ptr_fw])
    			guid_length = sqlite_parse.varint_to_text_length(guid_length)
			
			ptr_fw = ptr_fw + 1
			(foreign_count_length, foreign_count) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))

			# Backward from last_visit_date_length field to payload_length field
			if ord(ff_buffer[ptr_bw-1]) in (1, 2, 3, 4, 5, 6, 8, 9):
				ptr_bw -= 1
				(frecency_length, frecency) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_bw]))
			else:
				continue
		
			if ord(ff_buffer[ptr_bw-1]) in (0, 1, 2, 3, 4, 5, 6, 8, 9):
				ptr_bw -= 1
        			(favicon_id_length, favicon_id) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_bw]))
    			else:
        			continue
				
			if ord(ff_buffer[ptr_bw-1]) in (8, 9):
				ptr_bw -= 1
				(typed_length, typed) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_bw]))
			else:
				continue
		
			if ord(ff_buffer[ptr_bw-1]) in (8, 9):
				ptr_bw -= 1
				(hidden_length, hidden) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_bw]))
			else:
				continue

			if ord(ff_buffer[ptr_bw-1]) in (1, 2, 3, 4, 5, 6, 8, 9):
				ptr_bw -= 1
				(visit_count_length, visit_count) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_bw]))
			else:
				continue

			ptr_bw -= 1
    			(rev_host_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
   			rev_host_length = sqlite_parse.varint_to_text_length(rev_host_length)
		
    			ptr_bw -= varint_len
    			(title_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
    			title_length = sqlite_parse.varint_to_text_length(title_length)
    		
    			ptr_bw -= varint_len
    			(url_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
    			url_length = sqlite_parse.varint_to_text_length(url_length)
    	
    			ptr_bw -= varint_len
    			(url_id_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			
    			ptr_bw -= varint_len
    			(payload_header_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			
    			ptr_bw -= varint_len
    			(row_id, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			if row_id < 0:
				continue
			ptr_bw -= varint_len
			(payload_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			if payload_length <= 0:
        			continue
			
			# Extract content with length
			
			ptr_fw += 1
    			url = ff_buffer[ptr_fw:ptr_fw+url_length]
    			
			ptr_fw += url_length
    			title = ff_buffer[ptr_fw:ptr_fw+title_length]
			
			ptr_fw += title_length 
			rev_host = ff_buffer[ptr_fw:ptr_fw+rev_host_length]

 			ptr_fw += rev_host_length 
			visit_count = ff_buffer[ptr_fw:ptr_fw+visit_count_length]			
			visit_count = hex_unpack.unpack(visit_count)
			
			ptr_fw += visit_count_length + typed_length 
			favicon_id = ff_buffer[ptr_fw:ptr_fw+favicon_id_length]
			favicon_id = hex_unpack.unpack(favicon_id)
 			
			ptr_fw += favicon_id_length 
			frecency = ff_buffer[ptr_fw:ptr_fw+frecency_length]
			frecency = hex_unpack.unpack(frecency)
			
			ptr_fw += frecency_length
			last_visit_date = ff_buffer[ptr_fw:ptr_fw+last_visit_date_length]
    			last_visit_date = hex_unpack.unpack(last_visit_date)
			if last_visit_date > 1 and last_visit_date:
				last_visit_date = time_convert.get_time_from_msec(last_visit_date)

			ptr_fw += last_visit_date_length
			guid = ff_buffer[ptr_fw:ptr_fw+guid_length]

			# Make generator         			
			if row_id not in row_avaiable:
				row_avaiable.append(row_id)
				url_tuple = (row_id, url, title, rev_host, visit_count, hidden, typed, favicon_id,  frecency, str(last_visit_date), guid, foreign_count)				
				yield url_tuple
		
			
	def render_text(self,outfd,data):
		self.table_header(outfd, [("ID", "6"), ("URL", "80"), ("Title", "50"), ("Last Visit Date", "26")])
        	for row_id, url, title, rev_host, visit_count, hidden, typed, favicon_id,  frecency, last_visit_date, guid, foreign_count in data:
            		self.table_row(outfd, row_id, url, title, last_visit_date)

	def render_csv(self, outfd, data):
		c = csv.writer(open("/root/Desktop/URL-result.csv", "wb"))
		c.writerow(["RowID", "URL", "Title", "rev_host", "visit_count", "hidden", "typed", "favicon_id",  "frecency", "Last_visit_date", "guid", "foreign_count"])        	
		for d in data:
            		c.writerow(d)


class Linux_FFcookies(linux_common.AbstractLinuxCommand):
	"""Listing Cookies in Firefox"""
	
	def __init__(self,config, *args, **kwargs):
		linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)	

	def calculate(self):
		address_space = utils.load_as(self._config, astype = 'physical')		
		row_avaiable = []	
		needles = ['\x04\x06\x06','\x05\x06\x06']	
		time_convert = TimeConvert()
		sqlite_parse = SQLite_parse()
		hex_unpack = HEXunpack()
		scanner = FFScanMachine(needles)

		for offset in scanner.scan(address_space):
			ff_buffer = address_space.read(offset-30,3000)
			ptr_fw = ptr_bw = 30
			# Forward from ptr_fw to end of payload_header
			(expiry_length, typed) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
			ptr_fw += 1
			(lastAccessed_length, typed) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
			ptr_fw += 1
			(creationTime_length, typed) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))			
			ptr_fw += 1
			if ord(ff_buffer[ptr_fw]) in (8, 9):
				(isSecure_length, isSecure) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
			else:
				continue
			ptr_fw += 1
			if ord(ff_buffer[ptr_fw]) in (8, 9):
				(isHttpOnly_length, isHttpOnly) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
			else:
				continue
			ptr_fw += 1
			if ord(ff_buffer[ptr_fw]) in (8, 9):
				(appId_length, appId) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
			else:
				continue
			ptr_fw += 1
			if ord(ff_buffer[ptr_fw]) in (8, 9):
				(inBrowserElement_length, inBrowserElement) = sqlite_parse.stc_to_length(ord(ff_buffer[ptr_fw]))
			else:
				continue

			# Backward from last_visit_date_length field to payload_length field
			
			ptr_bw -= 1
			(path_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			path_length = sqlite_parse.varint_to_text_length(path_length)
						
								 
			ptr_bw -= varint_len
			(host_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			host_length = sqlite_parse.varint_to_text_length(host_length)
							 
			ptr_bw -= varint_len
			(value_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			value_length = sqlite_parse.varint_to_text_length(value_length)
							 
			ptr_bw -= varint_len
			(name_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			name_length = sqlite_parse.varint_to_text_length(name_length)

			ptr_bw -= varint_len
			(originAttributes_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			originAttributes_length = sqlite_parse.varint_to_text_length(originAttributes_length)

			ptr_bw -= varint_len
			(baseDomain_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			baseDomain_length = sqlite_parse.varint_to_text_length(baseDomain_length)

			ptr_bw -= varint_len
			(cookie_id_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
					
			ptr_bw -= varint_len
			(payload_header_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
							
			ptr_bw -= varint_len
            		(row_id, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			if row_id < 0:
                		continue

			ptr_bw -= varint_len
			(payload_length, varint_len) = sqlite_parse.find_varint(ff_buffer, ptr_bw)
			if payload_length <= 0:
                		continue
               						
			# Extract content with length			

			ptr_fw += 1 
			baseDomain = ff_buffer[ptr_fw:ptr_fw + baseDomain_length]

			ptr_fw += baseDomain_length 
			originAttributes = ff_buffer[ptr_fw:ptr_fw + originAttributes_length]
		
			ptr_fw += originAttributes_length
			name = ff_buffer[ptr_fw:ptr_fw + name_length]

			ptr_fw += name_length
			value = ff_buffer[ptr_fw:ptr_fw + value_length]

			ptr_fw += value_length
			host = ff_buffer[ptr_fw:ptr_fw + host_length]

			ptr_fw += host_length 
			path = ff_buffer[ptr_fw:ptr_fw + path_length]

			ptr_fw +=  path_length
			expiry = hex_unpack.unpack(ff_buffer[ptr_fw:ptr_fw + expiry_length])
			if expiry > 1 and expiry:
				expiry = time_convert.get_time_from_sec(expiry)

			ptr_fw += expiry_length
			lastAccessed = hex_unpack.unpack(ff_buffer[ptr_fw:ptr_fw + lastAccessed_length])
			if lastAccessed > 1 and lastAccessed:
				lastAccessed = time_convert.get_time_from_msec(lastAccessed)

			ptr_fw += lastAccessed_length
			creationTime = hex_unpack.unpack(ff_buffer[ptr_fw:ptr_fw + creationTime_length])
			if creationTime > 1 and creationTime:
				creationTime = time_convert.get_time_from_msec(creationTime)
						
			cookies_tuple = (row_id, baseDomain, originAttributes, name, value, host, path, str(expiry), str(lastAccessed), str(creationTime), isSecure_length, isHttpOnly, appId, inBrowserElement)
			if row_id not in row_avaiable:
				row_avaiable.append(row_id)				
				yield cookies_tuple 
							
			
	def render_text(self,outfd,data):
		self.table_header(outfd, [("ID", "6"), ("baseDomain", "20"), ("name", "10"), ("value", "16"),("path", "10"), ("host", "16"),("expiry", "26"),("lastAccessed", "26"),("creationTime", "26")])
        	for row_id, baseDomain, originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure_length, isHttpOnly, appId, inBrowserElement in data:
            		self.table_row(outfd, row_id, baseDomain, name, value, path, host, expiry, lastAccessed, creationTime)
	def render_csv(self, outfd, data):
        	c = csv.writer(open("/root/Desktop/Cookies-result.csv", "wb"))
		c.writerow(["ROW_ID", "baseDomain", "originAttributes", "name", "value", "host", "path", "expiry", "lastAccessed", "creationTime", "isSecure_length", "isHttpOnly", "appId", "inBrowserElement"])        	
		for d in data:
            		c.writerow(d)


