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
# Helper functions for working with a SQLite database

import struct
import datetime
import math

FORWARD = 1
BACKWARD = -1

def unix_time(dt):
    epoch = datetime.datetime.utcfromtimestamp(0)
    delta = dt - epoch
    return int(delta.total_seconds())

def get_wintime_from_msec(msec):
    """ Convert windows epoch time in microseconds to a date string """
    seconds, msec= divmod(msec, 1000000)
    days, seconds = divmod(seconds, 86400)
    if days > 160000 or days < 140000:
        days = 0
        seconds = 0
        msec = 0
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds, msec)

def get_nixtime_from_sec(sec):
    """ Convert unix epoch time in seconds to a date string """
    return get_nixtime_from_msec(sec*1000000)

def get_nixtime_from_msec(msec):
    """ Convert unix epoch time in microseconds to a date string """
    seconds, msec= divmod(msec, 1000000)
    days, seconds = divmod(seconds, 86400)
    if days > 20000 or days < 9000:
        days = 0
        seconds = 0
        msec = 0
    return datetime.datetime(1970, 1, 1) + datetime.timedelta(days, seconds, msec)

def varint_type_to_length(varint):
    """ Return the number of bytes used by a varint type """
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

def ones_comp(bin_str):
    """ Return the ones complement of a string of 0s and 1s """
    output = ""
    for i in bin_str:
        if i == '0':
            output += '1'
        if i == '1':
            output += '0'
    return output

def find_varint(buff, start, direct):
    """ varint are 1-9 bytes, big-endian.  The most sig bit is not used, which is why 128 is subtracted
    in the for loops below.
    See: http://www.evolane.com/support/manuals/shared/manuals/tcltk/sqlite/fileformat.html#varint_format"""
    buff_len = len(buff)
    varint_len = 1
    varint_buff = ""
    begin = 0
    # at start index and going backwards, so only 1 byte available
    if direct == BACKWARD and start == 0:
        begin = 0
    # going backwards
    elif direct == BACKWARD:
        # set stopping point, lowest possible is start of the buffer
        if start >= 9:
            stop = start - 9
        else:
            stop = 0
        for i in range(start, stop, direct):
            if ord(buff[i-1]) < 128:
                break
            if i > stop + 1:
                varint_len += 1
        begin = start - varint_len + 1
    # going forwards
    else:
        # set a stopping point, maximum length of 9 bytes
        if start + 9 > buff_len:
            stop = buff_len
        else:
            stop = start + 9
        begin = start
        for i in range(start, stop, direct):
            if ord(buff[i]) < 128:
                break
            if i < stop-1:
                varint_len += 1
    # num_buff contains the varint that was extracted
    num_buff = buff[begin:begin+varint_len]

    if num_buff == "":
        return (-1, 0)
    return (varint_to_int(num_buff), varint_len)

def varint_to_int(buff):
    """ convert a varint to an integer """

    bin_str = ""
    varint_len = len(buff)
    # convert each byte to a binary string, keeping 7 bytes, unless the buffer is 9 bytes and
    # and we are grabbing the last byte, then keep all 8
    for i in range(0,varint_len):
        if i == 8 and varint_len == 9:
            bin_str += bin(ord(buff[i]))[2:].zfill(8)
        else:
            bin_str += bin(ord(buff[i]))[2:].zfill(8)[1:]

    if len(bin_str) == 64 and bin_str[0] == '1':
        # negative numbers use all 64 bits and will start with a 1.
        # take the ones complement, add 1, then put a negative sign in front
        sub_bin_str = ones_comp(bin_str)
        value = -(int(sub_bin_str, 2) + 1)
    else:
        value = int(bin_str, 2)

    return value

def varint_to_blob_length(l):
    """ Blob field lengths are doubled and 12 is added so that they are even and at least 12 """
    if l == 0:
        return 0
    else:
        return (l - 12) / 2

def varint_to_text_length(l):
    """ Text field lengths are doubled and 13 is added so that they are odd and at least 13 """
    if l == 0:
        return 0
    else:
        return (l - 13) / 2

def sql_unpack(buff):
    """ Convert SQL integer bytes into decimal integer """
    size = len(buff)
    value = ""
    if size == 1:
        value = struct.unpack(">b", buff)[0]
    elif size == 2:
        value = struct.unpack(">h", buff)[0]
    elif size == 3:
        tmp = "\x00" + buff
        value = struct.unpack(">l", tmp)[0]
    elif size == 4:
        value = struct.unpack(">l", buff)[0]
    elif size == 6:
        tmp = "\x00\x00" + buff
        value = struct.unpack(">q", tmp)[0]
    elif size == 8:
        value = struct.unpack(">q", buff)[0]
    return value

