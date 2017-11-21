# Copyright (C) 2017 Alessandro De Vito (@_cube0x8)
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
@author: Alessandro De Vito (@_cube0x8)
@license: GNU General Public License 2.0 or later
"""

import volatility.obj as obj
import struct

chrome_vtypes = {
    'stringimpl': [12, {
        'm_refCount': [0, ['unsigned int']],
        'm_length': [4, ['unsigned int']],
        'm_hash': [8, ['BitField', dict(start_bit=0, end_bit=23, native_type="unsigned int")]],
        'm_isAtomic': [11, ['BitField', dict(start_bit=0, end_bit=0, native_type="unsigned int")]],
        'm_is8bit': [11, ['BitField', dict(start_bit=1, end_bit=1, native_type="unsigned int")]],
        'm_isStatic': [11, ['BitField', dict(start_bit=2, end_bit=2, native_type="unsigned int")]],
    }],
    'qualifiedstringimpl': [40, {
        'm_localName': [16, ['pointer', ['stringimpl']]],
    }],
    'local_dom_window': [384, {
        'm_document': [152, ['pointer', ['chrome_document']]],
    }],
    'ElementData': [0, {
    }],
    'ShareableElementData': [40, {
        'm_attribute': [32, ['Attribute']],
    }],
    'Attribute': [16, {
        "m_name": [0, ['pointer', ['qualifiedstringimpl']]],
        "m_value": [8, ['pointer', ['stringimpl']]],
    }],
    'DOMNode': [40, {
        'm_nodeFlags': [16, ['unsigned int']],
        'm_parentOrShadowHostNode': [24, ['pointer', ['ContainerNode']]],
        'm_treeScope': [32, ['pointer', ['TreeScope']]],
        'm_previous': [40, ['pointer', ['DOMNode']]],
        'm_next': [48, ['pointer', ['DOMNode']]],
    }],
    'ContainerNode': [56, {
        'Node': [0, ['DOMNode']],
        'm_firstChild': [64, ['pointer', ['DOMNode']]],
        'm_lastChild': [72, ['pointer', ['DOMNode']]],
    }],
    'Element': [72, {
        'Container': [0, ['ContainerNode']],
        'm_tagName': [80, ['pointer', ['stringimpl']]],
        'm_elementData': [88, ['pointer', ['ElementData']]]
    }],
    'TextNode': [48, {
        'Node': [0, ['DOMNode']],
        'm_data': [64, ['pointer', ['stringimpl']]]
    }],
    'HTMLElementForm': [200, {
        'Container': [0, ['ContainerNode']],
        'm_method': [96, ['unsigned int']],
        'm_action': [104, ['pointer', ['stringimpl']]],
        'm_listedElements': [152, ['pointer', ['VectorBufferBase']]]
    }],
    'VectorBufferBase': [24, {
        'm_buffer': [0, ['pointer', ['Pointer']]],
        'm_capacity': [8, ['unsigned int']],
        'm_size': [16, ['unsigned int']],
    }],
    'HTMLIframeElement': [328, {
        'Element': [0, ['Element']],
        'm_contentFrame': [112, ['pointer', ['LocalFrame']]],
        'm_URL': [152, ['pointer', ['stringimpl']]]
    }],
    'HTMLAnchorElement': [144, {
        'Element': [0, ['Element']],
    }],
    'LocalFrame': [464, {
        'm_domWindow': [56, ['pointer', ['local_dom_window']]],
    }],
    'chrome_document': [3064, {
        'm_nodeFlags': [16, ['unsigned int']],
        'm_domWindow': [488, ['pointer', ['local_dom_window']]],
        'm_url': [664, ['pointer', ['stringimpl']]],
        'm_documentElement': [1360, ['pointer', ['DOMNode']]],
        'm_title': [1568, ['pointer', ['stringimpl']]],
    }],
}


# https://docs.google.com/document/d/1kOCUlJdh2WJMJGDf-WoEQhmnjKLaOYRbiHz5TiGJl14/edit
def get_chrome_string(self, strimpl_offset):
    strimpl_object = obj.Object("stringimpl", vm=self.obj_vm, offset=strimpl_offset)
    string_length = strimpl_object.m_length
    if string_length > 0:
        raw_string = self.obj_vm.read(strimpl_offset + 12, string_length)
        return raw_string
    return None


def get_qualified_string(self, qstrimpl_offset):
    qstrimpl_object = obj.Object("qualifiedstringimpl", vm=self.obj_vm, offset=qstrimpl_offset)
    return get_chrome_string(self, qstrimpl_object.m_localName)


Document_nodeFlag = [struct.unpack("<I", "\x04\x14\x0e\x00")[0],  # 922628
                     struct.unpack("<I", "\x04\x14\x02\x00")[0],  # 136196
                     struct.unpack("<I", "\x05\x14\x82\x00")[0],  # 8524805
                     struct.unpack("<I", "\x05\x14\x80\x00")[0],  # 8393733
                     struct.unpack("<I", "\x05\x14\x00\x00")[0],  # 5125
                     ]

containerNodeFlags = [struct.unpack("<I", "\x1c\x16\x00\x00")[0],  # 5660
                      struct.unpack("<I", "\x1c\x14\x02\x00")[0],  # 136220, html
                      struct.unpack("<I", "\x1c\x14\x00\x00")[0],  # 5148
                      struct.unpack("<I", "\x1d\x14\x00\x00")[0],  # 5149, (form, iframe)
                      struct.unpack("<I", "\x1d\x16\x00\x00")[0],  # 5661
                      struct.unpack("<I", "\x1c\x14\x40\x00")[0],  # 4199452
                      struct.unpack("<I", "\x1d\x14\x82\x00")[0],  # 8524829, body
                      struct.unpack("<I", "\x1c\x15\x00\x00")[0],  # 5404, anchor
                      # da qui in giu meritano un oggetto personale
                      struct.unpack("<I", "\x1d\x34\x00\x00")[0],  # 13341, input, textarea
                      struct.unpack("<I", "\x1c\x34\x00\x00")[0],  # 13340, button
                      ]

formElements = [
]

otherFlags = [struct.unpack("<I", "\x02\x14\x00\x00")[0],  # text node,5122
              struct.unpack("<I", "\x00\x14\x00\x00")[0],  # comment,5120
              ]

HTMLFormControlElement = [struct.unpack("<I", "\x1c\x34\x00\x00")[0]]

LocalDOMWindow_offset = 488
DocumentSize = 3064
