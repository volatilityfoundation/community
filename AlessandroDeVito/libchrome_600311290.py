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
import time
import unicodedata, re

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
        'm_document': [168, ['pointer', ['chrome_document']]],
    }],
    'Data': [64, {
        'ref_count_': [0, ['signed int']],
        'key_string_': [8, ['pointer', ['stringimpl']]],
        'vector_': [16, ['pointer', ['Vector']]],
    }],
    'Vector': [None, {
        'first_entry': [0, ['pointer', ['void']]],
    }],
    'ElementData': [8, {
        'class_names_': [16, ['pointer', ['Data']]],
        'id_style_for_resolution': [24, ['pointer', ['stringimpl']]],
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
        'm_parentOrShadowHostNode': [24, ['pointer', ['Element']]],
        'm_treeScope': [32, ['pointer', ['TreeScope']]],
        'm_previous': [40, ['pointer', ['Element']]],
        'm_next': [48, ['pointer', ['Element']]],
    }],
    'ContainerNode': [56, {
        'Node': [0, ['DOMNode']],
        'm_firstChild': [64, ['pointer', ['Element']]],
        'm_lastChild': [72, ['pointer', ['Element']]],
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
        'Element': [0, ['Element']],
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
    'HTMLImageElement': [64, {
	    'Element': [0, ['Element']],
        'best_fit_image_url_': [160, ['pointer', ['stringimpl']]],
    }],
    'LocalFrame': [464, {
        'm_domWindow': [48, ['pointer', ['local_dom_window']]],
    }],
    'chrome_document': [3064, {
        'm_nodeFlags': [16, ['unsigned int']],
        'm_domWindow': [536, ['pointer', ['local_dom_window']]],
        'm_url': [696, ['pointer', ['stringimpl']]],
        'm_documentElement': [1392, ['pointer', ['DOMNode']]],
        'm_title': [1608, ['pointer', ['stringimpl']]],
    }],
    'WebContents': [None, {
        'controller_': [112, ['pointer', ['NavigationController']]],
        'contents_mime_type_': [800, ['basic_string']],
        'canonical_encoding_': [864, ['basic_string']],
        'last_time_activity_': [1376, ['TimeTick']],
        'last_hidden_time_': [1384, ['TimeTick']],
    }],
    'NavigationController': [8, {
        'entries_': [16, ['pointer', ['Vector']]],
    }],
    'NavigationEntry': [976, {
        'frame_tree_': [8, ['pointer', ['TreeNode']]],
        'unique_id_': [16, ['int']],
        'page_type_': [24, ['int']],
        'virtual_url_': [32, ['GURL']],
        'title_': [168, ['pointer', ['basic_string']]],
        'ssl_': [344, ['SSLStatus']],
        'transition_type_': [416, ['unsigned int']],
        'user_typed_url_': [424, ['GURL']],
        'restore_type_': [552, ['unsigned int']],
        'original_request_url_': [560, ['GURL']],
        'timestamp_': [696, ['long long']],
        'http_status_code_': [704, ['unsigned int']],
        'post_data_': [712, ['pointer', ['ResourceRequestBody']]],
        'extra_headers_': [728, ['pointer', ['basic_string']]],
        'reload_type_': [944, ['unsigned int']],
        'extra_data_': [952, ['pointer', ['basic_string']]],
        'ssl_error_': [968, ['unsigned int']],
    }],
    'FrameNavigationEntry': [None, {
        'frame_unique_name_': [16, ['pointer', ['basic_string']]],
        'item_sequence_number_': [48, ['long long']],
        'document_sequence_number_': [56, ['long long']],
        'url_': [80, ['GURL']],
        'referer_': [208, ['Referer']],
        'redirect_chain_': [344, ['Vector']],
        'page_state_': [368, ['PageState']],
        'method_': [400, ['basic_string']],
    }],
    'TreeNode': [None, {
        'parent_': [0, ['pointer', ['TreeNode']]],
        'frame_entry_': [8, ['pointer', ['FrameNavigationEntry']]],
        'children_': [16, ['pointer', ['Vector']]],
    }],
    'GURL': [128, {
        'spec_': [0, ['pointer', ['basic_string']]],
        'is_valid_': [32, ['unsigned int']],
        'parsed_': [40, ['void']],
        'inner_url_': [120, ['GURL']],
    }],
    'SSLStatus': [None, {
        #TODO
    }],
    'ResourceRequestBody': [None,{
        'elements_': [8, ['pointer', ['Vector']]], #vector of DataElement
    }],
    'basic_string': [8, {
        'char_buffer': [0, ['pointer', ['char']]],
    }],
    'Referer': [16, {
        'url_': [0, ['GURL']],
        'policy_': [8, ['unsigned int']],
    }],
    'PageState': [8, {
        'data_': [0, ["long long"]],
        'size_': [16, ["unsigned int"]],
    }],
    'CacheLinkedListEntry': [24, {
        '_Next': [0, ['pointer', ['CacheLinkedListEntry']]],
        '_Prev': [8, ['pointer', ['CacheLinkedListEntry']]],
        '_Myval': [16, ['CacheLinkedListValue']],
    }],
    'CacheLinkedListValue': [None, {
        'first': [0, ['pointer', ['char']]],
        'Stuff': [8, ['pointer', ['void']]],
        'size_': [16, ['unsigned int']],
        'second': [32, ['pointer', ['MemEntryImpl']]],
    }],
    'CharVector': [24, {
        'MyFirst': [0, ['long long']],
        'MyLast': [8, ['long long']],
        'MyEnd': [16, ['long long']],
    }],
    'MemEntryImpl': [None, {
        'key_': [24, ['pointer', ["char"]]],
        'vector_size': [40, ['unsigned int']],
        'HTTPdata_': [56, ["CharVector"]],
        'BODYdata_': [80, ["CharVector"]],
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

def get_basic_string(self, basic_string_offset, limit=1):
    if self.obj_vm.is_valid_address(basic_string_offset):
            title_string = []
            zero_hit = 0
            count = 0
            while zero_hit != limit:
                char = self.obj_vm.read(basic_string_offset, 0x1)
                basic_string_offset = basic_string_offset + 1
                if char == "\x00":
                    zero_hit = zero_hit + 1
                else:
                    title_string.append(char)
                    zero_hit = 0
            string = "".join(title_string)
            control_chars = "".join(map(unichr, range(0,32) + range(127,160)))
            control_char_re = re.compile('[%s]' % re.escape(control_chars))
            string = control_char_re.sub("", string)
            return string
    return None

def get_timestamp(self, timestamp):
    try:
        microseconds = timestamp - 11644473600000000
        milliseconds = microseconds / 1000.0
        millisecond = milliseconds % 1000.0
        seconds = milliseconds / 1000.0
        utc = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(seconds))
    except ValueError:
        return None
    except TypeError:
        return None
    else:
        return utc

Document_nodeFlag = [struct.unpack("<I", "\x04\x14\x0e\x00")[0],  # 922628
                     struct.unpack("<I", "\x05\x14\x8e\x00")[0],  # 9311237
                     struct.unpack("<I", "\x04\x14\x02\x00")[0],  # 136196
                     struct.unpack("<I", "\x05\x14\x82\x00")[0],  # 8524805
                     struct.unpack("<I", "\x05\x14\x80\x00")[0],  # 8393733
                     struct.unpack("<I", "\x05\x14\x00\x00")[0],  # 5125
                     struct.unpack("<I", "\x04\x14\x00\x00")[0],  # 5124
                     ]

containerNodeFlags = [struct.unpack("<I", "\x1c\x16\x00\x00")[0],  # 5660
                      struct.unpack("<I", "\x1c\x14\x02\x00")[0],  # 136220, html
                      struct.unpack("<I", "\x1c\x14\x0e\x00")[0],  # 922652, html
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

'''
enum PageTransition {
  PAGE_TRANSITION_FIRST = 0,

  // User got to this page by clicking a link on another page.
  PAGE_TRANSITION_LINK = PAGE_TRANSITION_FIRST,

  // User got this page by typing the URL in the URL bar.  This should not be
  // used for cases where the user selected a choice that didn't look at all
  // like a URL; see GENERATED below.
  //
  // We also use this for other "explicit" navigation actions.
  PAGE_TRANSITION_TYPED = 1,

  // User got to this page through a suggestion in the UI, for example)
  // through the destinations page.
  PAGE_TRANSITION_AUTO_BOOKMARK = 2,

  // This is a subframe navigation. This is any content that is automatically
  // loaded in a non-toplevel frame. For example, if a page consists of
  // several frames containing ads, those ad URLs will have this transition
  // type. The user may not even realize the content in these pages is a
  // separate frame, so may not care about the URL (see MANUAL below).
  PAGE_TRANSITION_AUTO_SUBFRAME = 3,

  // For subframe navigations that are explicitly requested by the user and
  // generate new navigation entries in the back/forward list. These are
  // probably more important than frames that were automatically loaded in
  // the background because the user probably cares about the fact that this
  // link was loaded.
  PAGE_TRANSITION_MANUAL_SUBFRAME = 4,

  // User got to this page by typing in the URL bar and selecting an entry
  // that did not look like a URL.  For example, a match might have the URL
  // of a Google search result page, but appear like "Search Google for ...".
  // These are not quite the same as TYPED navigations because the user
  // didn't type or see the destination URL.
  // See also KEYWORD.
  PAGE_TRANSITION_GENERATED = 5,

  // This is a toplevel navigation. This is any content that is automatically
  // loaded in a toplevel frame.  For example, opening a tab to show the ASH
  // screen saver, opening the devtools window, opening the NTP after the safe
  // browsing warning, opening web-based dialog boxes are examples of
  // AUTO_TOPLEVEL navigations.
  PAGE_TRANSITION_AUTO_TOPLEVEL = 6,

  // The user filled out values in a form and submitted it. NOTE that in
  // some situations submitting a form does not result in this transition
  // type. This can happen if the form uses script to submit the contents.
  PAGE_TRANSITION_FORM_SUBMIT = 7,

  // The user "reloaded" the page, either by hitting the reload button or by
  // hitting enter in the address bar.  NOTE: This is distinct from the
  // concept of whether a particular load uses "reload semantics" (i.e.
  // bypasses cached data).  For this reason, lots of code needs to pass
  // around the concept of whether a load should be treated as a "reload"
  // separately from their tracking of this transition type, which is mainly
  // used for proper scoring for consumers who care about how frequently a
  // user typed/visited a particular URL.
  //
  // SessionRestore and undo tab close use this transition type too.
  PAGE_TRANSITION_RELOAD = 8,

  // The url was generated from a replaceable keyword other than the default
  // search provider. If the user types a keyword (which also applies to
  // tab-to-search) in the omnibox this qualifier is applied to the transition
  // type of the generated url. TemplateURLModel then may generate an
  // additional visit with a transition type of KEYWORD_GENERATED against the
  // url 'http://' + keyword. For example, if you do a tab-to-search against
  // wikipedia the generated url has a transition qualifer of KEYWORD, and
  // TemplateURLModel generates a visit for 'wikipedia.org' with a transition
  // type of KEYWORD_GENERATED.
  PAGE_TRANSITION_KEYWORD = 9,

  // Corresponds to a visit generated for a keyword. See description of
  // KEYWORD for more details.
  PAGE_TRANSITION_KEYWORD_GENERATED = 10,

  // ADDING NEW CORE VALUE? Be sure to update the LAST_CORE and CORE_MASK
  // values below.  Also update CoreTransitionString().
  PAGE_TRANSITION_LAST_CORE = PAGE_TRANSITION_KEYWORD_GENERATED,
  PAGE_TRANSITION_CORE_MASK = 0xFF,

  // Qualifiers
  // Any of the core values above can be augmented by one or more qualifiers.
  // These qualifiers further define the transition.

  // A managed user attempted to visit a URL but was blocked.
  PAGE_TRANSITION_BLOCKED = 0x00800000,

  // User used the Forward or Back button to navigate among browsing history.
  PAGE_TRANSITION_FORWARD_BACK = 0x01000000,

  // User used the address bar to trigger this navigation.
  PAGE_TRANSITION_FROM_ADDRESS_BAR = 0x02000000,

  // User is navigating to the home page.
  PAGE_TRANSITION_HOME_PAGE = 0x04000000,

  // The transition originated from an external application; the exact
  // definition of this is embedder dependent.
  PAGE_TRANSITION_FROM_API = 0x08000000,

  // The beginning of a navigation chain.
  PAGE_TRANSITION_CHAIN_START = 0x10000000,

  // The last transition in a redirect chain.
  PAGE_TRANSITION_CHAIN_END = 0x20000000,

  // Redirects caused by JavaScript or a meta refresh tag on the page.
  PAGE_TRANSITION_CLIENT_REDIRECT = 0x40000000,

  // Redirects sent from the server by HTTP headers. It might be nice to
  // break this out into 2 types in the future, permanent or temporary, if we
  // can get that information from WebKit.
  PAGE_TRANSITION_SERVER_REDIRECT = 0x80000000,

  // Used to test whether a transition involves a redirect.
  PAGE_TRANSITION_IS_REDIRECT_MASK = 0xC0000000,

  // General mask defining the bits used for the qualifiers.
  PAGE_TRANSITION_QUALIFIER_MASK = 0xFFFFFF00,
};
'''
page_transition = {0: "by clicking link on another page", 1: "typed address in the URL bar", 2: "By suggestion in the URL bar", 3: "content automatically loaded not in a top-level frame", 4: "subframe navigation explicitly requested by the user", 5: "by clicking a suggestion in the URL bar which isn't a URL", 6: "any content that is loaded in the top-level frame", 7: "The user has submitted a form (no JS submit function)", 8: "Reload page, session restore or undo close tab", 9: "The url was generated from a replaceable keyword", 10: "visit generated for a keyword", 16777216: "back/forward navigation", 33554432: "User used the address bar to trigger this navigation", 33554433: "User used the address bar to trigger this navigation" , 67108864: "User is navigating to the home page", 134217728: "Transition originated from an external application", 268435456: "Beginning of a navigation chain", 536870912: "Last transition in a redirect chain", 1073741824: "Redericts caused by JavaScript or meta refresh tag on the page", 2147483648: "Redirects sent from the server by HTTP headers"}

'''
// The type of the page an entry corresponds to.  Used by chrome_frame and the
// automation layer to detect the state of a WebContents.
enum PageType {
  PAGE_TYPE_NORMAL = 0,
  PAGE_TYPE_ERROR,
  PAGE_TYPE_INTERSTITIAL
};
'''
page_type = {0: "NORMAL", 1: "ERROR", 2: "INTERSTITIAL"}


'''
// Enumerations of the possible restore types.
enum class RestoreType {
  // Restore from the previous session.
  LAST_SESSION_EXITED_CLEANLY,
  LAST_SESSION_CRASHED,

  // The entry has been restored from the current session. This is used when
  // the user issues 'reopen closed tab'.
  CURRENT_SESSION,

  // The entry was not restored.
  NONE
};
'''

restore_type = {0: "LAST_SESSION_EXITED_CLEANLY", 1: "LAST_SESSION_CRASHED", 2: "CURRENT_SESSION (reopen closed tab)", 3: "Entry was not restored"}
http_methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
