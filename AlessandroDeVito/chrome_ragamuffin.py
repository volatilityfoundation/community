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

import libchrome_600311290 as libchrome
import struct
import volatility.obj as obj
import volatility.addrspace as addrspace
import volatility.plugins.common as common
import volatility.win32 as win32
import volatility.utils as utils
import volatility.scan as scan
import volatility.utils as utils
from volatility.renderers import TreeGrid
import string

class DocumentFlagScanner(scan.ScannerCheck):
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + 16, 0x4)
        flag = struct.unpack("<I", data)[0]
        if flag in libchrome.Document_nodeFlag:
            return True
        return False

    def skip(self, data, offset):
        return 8

class NavigationControllerPendingTransient(scan.ScannerCheck):
    def __init__(self, address_space, **kwargs):
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        failed_pending_entry_id = struct.unpack("<i", self.address_space.read(offset, 0x4))[0]
        last_committed_entry_index = struct.unpack("<i", self.address_space.read(offset + 4, 0x4))[0]
        pending_entry_index = struct.unpack("<i", self.address_space.read(offset + 8, 0x4))[0]
        transient_entry_index = struct.unpack("<i", self.address_space.read(offset + 12, 0x4))[0]
        last_pending_entry_index = struct.unpack("<i", self.address_space.read(offset + 16, 0x4))[0]
        last_transient_entry_index = struct.unpack("<i", self.address_space.read(offset + 20, 0x4))[0]
        if failed_pending_entry_id == 0 and last_committed_entry_index >= 0  and pending_entry_index == -1 and transient_entry_index == -1 and last_pending_entry_index == -1 and last_transient_entry_index == -1:
            return True
        return False

    def skip(self, data, offset):
        return 8

class NavigationControllerEntriesCheck():
    def __init__(self, offset, address_space):
        self.offset = offset
        self.address_space = address_space

    def is_valid(self):
        entries_p = self.address_space.read(self.offset - 40, 0x8)
        if entries_p is not None:
            entries_p = struct.unpack("<Q", entries_p)[0] # entries_ pointer
            if self.address_space.is_valid_address(entries_p):
                entries_p = obj.Object("Pointer", vm=self.address_space, offset=entries_p) # First entry pointer 
                if entries_p.is_valid():
                    frame_tree = obj.Object("Pointer", vm=self.address_space, offset=entries_p + 0x8)
                    if frame_tree.is_valid():
                        parent_zero_pointer = struct.unpack("<Q", self.address_space.read(frame_tree, 0x8))[0]
                        if parent_zero_pointer == 0:
                            return True # We have just found a NavigationController Object
        return False


class DocumentScanner(scan.BaseScanner):
    checks = [("DocumentFlagScanner", {})]

class NavigationControllerScanner(scan.BaseScanner):
    checks = [("NavigationControllerPendingTransient", {})]

class WhatsappScanner():
    def __init__(self, dom):
        self.DOMTree = dom
    
    def get_sidebar(self):
        sidebar = None
        for node in self.DOMTree:
            if node.id == "side":
                sidebar = node
        if sidebar is not None:
            sidebar = DOMScanner(sidebar).scan()
        return sidebar
    
    def get_main(self):
        main = None
        for node in self.DOMTree:
            if node.id == "main":
                main = node
        if main is not None:
            main = DOMScanner(main).scan()
        return main

    def get_sidebar_users(self, sidebar):
        for node in sidebar:
            if node.class_name == "chat-body":
                    chatbody = DOMScanner(node).scan()
                    textNodes = [text for text in chatbody if text.tagName == "Text"]
                    for x in textNodes:
                            if x.nodeFlags() == 5122:
                                    value = libchrome.get_chrome_string(x, x.data) + "\n"
                                    yield value

    def get_main_chat(self, main):
            if node.nodeFlags() == 5122:
                value = libchrome.get_chrome_string(node, node.data) + "\n"
                yield value

    def sidebar_users(self):
        sidebar = self.get_sidebar()
        if sidebar is not None:
           users = self.get_sidebar_users(sidebar)
           return users

    def main_chat(self):
        main = self.get_main()
        if main is not None:
            main = self.get_main_chat(main)
            return main

class DOMScanner():
    def __init__(self, rootNode):
        self.rootNode = rootNode
        self.dom = []

    def wrap(self, node):
        if node.nodeFlags() in libchrome.otherFlags:
            node = node.dereference_as("TextNode")
        if node.tagName == "form":
            node = node.dereference_as("HTMLElementForm")
        if node.tagName == "iframe":
            node = node.dereference_as("HTMLIframeElement")
        if node.tagName == "a":
            node = node.dereference_as("HTMLAnchorElement")
        return node

    def scan(self):
        HTMLHtmlElement = self.rootNode.dereference_as("Element")
        # pdb.set_trace()
        self.parseDOMTree(HTMLHtmlElement)
        return self.dom

    def parseDOMTree(self, root):
        root = self.wrap(root)
        self.dom.append(root)
        if root.obj_type is not "TextNode" and root.obj_vm.is_valid_address(root.firstChild):  # container
            self.parseDOMTree(root.firstChild.dereference())
        if root.obj_vm.is_valid_address(root.next):  # not container
            self.parseDOMTree(root.next.dereference())
        return

class _node(obj.CType):
    def nodeFlags(self):
        return self.m_nodeFlags

    @property
    def previous(self):
        return self.m_previous

    @property
    def next(self):
        return self.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.m_parentOrShadowHostNode

    @property
    def tagName(self):
        return "unknown_node"

    def printNode(self):
        return "Node tag: {0}\nMemory offset: 0x{1:08x}\n".format(
        self.tagName,
        self.obj_offset)

class _element_mixin():
    def nodeFlags(self):
        return self.Element.Container.Node.m_nodeFlags

    @property
    def previous(self):
        return self.Element.Container.Node.m_previous

    @property
    def next(self):
        return self.Element.Container.Node.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.Element.Container.Node.m_parentOrShadowHostNode

    @property
    def firstChild(self):
        return self.Element.Container.m_firstChild

    @property
    def lastChild(self):
        return self.Element.Container.m_lastChild

    @property
    def tagName(self):
        return libchrome.get_qualified_string(self, self.Element.m_tagName)

    @property
    def class_name(self):
        return libchrome.get_chrome_string(self, self.Element.m_elementData.class_names_.key_string_.v())

    @property
    def object_id(self):
        id_style_for_resolution = self.Element.m_elementData.id_style_for_resolution
        return libchrome.get_chrome_string(self, id_style_for_resolution.v())

    def get_attributes(self):
        attributes = dict()

        shareableElementData = self.Element.m_elementData.dereference_as("ShareableElementData")
        Attribute = shareableElementData.m_attribute
        while self.obj_vm.is_valid_address(Attribute.m_name.v()):
            m_name = libchrome.get_qualified_string(Attribute, Attribute.m_name)
            m_value = libchrome.get_chrome_string(Attribute, Attribute.m_value)
            attributes[m_name] = m_value
            Attribute = obj.Object("Attribute", vm=self.obj_vm, offset=Attribute.v()+Attribute.struct_size)
        return attributes

    def printNode(self):
        return "Node tag: {0}\nNode attributes: {1}\nMemory offset: 0x{2:08x}\n".format(
        self.tagName,
        self.get_attributes(),
        self.obj_offset)

class _element_data(obj.CType):
    @property
    def id(self):
        return self.id_style_for_resolution

class _element(obj.CType):
    def nodeFlags(self):
        return self.Container.Node.m_nodeFlags

    @property
    def previous(self):
        return self.Container.Node.m_previous

    @property
    def next(self):
        return self.Container.Node.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.Container.Node.m_parentOrShadowHostNode

    @property
    def firstChild(self):
        return self.Container.m_firstChild

    @property
    def lastChild(self):
        return self.Container.m_lastChild

    @property
    def elementData(self):
        return self.Element.m_elementData

    @property
    def tagName(self):
        return libchrome.get_qualified_string(self, self.m_tagName)

    @property
    def class_name(self):
        return libchrome.get_chrome_string(self, self.m_elementData.class_names_.key_string_.v())

    @property
    def id(self):
        id_style_for_resolution = self.m_elementData.id_style_for_resolution
        return libchrome.get_chrome_string(self, id_style_for_resolution.v())

    def get_attributes(self):
        attributes = dict()

        shareableElementData = self.m_elementData.dereference_as("ShareableElementData")
        Attribute = shareableElementData.m_attribute
        while self.obj_vm.is_valid_address(Attribute.m_name.v()):
            m_name = libchrome.get_qualified_string(Attribute, Attribute.m_name)
            m_value = libchrome.get_chrome_string(Attribute, Attribute.m_value)
            attributes[m_name] = m_value
            Attribute = obj.Object("Attribute", vm=self.obj_vm, offset=Attribute.v()+Attribute.struct_size)
        return attributes

    def printNode(self):
        return "Node tag: {0}\nNode attributes: {1}\nMemory offset: 0x{2:08x}\n".format(
        self.tagName,
        self.get_attributes(),
        self.obj_offset)


class _html_element_form(_element_mixin, obj.CType):
    @property
    def method(self):
        return self.m_method

    @property
    def action(self):
        return self.m_action


class _html_iframe_element(_element_mixin, obj.CType):
    @property
    def src(self):
        return self.m_URL

    @property
    def contentDocument(self):
        return self.m_contentFrame.m_domWindow.m_document.dereference()

    def printNode(self):
        return "Node tag: {0}\nNode attributes: {1}\nsrc: {2}\nMemory offset: 0x{3:08x}\nContained document offset: 0x{4:08x}\n".format        (self.tagName,
         self.get_attributes(),
         libchrome.get_chrome_string(self, self.src),
         self.obj_offset,
         self.contentDocument)

class _html_anchor_element(_element_mixin, obj.CType):
    def href(self):
        attributes = self.get_attributes()
        return attributes["href"] if "href" in attributes.keys() else None

class _html_image_element(_element_mixin, obj.CType):
    @property
    def src(self):
        return libchrome.get_chrome_string(self, self.best_fit_image_url_.v())

class _attributes(obj.CType):
    @property
    def getValue(self):
        return libchrome.get_chrome_string(self, self.m_value)

class _textNode(obj.CType):
    def nodeFlags(self):
        return self.Node.m_nodeFlags

    @property
    def previous(self):
        return self.Node.m_previous

    @property
    def next(self):
        return self.Node.m_next

    @property
    def parentOrShadowHostNode(self):
        return self.Node.m_parentOrShadowHostNode

    @property
    def data(self):
        return self.m_data

    @property
    def id(self):
        return None

    @property
    def class_name(self):
        return None

    @property
    def tagName(self):
        return "Text"

    def printNode(self):
        return "Node tag: {0}\nContent: {1}\n".format(
        self.tagName,
        libchrome.get_chrome_string(self, self.data))

class _document(obj.CType):
    @property
    def url_string(self):
        url_string = libchrome.get_chrome_string(self, self.m_url)
        return url_string

    @property
    def title(self):
        title = libchrome.get_chrome_string(self, self.m_title)
        return title

    def is_valid(self):
        if self.m_domWindow.m_document.v() == self.obj_offset:
            return True
        return False

    @property
    def documentElement(self):
        return self.m_documentElement

class _vector(obj.CType):
    def get_elements(self, object_type, object_size=8, pointers_vector=True):
        size = 0
        vector = []
        vector_pointer = self.v()
        element_p = obj.Object("Pointer", vm=self.obj_vm, offset=vector_pointer)
        first_element_p = element_p
        while obj.Object("Pointer", vm=self.obj_vm, offset=vector_pointer).is_valid():
            if pointers_vector:
                vector.append(element_p.dereference_as(object_type))
                vector_pointer = vector_pointer + 8
                element_p = obj.Object("Pointer", vm=self.obj_vm, offset=vector_pointer)
            else:
                size = size + 1
                element_p = element_p + object_size
                vector_pointer = element_p
        if pointers_vector is False and size > 0:
            vector = obj.Array(object_type, vm=self.obj_vm, offset=first_element_p.v(), count=size, targetType=object_type)
        return vector
            
class _web_contents(obj.CType):
    @property
    def _controller(self):
        return self.controller_

class _navigation_controller(obj.CType):
    @property
    def get_entries(self):
        entries_ = self.entries_
        entries_vector = entries_.get_elements("NavigationEntry")
        return entries_vector

class _navigation_entry(obj.CType):
    def is_valid(self):
        if self.obj_vm.is_valid_address(self.frame_tree_):
            return True
        return False

    def get_frame_entries(self, head, tree):
        if head.frame_entry_.is_valid() and head.frame_entry_.dereference().is_a_valid_frame_entry():
            tree.append(head.frame_entry_.dereference())
            if self.obj_vm.is_valid_address(head.children_):
                children_vector = head.children_.get_elements("TreeNode")
                for child in children_vector:
                    self.get_frame_entries(child, tree)
            return tree

    @property
    def id(self):
        return self.unique_id_

    @property
    def title(self):
        return libchrome.get_basic_string(self, self.title_, limit=2)

    @property
    def user_typed_url(self):
        return libchrome.get_basic_string(self, self.user_typed_url_.spec_)
        
    @property
    def original_request_url(self):
        return libchrome.get_basic_string(self, self.original_request_url_.spec_)

    @property
    def http_status_code(self):
        return self.http_status_code_

    @property
    def post_data(self):
        return self.post_data_

    @property
    def method(self):
        if self.post_data.is_valid():
            return "POST"
        return "GET"

    @property
    def transition(self):
        index = int(self.transition_type_)
        keys = libchrome.page_transition.keys()
        if index in keys:
            transition = libchrome.page_transition[index] 
            if transition:
                return transition
        return "Unknown"

    @property
    def page_type(self):
        index = int(self.page_type_)
        keys = libchrome.page_type.keys()
        if index in keys:
            page_type = libchrome.page_type[index] 
            if page_type:
                return page_type
        return None

    @property
    def restore_type(self):
        index = int(self.restore_type_)
        keys = libchrome.restore_type.keys()
        if index in keys:
            restore_type = libchrome.restore_type[index] 
            if restore_type:
                return restore_type
        return None

    @property
    def timestamp(self):
        return libchrome.get_timestamp(self, self.timestamp_)

    @property
    def referer(self):
        return None

    @property
    def redirect_chain(self):
        return None
        
class _frame_navigation_entry(obj.CType):
    def is_a_valid_frame_entry(self):
        if self.item_sequence_number is not None:
            if self.document_sequence_number is not None:
                if self.method in libchrome.http_methods:
                    return True
        return False

    @property
    def item_sequence_number(self):
        return self.item_sequence_number_

    @property
    def document_sequence_number(self):
        return self.document_sequence_number_

    @property
    def url(self):
        return libchrome.get_basic_string(self, self.url_.spec_)

    @property
    def referer(self):
        gurl = self.referer_.dereference_as("GURL")
        if gurl.is_a_valid_gurl():
            return libchrome.get_basic_string(self, gurl.spec_)
        return None

    @property
    def redirect_chain(self):
        gurls = []
        redirect_chain_vector = self.redirect_chain_.get_elements("GURL", object_size=128, pointers_vector=False)
        redirect_chain_vector = [gurl for gurl in redirect_chain_vector if self.obj_vm.is_valid_address(gurl.spec_)]
        for gurl in redirect_chain_vector:
            if gurl.is_a_valid_gurl():
                gurls.append(libchrome.get_basic_string(self, gurl.spec_))
        if gurls:
            return ",".join(gurls)
        return None
    
    @property
    def method(self):
        return libchrome.get_basic_string(self, self.method_.v())

    @property
    def page_state(self):
        return self.page_state_.v()

    @property
    def frame_unique_name(self):
        return libchrome.get_basic_string(self, self.frame_unique_name_)

class _page_state(obj.CType):
    @property
    def size(self):
        return self.size_
    
    @property
    def dump_page_state(self):
        size = int(self.size)
        data = self.data_
        page_state_dump = self.obj_vm.read(data, size)
        no_null_terminator = page_state_dump.replace("\x00", "")
        string_readable = "".join([c for c in no_null_terminator if c in string.printable])
        return string_readable

class _tree_node(obj.CType):
    @property
    def parent(self):
        return self.parent_

class _gurl(obj.CType):
    def is_a_valid_gurl(self):
        if int(bin(self.is_valid_), 2) & 0x1:
            return True
        return False

class ChromeTypes(obj.ProfileModification):
    def modification(self, profile):
        profile.vtypes.update(libchrome.chrome_vtypes)
        profile.object_classes.update(
            {"chrome_document": _document, "TextNode": _textNode, "Element": _element,
             "DOMNode": _node, "HTMLElementForm": _html_element_form, "HTMLIframeElement": _html_iframe_element, "HTMLAnchorElement": _html_anchor_element, "Attribute": _attributes, "ElementData": _element_data, "HTMLImageElement": _html_image_element, "WebContents": _web_contents, "NavigationController": _navigation_controller, "NavigationEntry": _navigation_entry, "Vector": _vector, "FrameNavigationEntry": _frame_navigation_entry, "TreeNode": _tree_node, "GURL": _gurl, "PageState": _page_state})


class chrome_ragamuffin(common.AbstractWindowsCommand):
    """Recover some useful artifact from Chrome process memory"""
    urlparsed = []

    def __init__(self, config, *args, **kwargs):
        self.analysis_missing = "you need to add the --analysis flag. run with -h for help"
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        config.add_option('PID', short_option='p', default=None,
                          help='Operate on this Process ID',
                          action='store', type='str')
        config.add_option('documents', default=None,
                          help='Blink::Document\'s offsets (comma separated values)',
                          action='store', type='str')
        config.add_option('dom', default=None,
                            help='DOM root node offset. This will dump the DOM tree',
                            action='store', type='str')
        config.add_option('whatsapp', default=None,
                            help='get sidebar and main active chat')
        config.add_option('analysis', default=None,
                            help='you have to choose between "history" (history navigation from browser process) and "renderer" (document objects from the renderer process)')

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        history_done = False

        for task in tasks:
            proc_name = task.ImageFileName
            proc_pid = task.UniqueProcessId
            proc_as = task.get_process_address_space()

            # In cases when mm is an invalid pointer
            if not proc_as:
                continue

            # We scan just chrome instances
            if str(proc_name) != "chrome.exe":
                continue

            if "pid" in self._config.opts and str(proc_pid) != str(self._config.opts["pid"]):
                continue

            if "analysis" in self._config.opts and self._config.opts["analysis"] == "history":
                    if history_done is False:
                        navigation_controllers = []
                        web_contents = []
                        for navigation_controller in NavigationControllerScanner().scan(proc_as):
                            if NavigationControllerEntriesCheck(navigation_controller, proc_as).is_valid():
                                navigation_controller = obj.Object("NavigationController", vm=proc_as, offset=navigation_controller - 56)
                                web_contents.append(navigation_controller.v() - 112)
                                entries = navigation_controller.get_entries 
                                entries = [entry for entry in entries if entry.is_valid()]
                                for entry in entries:
                                    tree = []
                                    frame_entries = entry.get_frame_entries(entry.frame_tree_.dereference(), tree)
                                    if frame_entries:
                                        first_entry = frame_entries[0]
                                        frame_entries.pop(0)
                                        yield entry.id, entry.obj_offset, entry.title, entry.user_typed_url, entry.original_request_url, entry.http_status_code, first_entry.method, first_entry.page_state, entry.transition, first_entry.referer, first_entry.redirect_chain, entry.timestamp, entry.restore_type, entry.page_type
                                    if frame_entries:
                                            for frame_entry in frame_entries:
                                                yield entry.id, frame_entry.obj_offset, "frame_entry_object", frame_entry.url, frame_entry.url, None, frame_entry.method, frame_entry.page_state, None, frame_entry.referer, frame_entry.redirect_chain, entry.timestamp, None, frame_entry.frame_unique_name
                                history_done = True

            
            if "analysis" in self._config.opts and self._config.opts["analysis"] == "renderer":
                documents = []
                if "documents" in self._config.opts:
                    document_pointers = [int(p, 16) for p in self._config.opts["documents"].split(',')]
                    documents = [obj.Object("chrome_document", vm=proc_as, offset=p) for p in document_pointers]
                else:
                    for document_offset in DocumentScanner().scan(proc_as):
                        documents.append(obj.Object("chrome_document", vm=proc_as, offset=document_offset))
            
                #Validate all blink::Document objects
                documents = [document for document in documents if document.is_valid()]

                DOM = None
                if "dom" in self._config.opts:
                    rootNode = int(self._config.opts["dom"], 16)
                    if proc_as.is_valid_address(rootNode):
                        rootNode = obj.Object("DOMNode", vm=proc_as, offset=rootNode)
                        DOMTreeParser = DOMScanner(rootNode)
                        DOM = DOMTreeParser.scan()
                        sidebar = None
                        main = None

                sidebar = None
                main = None
                if "whatsapp" in self._config.opts:
                    for document in documents:
                        if proc_as.is_valid_address(document.documentElement.v()):
                            rootNode = obj.Object("DOMNode", vm=proc_as, offset=document.documentElement.v())
                            whatsapp_dom = DOMScanner(rootNode).scan()
                            whatsapp_scanner = WhatsappScanner(whatsapp_dom)
                            sidebar = whatsapp_scanner.sidebar_users()
                            main = whatsapp_scanner.main_chat()

                # Return for each document found in this process address space
                for document in documents:
                    yield proc_pid, document, DOM, sidebar, main

    def render_text(self, outfd, data):
        if "analysis" in self._config.opts:
            if "analysis" in self._config.opts and self._config.opts["analysis"] == "history":
                    # <History>
                    self.table_header(outfd, [("ID", "3"), 
                                              ("Offset", "20"),
                                              ("Title", "50"),
                                              ("User typed url", "50"),
                                              ("Original request url", "50"),
                                              ("Status code", "3"),
                                              ("Method", "3"),
                                              ("PageState address", "20"),
                                              ("Transition", "10"),
                                              ("Referrer", "10"),
                                              ("Redirect chain", "8"),
                                              ("UTC Timestamp", "23"),
                                              ("Restore type", "30"),
                                              ("Page type", "10")])

                    for id, offset, title, user_typed_url, original_request_url, http_status_code, method, post_data, transition, referer, redirect_chain, timestamp, restore_type, page_type in data:
                        self.table_row(outfd, id, hex(offset), title, user_typed_url, original_request_url, http_status_code, method, post_data, transition, referer, redirect_chain, timestamp, restore_type, page_type)

                    # </History>

            if "analysis" in self._config.opts and self._config.opts["analysis"] == "renderer":
                self.table_header(outfd, [("Pid", "8"),
                                          ("Document offset", "20"),
                                          ("URL", "50"),
                                          ("Title", "50"),
                                          ("DOM start address", "8")])
                for pid, document, DOM, sidebar, main in data:
                    if document is not None:
                            self.table_row(outfd, pid, hex(document.obj_offset), str(document.url_string), str(document.title), hex(document.documentElement.v())[:-1])
                    if DOM is not None:
                        for node in DOM:
                            expanded_node = node.printNode()
                            outfd.write(expanded_node)
                    if sidebar is not None:
                        outfd.write("===== SIDEBAR =====\n")
                        for i in sidebar:
                            outfd.write(i)
                    if main is not None:
                        outfd.write("===== MAIN CHAT =====\n")
                        for i in main:
                            outfd.write(i)

        else:
            outfd.write(self.analysis_missing)

    def render_csv(self, outfd, data):
        if "analysis" in self._config.opts:
            #ipdb.set_trace()
            outfd.write('ID$Offset$Title$User typed url$Original request url$Status code$Method$Post params$Transition$Referer$Redirect chain$UTC Timestamp$Restore Type$Type page\n')
            for id, offset, title, user_typed_url, original_request_url, http_status_code, method, post_data, transition, referer, redirect_chain, timestamp, restore_type, page_type in data:
                row_output = "{0}${1}${2}${3}${4}${5}${6}${7}${8}${9}${10}${11}${12}${13}\n".format(
                    id, 
                    offset, 
                    title, 
                    user_typed_url, 
                    original_request_url, 
                    http_status_code, 
                    method, 
                    post_data, 
                    transition, 
                    referer, 
                    redirect_chain, 
                    timestamp, 
                    restore_type, 
                    page_type)
                outfd.write(row_output)
        else:
            outfd.write(self.analysis_missing)

    def render_dot(self, outfd, data):
        if "analysis" in self._config.opts:
            for pid, document, DOM, sidebar, main in data:
                outfd.write("/" + "*" * 72 + "/\n")
                outfd.write("/* Pid: {0:6}, url: {1} */\n".format(pid, str(document.url_string)))
                outfd.write("digraph DOMTree {\n")
                outfd.write("graph [rankdir = \"TB\"];\n")
                for node in DOM:
                    fillcolor = "white"
                    if node:
                        if node.parentOrShadowHostNode:
                            outfd.write(
                                "{2}_0x{0:08x} -> {3}_0x{1:08x}\n".format(
                                    node.parentOrShadowHostNode.dereference().obj_offset or 0, 
                                    node.obj_offset, 
                                    node.parentOrShadowHostNode.dereference().tagName, 
                                    node.tagName))
                            if node.tagName == "iframe":
                                fillcolor = "yellow"
                                outfd.write("{0}_0x{1:08x} [label = \"{{ {0} | node_0x{1:08x} | iframe document offset: 0x{2:08x} }}\" "
                                        "shape = \"record\" color = \"blue\" style = \"filled\" fillcolor = \"{3}\"];\n".format(
                                node.tagName,
                                node.obj_offset,
                                node.contentDocument.v(),
                                fillcolor))
                            else:
                                if node.tagName == "a":
                                    fillcolor = "red"
                                    outfd.write("{3}_0x{0:08x} [label = \"{{ {3}  | id: {1} | class: {2} }}\" "
                                                "shape = \"record\" color = \"blue\" style = \"filled\" fillcolor = \"{4}\"];\n".format(
                                    node.obj_offset,
                                    node.object_id,
                                    node.class_name,
                                    node.tagName,
                                    fillcolor))
                outfd.write("}\n")
        else:
            outfd.write(self.analysis_missing)
