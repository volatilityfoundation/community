"""
@author:       Adam Bridge (bridgeythegeek)
@license:      GNU General Public License 2.0
@contact:      bridgeythegeek@gmail.com
@organization: 
"""

import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.pslist as linux_pslist
import volatility.utils as utils

import struct


xwindows_vtypes_x64 = {

    # typedef struct _PixmapFormat {
    #     unsigned char depth;
    #     unsigned char bitsPerPixel;
    #     unsigned char scanlinePad;
    # } PixmapFormatRec;

    'PixmapFormatRec' : [ 0x03, {
        'depth': [0x00, ['char']],
        'bitsPerPixel': [0x01, ['char']],
        'scanlinePad': [0x02, ['char']]
    }],

    # typedef struct _ScreenInfo {
    #     int imageByteOrder;
    #     int bitmapScanlineUnit;
    #     int bitmapScanlinePad;
    #     int bitmapBitOrder;
    #     int numPixmapFormats;
    #     PixmapFormatRec formats[MAXFORMATS];
    #     int numScreens;
    #     ScreenPtr screens[MAXSCREENS];
    #     int numGPUScreens;
    #     ScreenPtr gpuscreens[MAXGPUSCREENS];
    #     int x;                      /* origin */
    #     int y;                      /* origin */
    #     int width;                  /* total width of all screens together */
    #     int height;                 /* total height of all screens together */
    # } ScreenInfo;

    'ScreenInfo': [ 328, {
        'imageByteOrder': [0x00, ['int']],
        'bitmapScanlineUnit': [0x04, ['int']],
        'bitmapScanlinePad': [0x08, ['int']],
        'bitmapBitOrder': [0x0c, ['int']],
        'numPixmapFormats': [0x10, ['int']],
        'formats': [0x14, ['array', 8, ['PixmapFormatRec']]],
        'numScreens': [0x2c, ['int']],
        'screens': [0x30, ['array', 16, ['pointer', ['ScreenPtr']]]],
        'numGPUScreens': [0xb0, ['int']],
        'gpuScreens': [0xb8, ['array', 16, ['address']]], # Why at 0xb8 and not 0xb4???
        'x': [0x138, ['int']],
        'y': [0x13c, ['int']],
        'width': [0x140, ['int']],
        'height': [0x144, ['int']]
    }],

    # typedef struct _Screen {
    #     int myNum;                  /* index of this instance in Screens[] */
    #     ATOM id;
    #     short x, y, width, height;
    #     short mmWidth, mmHeight;
    #     short numDepths;
    #     unsigned char rootDepth;
    #     DepthPtr allowedDepths;
    #     unsigned long rootVisual;
    #     unsigned long defColormap;
    #     short minInstalledCmaps, maxInstalledCmaps;
    #     char backingStoreSupport, saveUnderSupport;
    #     unsigned long whitePixel, blackPixel;
    #     GCPtr GCperDepth[MAXFORMATS + 1];
    #     PixmapPtr PixmapPerDepth[1];
    #     void *devPrivate;
    #     short numVisuals;
    #     VisualPtr visuals;
    #     WindowPtr root;
    #     ...

    'ScreenPtr': [0xb8, {
        'myNum': [0x00, ['int']],
        'id': [0x04, ['unsigned int']],
        'x': [0x08, ['short']],
        'y': [0x0a, ['short']],
        'width': [0x0c, ['short']],
        'height': [0x0e, ['short']],
        'mmWidth': [0x10, ['short']],
        'mmHeight': [0x12, ['short']],
        'numDepths': [0x14, ['short']],
        'rootDepth': [0x16, ['short']], #unsigned char?
        'allowedDepths': [0x18, ['address']],
        'rootVisual': [0x20, ['unsigned long']],
        'defColormap': [0x28, ['unsigned long']],
        'minInstalledCmaps': [0x30, ['short']],
        'maxInstalledCmaps': [0x32, ['short']],
        'backingStoreSupport': [0x34, ['char']], #short?
        'saveUnderSupport': [0x36, ['char']], #short?
        'whitePixel': [0x38, ['unsigned long']],
        'blackPixel': [0x40, ['unsigned long']],
        'GCperDepth': [0x48, ['array', 9, ['address']]],
        'PixmapPerDepth': [0x90, ['array', 1, ['address']]],
        'devPrivate': [0x98, ['pointer', ['void']]],
        'numVisuals': [0xa0, ['short']],
        'visuals': [0xa8, ['address']],
        'root': [0xb0, ['pointer', ['WindowPtr']]]
    }],

    'DrawableRec': [0x20, {
        'type': [0x00, ['unsigned char']],
        'class': [0x01, ['unsigned char']],
        'depth': [0x02, ['unsigned char']],
        'bitsPerPixel': [0x03, ['unsigned char']],
        'id': [0x04, ['unsigned int']],
        'x': [0x08, ['short']],
        'y': [0x0a, ['short']],
        'width': [0x0c, ['unsigned short']],
        'height': [0x0e, ['unsigned short']],
        'pScreen': [0x10, ['pointer', ['ScreenPtr']]],
        'serialNumber': [0x18, ['unsigned long']]
    }],

    'WindowPtr': [0xd0, {
        'drawable': [0x00, ['DrawableRec']],
        'devPrivates': [0x20, ['pointer', ['void']]],
        'parent': [0x28, ['pointer', ['WindowPtr']]],
        'nextSib': [0x30, ['pointer', ['WindowPtr']]],
        'prevSib': [0x38, ['pointer', ['WindowPtr']]],
        'firstChild': [0x40, ['pointer', ['WindowPtr']]],
        'lastChild': [0x48, ['pointer', ['WindowPtr']]],
        'clipList': [0x50, ['RegionRec']],
        'borderClip': [0x60, ['RegionRec']],
        'valdata': [0x70, ['pointer', ['void']]],
        'winSize': [0x78, ['RegionRec']],
        'borderSize': [0x88, ['RegionRec']],
        #'origin': [0x98, ['DDXPointRec']],
        'borderWidth': [0x9c, ['unsigned short']],
        'deliverableEvents': [0x9e, ['unsigned short']],
        'eventMask': [0xa0, ['unsigned int']],
        #'background': [0xa8, ['PixUnion']],
        #'border': [0xac, ['PixUnion']],
        'optional': [0xb8, ['pointer', ['WindowOpt']]]
    }],
    
    'AtomNode': [0x20, {
        'left': [0x00, ['pointer', ['AtomNode']]],
        'right': [0x08, ['pointer', ['AtomNode']]],
        'a': [0x10, ['unsigned int']],
        'fingerPrint': [0x14, ['unsigned int']],
        'string': [0x18, ['pointer', ['String', dict(length=1024)]]]
    }],
    
    #(gdb) ptype screenInfo.screens[0].root.optional
    #type = struct _WindowOpt {
    # CursorPtr cursor; 8
    # VisualID visual; 4
    # Colormap colormap; 4
    # Mask dontPropagateMask; 4
    # Mask otherEventMasks; 4
    # struct _OtherClients *otherClients; 8
    # struct _GrabRec *passiveGrabs; 8
    # PropertyPtr userProps; 8
    # CARD32 backingBitPlanes;
    # CARD32 backingPixel;
    # RegionPtr boundingShape;
    # RegionPtr clipShape;
    # RegionPtr inputShape;
    # struct _OtherInputMasks *inputMasks;
    # DevCursorList deviceCursors;
    #} *
    
    'WindowOpt': [0x30, {
       'userProps': [0x28, ['pointer', ['Property']]]
    }],
    
    #(gdb) ptype screenInfo.screens[0].root.optional.userProps
    #type = struct _Property {
    # struct _Property *next;
    # ATOM propertyName;
    # ATOM type;
    # uint32_t format;
    # uint32_t size;
    # void *data;
    # PrivateRec *devPrivates;
    #} *

    'Property': [0x28, {
       'next_': [0x00, ['pointer', ['Property']]],
       'propertyName': [0x08, ['unsigned int']],
       'type': [0x0c, ['unsigned int']],
       'format': [0x10, ['unsigned int']],
       'size_': [0x14, ['unsigned int']],
       'data': [0x18, ['pointer', ['void']]],
       'devPrivates': [0x20, ['pointer', ['void']]]
    }]
}


class ScreenInfo(obj.CType):

    def __str__(self):
        """String representation of ScreenInfo"""

        return '<{0}(offset={6:#x}, numScreens={1}, x={2}, y={3}, width={4}, height={5})>'.format(
            self.__class__.__name__, self.numScreens, self.x, self.y, self.width, self.height, self.v())


class ScreenPtr(obj.CType):

    def __str__(self):
        """String representation of ScreenPtr"""

        return '<{0}(offset={8:#x}, myNum={1}, id={2}, x={3}, y={4}, width={5}, height={6}, root={7:#x})>'.format(
            self.__class__.__name__, self.myNum, self.id, self.x, self.y, self.width, self.height, self.root, self.v())


class WindowPtr(obj.CType):

    def __str__(self):
        """String representation of WindowPtr"""

        return '<{}(offset={:#x}, id={:#x}, x={}, y={}, width={}, height={}, parent={:#x}, firstChild={:#x}, lastChild={:#x}, nextSib={:#x}, prevSib={:#x})>'.format(
            self.__class__.__name__, self.v(), self.drawable.id, self.drawable.x, self.drawable.y, self.drawable.width, self.drawable.height,
            self.parent, self.firstChild, self.lastChild, self.nextSib, self.prevSib)


class AtomNode(obj.CType):

    def __str__(self):
        """String representation of AtomNode"""
        
        return '<{}(offset={:#x}, a={:#x}, string={})>'.format(
            self.__class__.__name__, self.v(), self.a, self.string.dereference())


class WindowOpt(obj.CType):

    def __str__(self):
        """String representation of WindowOpt"""
        
        return '<{}(offset={:#x}, userProps={:#x})>'.format(
            self.__class__.__name__, self.v(), self.userProps)


class Property(obj.CType):

    __type_string = ['STRING', '_NET_DESKTOP_NAMES', 'WM_CLASS', '_NET_WM_NAME', '_NET_WM_ICON_NAME']
    __type_uint32 = ['ATOM', 'CARDINAL', '_NET_WM_PID']
    __type_int32  = ['INTEGER']

    def read_data(self, vm, type):
        """Read the property's data. Each type needs to be implemented."""

        # Let's not go crazy!
        max_size = self.size_
        truncated = False
        if max_size > 0x200: # 512 bytes
            max_size = 0x200
            truncated = True
    
        if type in self.__type_string:
            # Null separated strings
            l = [x for x in vm.zread(self.data, max_size).split('\0') if x]
            temp = ','.join(l)
            return '{}... <and {:#x} more bytes>'.format(temp,
                                                          self.size_ - max_size) if max_size < self.size_ else temp
        elif type in self.__type_uint32:
            # unsigned int32
            temp = ','.join([str(x) for x in struct.unpack('{}I'.format(int(max_size)), vm.zread(self.data, int(max_size) * 4))])
            return '{}... <and {:#x} more bytes>'.format(temp,
                                                          self.size_ - max_size) if max_size < self.size_ else temp
        elif type in self.__type_int32:
            # signed int32
            temp = ','.join([str(x) for x in struct.unpack('{}i'.format(int(max_size)), vm.zread(self.data, int(max_size) * 4))])
            return '{}... <and {:#x} more bytes>'.format(temp,
                                                          self.size_ - max_size) if max_size < self.size_ else temp

        return None # Don't know how to read

    def __str__(self):
        """String representation of Property"""
        
        return '<{}(offset={:#x}, propertyName={:#x}, type={:#x}, format={}, size={:#x}, data={:#x})>'.format(
            self.__class__.__name__, self.v(), self.propertyName, self.type, self.format, self.size_, self.data)


class linux_xatoms(linux_pslist.linux_pslist):
    """Lists the Atoms from each X server process"""
    
    xatoms_classes = {
        'AtomNode'   : AtomNode
    }
    
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID',
                                short_option='p',
                                default=None,
                                help='PIDs to analyse (comma separated)',
                                action='store',
                                type='str'
                                )
    
    def seek_atom_root(self, task, proc_maps):
        """Find the root Atom node; it's in the heap somewhere"""
    
        _atom_root = None
        
        debug.info("Seeking atomRoot.")
        
        for proc_map in proc_maps:
            (fname, major, minor, ino, pgoff) = proc_map.info(task)
            if fname == '[heap]': # The atoms are on the heap
                debug.info('Heap: {} {:#x} {:#x}'.format(str(proc_map.vm_flags), proc_map.vm_start, proc_map.vm_end))
                offset = proc_map.vm_start
                while offset < proc_map.vm_end:
                    if self._current_vm.is_valid_address(offset):
                        atom_root = obj.Object('AtomNode', vm=self._current_vm, offset=offset)
                        if self.is_atom_root_sane(atom_root):
                            debug.info(atom_root)
                            return atom_root
                    offset += 8

        return None # Didn't find the root Atom node

    def is_atom_root_sane(self, atom_root):
        """Validate a candidate root Atom node"""
    
        if not self._current_vm.is_valid_address(atom_root.string):
            return False
        
        return atom_root.a == 0x01 and str(atom_root.string.dereference()) == 'PRIMARY'
    
    def visit_atomNode(self, atomNode):
    
        if atomNode.v() in self._seen_atoms:
            debug.info('Atom referenced more than once! Offset {:#x}.'.format(atomNode.v()))
        else:
            self._atoms[int(atomNode.a)] = atomNode
            self._seen_atoms.add(atomNode.v())
        
        if atomNode.left and self._current_vm.is_valid_address(atomNode.left):
            self.visit_atomNode(atomNode.left.dereference())
        
        if atomNode.right and self._current_vm.is_valid_address(atomNode.right):
            self.visit_atomNode(atomNode.right.dereference())
    
    def calculate(self):
    
        # Apply the correct vtypes for the profile
        addr_space = utils.load_as(self._config)
        addr_space.profile.object_classes.update(linux_xatoms.xatoms_classes)
        addr_space.profile.vtypes.update(xwindows_vtypes_x64)
        addr_space.profile.compile()

        # Build a list of tasks
        tasks = linux_pslist.linux_pslist.calculate(self)
        if self._config.PID:
            pids = [int(p) for p in self._config.PID.split(',')]
            the_tasks = [t for t in tasks if t.pid in pids]
        else:
            # Find the X Windows task
            the_tasks = []
            for task in tasks:
                task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)
                task_name = str(task.comm)
                task_pid = int(task.pid)
                if task_name == 'X' or task_name == 'Xorg':
                    the_tasks.append(task)

        # In case no appropriate processes are found
        if len(the_tasks) < 1:
            return

        for task in the_tasks:

            # These need to be here so that they're reset for each X/Xorg process.
            self._atoms = {}  # Holds the atoms, per X process
            self._seen_atoms = set()  # Holds a list of atom offsets for avoiding circular referencing

            self._current_vm = task.get_process_address_space()
            msg = 'Working with \'{0}\' (pid={1}).'.format(str(task.comm), task.pid)
            debug.info(msg)
            proc_maps = task.get_proc_maps()
            atom_root = self.seek_atom_root(task, proc_maps)
            if atom_root:
                self.visit_atomNode(atom_root)
            debug.info('Found {:,} atom(s).'.format(len(self._atoms)))
            yield msg, self._atoms
    
    def render_text(self, outfd, data):
    
        for msg, atoms in data:
            outfd.write('{}\n{}\n'.format('*' * 70, msg))
            for atom_id in sorted(atoms):
                outfd.write('{}\n'.format(str(self._atoms[atom_id])))


class linux_xwindows(linux_pslist.linux_pslist):
    """Lists the windows known to each X server process"""

    xwindows_classes = {
        'ScreenInfo' : ScreenInfo,
        'ScreenPtr'  : ScreenPtr,
        'WindowPtr'  : WindowPtr,
        'WindowOpt'  : WindowOpt,
        'Property'   : Property,
        'AtomNode'   : AtomNode
    }

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID',
                                short_option='p',
                                default=None,
                                help='PIDs to analyse (comma separated)',
                                action='store',
                                type='str'
                                )
        self._config.add_option('ATOMS',
                                default=False,
                                help='Dump the Atom Table',
                                action='store_true',
                                dest='dump_atoms'
                                )

    def seek_screen_info(self, task, proc_maps):
    
        _screen_info = None
    
        debug.info("Seeking screenInfo. (This can take a while!)")
        bss_start = -1
        for proc_map in proc_maps:
            (fname, major, minor, ino, pgoff) = proc_map.info(task)
            if fname.endswith('/{0}'.format(str(task.comm))) and str(proc_map.vm_flags) == 'rw-':
                bss_start = proc_map.vm_end
            elif fname.endswith('/{0}'.format('Xorg')) and str(proc_map.vm_flags) == 'rw-':
                # This is because in some cases,e.g. OpenSUSE Leap 42.3, the process is called 'X' but the mapped binary is 'Xorg'
                bss_start = proc_map.vm_end
            elif str(proc_map.vm_flags) == 'rw-' and proc_map.vm_start == bss_start:
                debug.info('Anonymous section (BSS): {} {:#x} {:#x}'.format(str(proc_map.vm_flags), proc_map.vm_start, proc_map.vm_end))
                offset = 0
                while bss_start < proc_map.vm_end:
                    if self._current_vm.is_valid_address(bss_start+offset):
                        screen_info = obj.Object('ScreenInfo', vm=task.get_process_address_space(), offset=bss_start+offset)
                        if self.is_screen_info_sane(screen_info):
                            debug.info(screen_info)
                            return screen_info
                    offset += 8
    
    def is_screen_info_sane(self, screen_info):
        """Validate a candidate screenInfo struct"""
    
        if screen_info.numScreens < 1 or screen_info.numScreens > 16:
            return False
        
        if screen_info.x < 0 or screen_info.x > 10000:
            return False
        
        if screen_info.y < 0 or screen_info.y > 10000:
            return False
        
        if screen_info.width < 640 or screen_info.width > 10000:
            return False
        
        if screen_info.height < 480 or screen_info.height > 10000:
            return False
        
        if not self._current_vm.is_valid_address(screen_info.screens[0]):
            return False
        
        if not self._current_vm.is_valid_address(screen_info.screens[0].dereference().root):
            return False
        
        root_window = screen_info.screens[0].dereference().root.dereference()
        if root_window.drawable.x != 0 or root_window.drawable.y != 0 or root_window.parent != 0:
            return False
        
        return True
    
    def seek_atom_root(self, task, proc_maps):
    
        _atom_root = None
        
        debug.info("Seeking atomRoot.")
        
        for proc_map in proc_maps:
            (fname, major, minor, ino, pgoff) = proc_map.info(task)
            if fname == '[heap]':
                debug.info('Heap: {} {:#x} {:#x}'.format(str(proc_map.vm_flags), proc_map.vm_start, proc_map.vm_end))
                offset = proc_map.vm_start
                while offset < proc_map.vm_end:
                    if self._current_vm.is_valid_address(offset):
                        atom_root = obj.Object('AtomNode', vm=self._current_vm, offset=offset)
                        if self.is_atom_root_sane(atom_root):
                            debug.info(atom_root)
                            return atom_root
                    offset += 8

        return None

    def is_atom_root_sane(self, atom_root):
    
        if not self._current_vm.is_valid_address(atom_root.string):
            return False
        
        return atom_root.a == 0x01 and str(atom_root.string.dereference()) == 'PRIMARY'

    def lookup_atom(self, atom_id):
        """Get an Atom's string from its ID"""
    
        atom_id = int(atom_id)
        if atom_id in self._atoms:
            return str(self._atoms[atom_id].string.dereference())
        else:
            return "<Unknown>"

    def visit_atomNode(self, atomNode):
    
        if atomNode.v() in self._seen_atoms:
            debug.info('Atom referenced more than once! Offset {:#x}.'.format(atomNode.v()))
        else:
            self._atoms[int(atomNode.a)] = atomNode
            self._seen_atoms.add(atomNode.v())
        
        if atomNode.left and self._current_vm.is_valid_address(atomNode.left):
            self.visit_atomNode(atomNode.left.dereference())
        
        if atomNode.right and self._current_vm.is_valid_address(atomNode.right):
            self.visit_atomNode(atomNode.right.dereference())
    
    def parse_screenInfo(self, screen_info):
    
        debug.info('Parsing the {} ScreenPtr structure(s).'.format(screen_info.numScreens))
        for screen_ptr in screen_info.screens:
            if screen_ptr and self._current_vm.is_valid_address(screen_ptr):
                screen = screen_ptr.dereference()
                debug.info(screen)
                debug.info('Parsing the windows.')
                if self._current_vm.is_valid_address(screen.root):
                    self.visit_window(screen.myNum, screen.root.dereference())

    def visit_window(self, screen_id, win):
        
        if win.v() in self._seen_windows:
            debug.info('Window referenced more than once! Offset {:#x}. (Skipped)'.format(win.v()))
        else:
            self._windows.append((screen_id, win))
            self._seen_windows.add(win.v())

        if win.firstChild and self._current_vm.is_valid_address(win.firstChild):
            self.visit_window(screen_id, win.firstChild.dereference())
        
        if win.nextSib and self._current_vm.is_valid_address(win.nextSib):
            self.visit_window(screen_id, win.nextSib.dereference())
    
    def visit_property(self, prop, outfd):
    
        for atom_id in self._atoms:
            if prop.propertyName == atom_id:
                
                prop_name = str(self._atoms[atom_id].string.dereference())
                prop_type = int(prop.type)
                
                type_atom = self.lookup_atom(prop.type)
                
                outfd.write('{}\n'.format('~' * 50))
                outfd.write('{}({}): {}\n'.format(prop_name, type_atom, str(prop)))
                
                d = prop.read_data(self._current_vm, type_atom)
                if d:
                    if isinstance(d, str):
                        outfd.write('{}{}'.format(d, '' if d.endswith('\n') else '\n'))
                    elif isinstance(d, int):
                        outfd.write('{}\n'.format(d))
        
        if prop.next_ and self._current_vm.is_valid_address(prop.next_):
            self.visit_property(prop.next_.dereference(), outfd)

    def calculate(self):
        
        addr_space = utils.load_as(self._config)
        
        # Check the profile: we only support 64-bit Linux
        meta = addr_space.profile.metadata
        if not (meta['os'] == 'linux' and meta['memory_model'] == '64bit'):
            debug.error('Sorry, currently only 64-bit Linux is supported.')

        # Apply the correct vtypes for the profile
        addr_space.profile.object_classes.update(linux_xwindows.xwindows_classes)
        addr_space.profile.vtypes.update(xwindows_vtypes_x64)
        addr_space.profile.compile()

        # Build a list of tasks
        tasks = linux_pslist.linux_pslist.calculate(self)
        if self._config.PID:
            pids = [int(p) for p in self._config.PID.split(',')]
            the_tasks = [t for t in tasks if t.pid in pids]
        else:
            # Find the X Windows task
            the_tasks = []
            for task in tasks:
                task_offset, dtb, ppid, uid, gid, start_time = self._get_task_vals(task)
                task_name = str(task.comm)
                task_pid = int(task.pid)
                if task_name == 'X' or task_name == 'Xorg':
                    the_tasks.append(task)

        # In case no appropriate processes are found
        if len(the_tasks) < 1:
            return

        for task in the_tasks:

            # These need to be here so that they're reset for each X/Xorg process.
            self._windows = []  # Stores a list of WindowPtr objects; one for each window found
            self._seen_windows = set()  # Holds a list of window offsets for avoiding circular referencing
            self._atoms = {}  # Stores a dictionary of AtomNode objects, indexed by atom id
            self._seen_atoms = set()  # Holds a list of atom offsets for avoiding circular referencing
            self._current_vm = task.get_process_address_space()

            msg = 'Working with \'{0}\' (pid={1}).'.format(str(task.comm), task.pid)
            debug.info(msg)
            proc_maps = task.get_proc_maps()
            screen_info = self.seek_screen_info(task, proc_maps)
            atom_root = self.seek_atom_root(task, proc_maps)
            if atom_root:
                self.visit_atomNode(atom_root)
            debug.info('Found {:,} atom(s).'.format(len(self._atoms)))
            self.parse_screenInfo(screen_info)
            debug.info('Found {:,} window(s).'.format(len(self._windows)))
            yield msg, self._windows

    # This function never seems to get called??
    # def generator(self, data):
    #    pass

    def render_text(self, outfd, data):
    
        for msg, screen_windows in data: # Iterate the windows/atoms for each X process

            outfd.write('{}\n{}\n'.format('*' * 70, msg))
        
            if self._config.dump_atoms:
                for atom_id in sorted(self._atoms):
                    outfd.write('{}\n'.format(str(self._atoms[atom_id])))
                outfd.write('{}\n'.format('+' * 60))
        
            for screen_id, win in screen_windows:
                outfd.write('{}\n'.format('=' * 60))
                outfd.write('{} on Screen {}\n'.format(str(win), screen_id))
                
                self.visit_property(win.optional.dereference().userProps.dereference(), outfd)
