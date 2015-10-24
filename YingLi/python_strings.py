"""
Plugin to find python strings within process heaps.
"""
import os
import re
import struct

from itertools import groupby

from volatility import debug as debug
from volatility import obj as obj
from volatility.plugins.linux import common as linux_common
from volatility.plugins.linux import pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility import utils


# Note: It doesn't actually matter if Py_TRACE_REF is defined, that just means
# there are more structures at the beginning, which we don't care about
pyobjs_vtype_64 = {
    '_PyStringObject': [
        37,
        {
            'ob_refcnt': [0, ['long long']],  # Py_ssize_t = ssize_t
            'ob_type': [8, ['pointer', ['void']]],  # struct _typeobject *
            'ob_size': [16, ['long long']],  # Py_ssize_t = ssize_t
            'ob_shash': [24, ['long long']],
            'ob_sstate': [32, ['Enumeration',
                               dict(target='int', choices={
                                   0: 'SSTATE_NOT_INTERNED',
                                   1: 'SSTATE_INTERNED_MORTAL',
                                   2: 'SSTATE_INTERNED_IMMORTAL'
                               })]],
            'ob_sval': [36, ['array', 1, ['char']]]
        }],
    '_PyDictEntry': [
        24,
        {
            'me_hash': [0, ['long long']],  # Py_ssize_t = ssize_t
            'me_key': [8, ['pointer', ['_PyStringObject']]],
            'me_value': [16, ['pointer', ['_PyStringObject']]]
        }]
    }


class _PyStringObject(obj.CType):
    r"""
    A class for python string objects.

    ----
    stringobject.h
    ----

    typedef struct {
        PyObject_VAR_HEAD
        long ob_shash;
        int ob_sstate;
        char ob_sval[1];

        /* Invariants:
         *     ob_sval contains space for 'ob_size+1' elements.
         *     ob_sval[ob_size] == 0.
         *     ob_shash is the hash of the string or -1 if not computed yet.
         *     ob_sstate != 0 iff the string object is in stringobject.c's
         *       'interned' dictionary; in this case the two references
         *       from 'interned' to this object are *not counted* in
         *       ob_refcnt.
         */
    } PyStringObject;

    #define SSTATE_NOT_INTERNED 0
    #define SSTATE_INTERNED_MORTAL 1
    #define SSTATE_INTERNED_IMMORTAL 2

    ----
    object.h - note that _PyObject_HEAD_EXTRA is empty if
    Py_TRACE_REFs is not defined
    ----

    /* PyObject_HEAD defines the initial segment of every PyObject. */
    #define PyObject_HEAD                   \
        _PyObject_HEAD_EXTRA                \
        Py_ssize_t ob_refcnt;               \
        struct _typeobject *ob_type;

    #define PyObject_VAR_HEAD               \
        PyObject_HEAD                       \
        Py_ssize_t ob_size; /* Number of items in variable part */

    """
    def is_valid(self):
        """
        Determine whether the Python string struct is valid - an easy way to
        check is to calculate the hash of the string, and see if it matches
        the `ob_shash`.

        On Python 2.7, the hash function used is FNV.

        This assumes that the python version volatility is using matches the
        python version of the memory dump, because it uses the `hash()`
        function to compute the hash.
        """
        ob_sval_offset, _ = self.members['ob_sval']
        string_address = self.obj_offset + ob_sval_offset

        return (
            self.ob_type.is_valid() and
            # skip empty strings and strings that are too big
            self.ob_size > 0 and self.ob_size <= 1e6 and
            # state must be one of the valid states
            self.ob_sstate.v() in self.ob_sstate.choices.keys() and
            # the string should be null-terminated
            self.obj_vm.zread(string_address + self.ob_size, 1) == '\x00' and
            # the hash may not have been computed (-1), but otherwise
            # it should be correct
            (self.ob_shash == -1 or self.ob_shash == hash(self.string)))

    @property
    def string(self):
        """
        Read the string from memory, because `ob_sval` is a
        :class:`volatility.obj.NativeType.Array` object, which is slow to
        iterate through to turn into a string.
        """
        sval_offset, _ = self.members['ob_sval']
        return self.obj_vm.zread(self.obj_offset + sval_offset,
                                 self.ob_size)


class _StringStringPyDictEntry(obj.CType):
    r"""
    ----
    dictobject.h
    ----

    typedef struct {
        Py_ssize_t me_hash;
        PyObject *me_key;
        PyObject *me_value;
    } PyDictEntry;

    ----
    object.h
    ----
    /* Nothing is actually declared to be a PyObject, but every pointer to
     * a Python object can be cast to a PyObject*.  This is inheritance built
     * by hand.  Similarly every pointer to a variable-size Python object can,
     * in addition, be cast to PyVarObject*.
     */
    typedef struct _object {
        PyObject_HEAD
    } PyObject;
    """
    def is_valid(self):
        """
        Determine whether the {Python string key: Python string val}
        PyDictEntry struct is valid.

        Both pointers should be valid, and the hash of the entry should be
        the same as the hash of the key.
        """
        if self.me_key.is_valid() and self.me_value.is_valid():
            key = self.key
            if key.is_valid() and key.ob_shash == self.me_hash:
                return self.value.is_valid()
        return False

    @property
    def key(self):
        return self.me_key.dereference()

    @property
    def value(self):
        return self.me_value.dereference()


class PythonStringTypes(obj.ProfileModification):
    """
    Profile modifications for Python string types.  Only Linux and Mac OS,
    on 64-bit systems, are supported right now.
    """
    conditions = {"os": lambda x: x in ["linux", "mac"],
                  "memory_model": lambda x: x == "64bit"}

    def modification(self, profile):
        """
        Add python string overlays to the profile's vtypes.
        """
        profile.vtypes.update(pyobjs_vtype_64)
        profile.object_classes.update({
            "_PyStringObject": _PyStringObject,
            "_PyDictEntry": _StringStringPyDictEntry
        })


def brute_force_search(addr_space, obj_type_string, start, end, step_size=1):
    """
    Brute-force search an area of memory for a given object type.  Returns
    valid types as a generator.
    """
    offset = start
    while offset < end:
        found_object = obj.Object(obj_type_string,
                                  offset=offset,
                                  vm=addr_space)
        if found_object.is_valid():
            yield found_object
            offset += found_object.size() + found_object.ob_size
        else:
            offset += step_size


def _brute_force_5_strings(addr_space, heaps):
    """
    Search the heaps 5K at a time until 5 strings are found.  Why 5?
    Arbitrary.  Just so long as it's not 1, which may be a false positive.
    """
    bfed_strings = []
    chunk_size = 1024 * 5
    for heap_vma in heaps:
        for chunk_start in xrange(heap_vma.vm_start,
                                  heap_vma.vm_end,
                                  chunk_size):
            bfed_strings.extend(list(brute_force_search(
                addr_space=addr_space,
                obj_type_string="_PyStringObject",
                start=chunk_start,
                end=chunk_start + chunk_size - 1,
                step_size=4)))
            if len(bfed_strings) >= 5:
                return bfed_strings


def find_python_strings(task):
    """
    Attempt to find python strings.  Brute-force search is pretty slow, so we
    are going to optimize a bit.

    The `ob_type` of a PyObjString is a pretty involved struct, so we are not
    searching on that pattern, but all Python strings should point to the
    same type in memory.

    We will brute-force search the heaps only until a couple of strings are
    found.  We want to make sure that they all point to the same type in
    memory.  Once we have a good guess at where that type resides in memory,
    we can search specifically for that address value and use that as a hint
    as to where there might be a PyObjString.

    We want to search the rest of memory though
    """
    addr_space = task.get_process_address_space()
    heaps_and_anon = get_heaps_and_anon(task)
    likely_strings = _brute_force_5_strings(addr_space, heaps_and_anon)
    likely_strings_by_type = {
        pointer: list(strings) for pointer, strings
        in groupby(likely_strings, lambda pystr: pystr.ob_type)
    }

    debug.debug("Found {0} possible str _typeobject pointer(s): {1}".format(
        len(likely_strings_by_type),
        ", ".join([
            "0x{0:012x} ({1})".format(pointer.v(), len(strings))
            for pointer, strings in likely_strings_by_type.iteritems()])))

    memory_model = addr_space.profile.metadata.get('memory_model', '32bit')
    pack_format = "I" if memory_model == '32bit' else "Q"
    offset = addr_space.profile.get_obj_offset("_PyStringObject", "ob_type")

    str_types_as_bytes = [struct.pack(pack_format, pointer.v())
                          for pointer in likely_strings_by_type]

    for address in search_vmas(str_types_as_bytes, heaps_and_anon, task):
        # We will find the likely_strings again, but that's ok
        py_string = obj.Object("_PyStringObject",
                               offset=address - offset,
                               vm=addr_space)
        if py_string.is_valid():
            yield py_string


def search_vmas(s, vmas, task):
    """
    Searches VMAs for lists of strings.
    volatility.plugins.overlays.linux.linux.task_struct.search_process_memory
    could be used, but we want to search more than the heap and less than all
    of process memory.

    This code is mostly copied from there.
    """
    # Allow for some overlap in case objects are
    # right on page boundaries
    overlap = 1024
    scan_blk_sz = 1024 * 1024 * 10

    addr_space = task.get_process_address_space()

    for vma in vmas:
        offset = vma.vm_start
        out_of_range = vma.vm_start + (vma.vm_end - vma.vm_start)
        while offset < out_of_range:
            # Read some data and match it.
            to_read = min(scan_blk_sz + overlap, out_of_range - offset)
            data = addr_space.zread(offset, to_read)
            if not data:
                break
            for x in s:
                for hit in utils.iterfind(data, x):
                    yield offset + hit
            offset += min(to_read, scan_blk_sz)


def get_heaps_and_anon(task):
    """
    Given a task, return the mapped sections corresponding to that task's
    heaps and anonymous mappings (since CPython sometimes mmaps things).
    """
    for vma in task.get_proc_maps():
        if (vma.vm_start <= task.mm.start_brk and vma.vm_end >= task.mm.brk):
            yield vma
        elif vma.vm_name(task) == "Anonymous Mapping":
            yield vma


def _is_python_task(task):
    """
    Return true if this is a python task (as per the executable name, not
    necessarily by task name), false otherwise.
    """
    code_area = [vma for vma in task.get_proc_maps()
                 if (task.mm.start_code >= vma.vm_start and
                 task.mm.end_code <= vma.vm_end)]
    return code_area and 'python' in code_area[0].vm_name(task)


class linux_python_strings(linux_pslist.linux_pslist):
    """
    Pull python strings from a process's heap.
    """
    def __init__(self, config, *args, **kwargs):
        """
        Add a configuration for checking strings, basically a regex to check
        for.
        """
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        self._config.add_option(
            'REGEX', default='None', type='string',
            help='Provide a regex: only return strings that match the regex.')
        self._config.add_option(
            'DUMP-DIR', default='None', type='string',
            help='Output strings to file(s) in this dump directory.')

    def _validate_config(self):
        """
        Check the config values, and converts them to the right value.
        """
        if self._config.REGEX:
            self._config.REGEX = re.compile(self._config.REGEX)

        if (self._config.DUMP_DIR is not None and
                not os.path.isdir(os.path.expanduser(self._config.DUMP_DIR))):
            debug.error(self._config.DUMP_DIR + " is not a directory")
            self._config.DUMP_DIR = None

    def calculate(self):
        """
        Find the tasks that are actually python processes.  May not
        necessarily be called "python", but the executable is python.

        Then find all python strings in that process's heap.
        """
        linux_common.set_plugin_members(self)
        self._validate_config()

        tasks = [task for task in linux_pslist.linux_pslist.calculate(self)
                 if _is_python_task(task)]

        for task in tasks:
            for py_string in find_python_strings(task):
                if (self._config.REGEX is None or
                        self._config.REGEX.match(py_string.string)):
                    yield task, py_string

    def unified_output(self, data):
        """
        Return a TreeGrid with data to print out.
        """
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("Size", int),
                         ("String", str)],
                        self.generator(data))

    def generator(self, data):
        """
        If writing to a file is desired, write to a file.  Also generate data
        that may be formatted for printing.
        """
        files = {}

        for task, py_string in data:
            if self._config.DUMP_DIR is not None:
                filename = "{0}.{1}.strings".format(task.pid, task.comm)
                if task.pid not in files:
                    files[task.pid] = open(os.path.expanduser(os.path.join(
                        self._config.DUMP_DIR, filename)), 'wb')
                files[task.pid].write(repr(py_string.string))
                files[task.pid].write("\n")

            yield (0, [int(task.pid),
                       str(task.comm),
                       int(py_string.ob_size),
                       py_string.string])

        for file_handle in files.values():
            file_handle.close()

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Pid", "15"),
                                  ("Name", "10"),
                                  ("Size", "10"),
                                  ("String", "50")])
        for _, output in self.generator(data):
            self.table_row(outfd, *[str(o) for o in output])


class linux_python_str_dict_entry(linux_pslist.linux_pslist):
    """
    Pull {python-strings: python-string} dictionary entries from a process's
    heap.
    """
    def calculate(self):
        """
        Get all the python strings for a task, and assume those strings
        might be keys of a dictionary entry.  Return the valid dictionary
        entries from that pool of maybes.

        This repeats a lot of linux_python_strings's code, but we want to get
        python strings per task, so we can optimize the bytstring search.
        """
        linux_common.set_plugin_members(self)

        tasks = [task for task in linux_pslist.linux_pslist.calculate(self)
                 if _is_python_task(task)]

        for task in tasks:
            addr_space = task.get_process_address_space()
            memory_model = addr_space.profile.metadata.get('memory_model',
                                                           '32bit')
            pack_format = "I" if memory_model == '32bit' else "Q"

            bytestrings = [
                # the hash as bytes
                struct.pack(pack_format.lower(), py_string.ob_shash) +
                # the pointer the PyStringObject as bytes
                struct.pack(pack_format, py_string.obj_offset)
                for py_string in find_python_strings(task)
            ]

            for address in task.search_process_memory(bytestrings,
                                                      heap_only=True):
                py_dict_entry = obj.Object("_PyDictEntry",
                                           offset=address,
                                           vm=addr_space)
                if py_dict_entry.is_valid():
                    yield task, py_dict_entry

    def unified_output(self, data):
        """
        Return a TreeGrid with data to print out.
        """
        return TreeGrid([("Pid", int),
                         ("Name", str),
                         ("Key", str),
                         ("Value", str)],
                        self.generator(data))

    def generator(self, data):
        """
        Generate data that may be formatted for printing.
        """
        for task, py_dict_entry in data:
            yield (0, [int(task.pid),
                       str(task.comm),
                       py_dict_entry.key.string,
                       py_dict_entry.value.string])
