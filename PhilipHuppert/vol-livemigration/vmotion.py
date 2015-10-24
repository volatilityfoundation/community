#!/usr/bin/env python2.7
# coding=utf-8

"""Volatility address space to access VM memory contents in VMotion live migration traffic."""

import volatility.addrspace as addrspace
import volatility.debug as debug
import struct
from time import time

__author__ = "Philip Huppert"
__copyright__ = "Copyright 2015, Philip Huppert"
__license__ = "MIT"


# header related constants
VMOTION_MAGIC = "\0\0\0\0\x03\0\x05\0"
HEADER_LENGTH = 0x54

# iteration marker related constants
LAST_ITERATION_MARKER = 1
LAST_ITERATION_MARKER_LENGTH = 15

NEXT_ITERATION_MARKER = 2
NEXT_ITERATION_MARKER_LENGTH = 15

# bundle & page related contsants
BUNDLE_MARKER = 0
LAST_BUNDLE_MARKER = 1
BUNDLE_MARKERS = {BUNDLE_MARKER, LAST_BUNDLE_MARKER}
BUNDLE_MAGIC = 0x00000e04

PAGE_SIZE = 4096
PAGE_BITS = 0xFFF

PAGE_COUNT_MIN = 0
PAGE_COUNT_MAX = 128

PAGE_TYPES_WITH_CONTENTS = {1, 4}
VALID_PAGETYPES = {(0, 8), (1, 8), (2, 0), (4, 4), (4, 5), (4, 7)}

# legacy VGA related constants
#
# https://github.com/volatilityfoundation/volatility/issues/223
#
# VMs contain a legacy VGA memory hole from 0xa0000 (incl) to 0xc0000 (excl).
# In Volatility 2.4 some profiles, mostly Windows, can't deal with this and
# expect the first 10M of memory to be read()-able. Therefore, reading of
# the hole will be done with zread().
#
# This bug is fixed in the current master branch. In this case, the fix
# can be disabled to improve read() performance.
#
ENABLE_VGA_ZREAD_FIX = True
VGA_START = 0xa0000
VGA_END = 0xc0000


class AdvancingReader(object):
    """Utility class to read memory like a file."""

    def __init__(self, aspace):
        self.offset = 0
        self.addrspace = aspace

    def skip(self, length):
        self.offset += length

    def read(self, length):
        data = self.read_maybe(length)
        assert len(data) == length
        return data

    def read_maybe(self, length):
        data = self.addrspace.read(self.offset, length)
        if data is None:
            data = ""
        self.offset += len(data)
        return data

    def unpack(self, fmt):
        s = struct.calcsize(fmt)
        data = self.read(s)
        return struct.unpack(fmt, data)


class VMotionMigrationAddressSpace(addrspace.AbstractDiscreteAllocMemory):
    """Address space to access memory from VMotion (ESXi 6) live migration traffic."""

    def __init__(self, base, config, *args, **kwargs):
        c_start = time()
        self.as_assert(base, "VMotionMigration requires a base")

        addrspace.AbstractDiscreteAllocMemory.__init__(self, base, config, *args, **kwargs)

        # test for magic value
        magic = base.read(0, len(VMOTION_MAGIC))
        self.as_assert(magic == VMOTION_MAGIC, "VMotion migration magic not found")
        debug.debug("VMotion migration magic found")

        # migration statistics
        self._skipped_pages = 0
        self._transferred_pages = 0
        self._retransmitted_pages = 0
        self._iterations = 0

        # page start addr (VM physical) -> page start addr (offset into migration data)
        self._pages = {}
        # parse migration data
        self._parse_migration()

        c_end = time()
        debug.debug("VMotionMigration constructor took %f seconds to run" % (c_end - c_start))

    def write(self, _addr, _buf):
        raise Exception("write() not implemented")

    def read(self, addr, length):
        if ENABLE_VGA_ZREAD_FIX and (
                                VGA_START <= addr < VGA_END or
                                VGA_START <= addr + length < VGA_END or
                                (addr < VGA_START and VGA_END <= addr + length)):
            debug.debug("Redirecting read(%#x, %d) to zread" % (addr, length), level=2)
            return self.zread(addr, length)

        return super(VMotionMigrationAddressSpace, self).read(addr, length)

    def translate(self, vaddr):
        # map vaddr to offset in file using self._pages

        page_start_addr = vaddr & ~PAGE_BITS
        page_local_addr = vaddr & PAGE_BITS

        page_file_offset = self._pages.get(page_start_addr)
        if page_file_offset is None:
            return None

        return page_file_offset + page_local_addr

    def get_available_allocs(self):
        # generate available memory chunks from self._pages
        for addr in sorted(self._pages.keys()):
            yield addr, PAGE_SIZE

    def get_available_addresses(self):
        # generate all available, non-overlapping, non-continuous memory regions
        start = 0
        end = 0
        for (addr, _) in self.get_available_allocs():
            if addr == end:
                # keep collecting continuous memory
                end += PAGE_SIZE
            else:
                # yield address range when a memory region ends
                yield (start, end - start)

                # start collecting the next region
                start = addr
                end = start + PAGE_SIZE

        # yield the last region
        yield (start, end - start)

    def _parse_migration(self):
        # use AdvancingReader to treat the base AS like a file
        r = AdvancingReader(self.base)

        # skip header
        r.skip(HEADER_LENGTH)

        # read page bundles
        last_bundle = False
        last_iteration = False
        self._iterations += 1

        while not last_bundle:
            # determine bundle/marker type
            bundle_start = r.offset
            bundle_type, = r.unpack("<B")

            # handle next iteration marker
            if bundle_type == NEXT_ITERATION_MARKER:
                debug.debug("Skipping next iteration marker @ %#x" % r.offset)
                r.skip(NEXT_ITERATION_MARKER_LENGTH)
                self._iterations += 1
                continue

            # handle last iteration marker (only occurs once)
            elif bundle_type == LAST_ITERATION_MARKER and not last_iteration:
                debug.debug("Skipping last iteration marker @ %#x" % r.offset)
                r.skip(LAST_ITERATION_MARKER_LENGTH)
                self._iterations += 1

                # this flag is used to only parse this marker exactly once
                # the very last bundle also starts with a 0x1 byte
                # setting this flag prevents the parser from confusing the two structures
                last_iteration = True

                continue

            # verify bundle type
            self.as_assert(bundle_type in BUNDLE_MARKERS, "Invalid bundle_type: %d @ %#x" % (bundle_type, bundle_start))
            last_bundle = bundle_type == LAST_BUNDLE_MARKER

            # parse and verify bundle header
            # uint32 magic; uint8 reserved[11]; uint32 pageCount;
            magic, page_count = r.unpack("<I11xI")
            self.as_assert(magic == BUNDLE_MAGIC, "Invalid page bundle magic: %#x @ %#x" % (magic, bundle_start))
            self.as_assert(PAGE_COUNT_MIN <= page_count <= PAGE_COUNT_MAX,
                           "Invalid page_count: %d @ %#x" % (page_count, bundle_start))

            debug.debug("Page bundle with %d entries @ %#x" % (page_count, bundle_start))

            # parse array of page numbers
            # uint32 pageNumbers[128];
            page_numbers = r.unpack("<128I")
            # discard unpopulated array entries
            page_numbers = page_numbers[:page_count]

            # parse array of page metadata
            # pageMeta pageMetadata[128];
            # struct pageMeta {uint32 iteration; uint32 pageGroup; uint32 pageTypeA; uint64 pointer; uint32 pageTypeB;};
            page_metadata = r.unpack("<" + ("IIIQI" * 128))
            # discard unpopulated array entries
            page_metadata = page_metadata[:page_count * 5]

            # extract page types from page metadata
            page_types_a = page_metadata[2::5]
            page_types_b = page_metadata[4::5]

            # validate page types
            for x in zip(page_types_a, page_types_b):
                self.as_assert(x in VALID_PAGETYPES, "Unknown page type: %s @ %#x" % (x, bundle_start))

            # all information in the bundle header has been read
            # r.offset now points to page contents

            # populate _pages dictionary
            cnt = 0
            for i in xrange(page_count):
                # page contents are only transmitted for some types of pages
                if page_types_a[i] in PAGE_TYPES_WITH_CONTENTS:
                    # starting address of the page (VM physical)
                    page_addr = page_numbers[i] * PAGE_SIZE

                    # collect stats
                    cnt += 1
                    self._transferred_pages += 1
                    if page_addr in self._pages:
                        self._retransmitted_pages += 1

                    # store/overwrite translation mapping
                    self._pages[page_addr] = r.offset

                    # move r.offset to the next page
                    r.skip(PAGE_SIZE)
                else:
                    self._skipped_pages += 1

            debug.debug("Page bundle contained contents of %d pages @ %#x" % (cnt, bundle_start))

        def mb(pages):
            return (pages * PAGE_SIZE) >> 20

        report = ["%d pages (%dM) extracted from migration" % (len(self._pages), mb(len(self._pages))),
                  "%d (%dM) transferred" % (self._transferred_pages, mb(self._transferred_pages)),
                  "%d (%dM) retransmitted" % (self._retransmitted_pages, mb(self._retransmitted_pages)),
                  "%d iterations" % self._iterations]
        debug.info("; ".join(report))
