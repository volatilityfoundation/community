#!/usr/bin/env python
# coding=utf-8

"""Volatility plugin to extract base64/PEM encoded private RSA keys from
physical memory.

"""

import volatility.plugins.common as common
import volatility.utils as utils

START_MARKER = "-----BEGIN RSA PRIVATE KEY-----"
END_MARKER = "-----END RSA PRIVATE KEY-----"
CHUNK_SIZE = 10240

__author__ = "Philip Huppert"
__copyright__ = "Copyright 2014, Philip Huppert"
__license__ = "MIT"


class RSAKey(common.AbstractWindowsCommand):
    """Extract base64/PEM encoded private RSA keys from physical memory."""

    def calculate(self):
        """Search for PEM encoded RSA keys."""

        # Load physical memory address space
        mem = utils.load_as(self._config, astype="physical")

        # Verify that the address space consists of one large block
        addrs = list(mem.get_available_addresses())
        assert len(addrs) == 1, "Physical memory is fragmented"

        # Determine size of memory
        mem_start, mem_size = addrs[0]

        # Read the physical memory in chunks
        for offset in xrange(0, mem_size, CHUNK_SIZE):
            chunk = mem.zread(offset, CHUNK_SIZE)

            # Search for private key markers in the current chunk

            # This might miss a key if it crosses a chunk boundary.
            # To keep the implementation simple, this issue is not
            # fixed (yet).
            if START_MARKER in chunk and END_MARKER in chunk:
                key = []
                in_key = False

                # Treat the chunk as a string and iterate over each
                # line to extract the key
                for line in chunk.splitlines():
                    if START_MARKER in line and not in_key:
                        in_key = True
                        key.append(line)
                    elif END_MARKER in line and in_key:
                        in_key = False
                        key.append(line)
                    elif in_key:
                        key.append(line)

                if len(key) != 0:
                    yield "\n".join(key)

    def render_text(self, outfd, data):
        """Display found keys."""

        for key in data:
            outfd.writeln(key)
