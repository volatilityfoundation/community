#    Copyright (c) 2017, Frank Block, ERNW GmbH <fblock@ernw.de>

"""Gathers information about password entries for keepassx.
   The retrieved content of those entries comprises the username, title, URL
   and Comment.
"""

import struct
import volatility.plugins.linux.heap_analysis as heap_analysis
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist



class linux_keepassx(heap_analysis.HeapAnalysis):
    """Gathers password entries for keepassx.
    The retrieved content of those entries comprises the username, title, URL
    and Comment."""

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        for task in tasks:
            if self.init_for_task(task):

                chunks_dict = dict()

                data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

                for chunk in self.get_all_allocated_chunks():
                    chunks_dict[chunk.v() + data_offset] = chunk

                if self.profile.metadata.get('memory_model') == '64bit':
                    string_offset = 26
                    relevant_chunk_size = 192
                    pointer_offsets = [16, 24, 32, 64]

                else:
                    string_offset = 18
                    relevant_chunk_size = 96
                    pointer_offsets = [12, 16, 20, 36]

                entry_number = 1

                for chunk in chunks_dict.values():

                    try:
                        # chunks containing refs to password entries typically
                        # have a size of 96 in the tested 32 bit environment
                        if not chunk.chunksize() == relevant_chunk_size:
                            continue

                        p_entry_data = chunk.to_string()

                        field_strings = []

                        # the pointers to title, username and so on are at
                        # these offsets
                        for i in pointer_offsets:
                            if self.profile.metadata.get('memory_model') == '32bit':
                                pointer = struct.unpack('I',
                                                        p_entry_data[i:i+4])[0]
                            else:
                                pointer = struct.unpack('Q',
                                                        p_entry_data[i:i+8])[0]

                            # if there is no chunk for the given pointer, we
                            # most probably have a wrong chunk. this will
                            # throw a KeyError exception and we proceed with
                            # the next chunk
                            curr_chunk_data = chunks_dict[pointer].to_string()

                            string_size = struct.unpack(
                                'I', curr_chunk_data[8:12])[0]

                            string_size *= 2

                            curr_string = curr_chunk_data[
                                string_offset:string_offset+string_size]

                            curr_string = curr_string.decode('utf-16-le')

                            field_strings.append(repr(curr_string))


                        yield (task.pid,
                               entry_number,
                               field_strings[0],
                               field_strings[1],
                               field_strings[2],
                               field_strings[3])

                        entry_number += 1

                    except (KeyError, UnicodeDecodeError):
                        # a password entry struct not containing a pointer to
                        # a chunk => out of scope
                        pass

    def render_text(self, outfd, data):
        self.table_header(outfd, [
            ("pid", "6"),
            ("entry", ""),
            ("title", ""),
            ("url", ""),
            ("username", ""),
            ("comment", "")
        ])

        for entry in data:
            self.table_row(outfd, entry[0],entry[1],entry[2],entry[3],entry[4],entry[5])
