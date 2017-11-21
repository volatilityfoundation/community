#    Copyright (c) 2017, Frank Block, ERNW GmbH <fblock@ernw.de>

"""Gathers all issued commands for zsh."""

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.heap_analysis as heap_analysis
import volatility.obj as obj
import volatility.debug as debug



class linux_zsh(heap_analysis.HeapAnalysis):
    """Extracts the zsh command history, similar to the existing bash plugin.
    """

    def calculate(self):
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        for task in tasks:
            if self.init_for_task(task):

                if self.profile.metadata.get('memory_model') == '64bit':
                    self.profile.vtypes.update(ZshProfile64().zshprofile)

                else:
                    # default/fallback profile
                    self.profile.vtypes.update(ZshProfile32().zshprofile)

                self.profile.compile()

                chunks_dict = dict()
                chunk_data_pointers = list()
                chunk_size = self.get_aligned_size(
                    self.profile.get_obj_size('histent'))
                data_offset = self.profile.get_obj_offset("malloc_chunk", "fd")

                for chunk in self.get_all_allocated_chunks():
                    chunks_dict[chunk.v() + data_offset] = chunk
                    chunk_data_pointers.append(chunk.v() + data_offset)

                commands_dict = dict()

                valid_histentry = None

                # we first try to find a chunk that most probably contains a
                # histent struct
                for chunk in self.get_all_allocated_chunks():

                    if not chunk.chunksize() == chunk_size:
                        continue

                    histent = obj.Object('histent',
                                         offset=chunk.v()+data_offset,
                                         vm=self.process_as)

                    # we test if the current histent struct seems to be valid
                    # first test: do we know the chunks where relevant
                    # pointers point to
                    pointers = [histent.node.nam.v(),
                                histent.down.v(),
                                histent.up.v()]
                    if not len(set(pointers) & set(chunk_data_pointers)) \
                            == len(pointers):
                        continue

                    # second test: points the previous/next histent entry to
                    # this histent entry?
                    if not histent.up.down == histent or not histent.down.up \
                            == histent:
                        continue

                    # we hopefully found one
                    valid_histentry = histent
                    break

                if valid_histentry:
                    debug.debug(
                        "We probably found a valid histent chunk and now "
                        "start walking.")

                    # entries are linked circular so walking in one direction
                    # should be sufficient
                    for histent in heap_analysis.iterate_through_linked_list(
                            valid_histentry, lambda x: x.down):

                        command = ''

                        try:
                            command = chunks_dict[histent.node.nam.v()]
                            command = command.to_string()
                            command = command[:command.index("\x00")]

                        except KeyError:
                            debug.warning(
                                "Unexpected error: chunk for given "
                                "command-reference does not seem to exist.")

                        except ValueError:
                            pass

                        if histent.stim == histent.ftim == 0 and command == '':
                            histent_vma = heap_analysis.get_vma_for_offset(
                                self.vmas, histent.v())

                            if histent_vma not in self.heap_vmas:
                                # we most probably found the "curline" histent
                                # struct located in zsh's .bss section. as it
                                # doesn't contain an actual executed command,
                                # we are skipping it
                                continue

                        command_number = histent.histnum
                        start = obj.Object('UnixTimeStamp',
                                           offset=histent.stim.obj_offset,
                                           vm=self.process_as)
                        end = obj.Object('UnixTimeStamp',
                                         offset=histent.stim.obj_offset,
                                         vm=self.process_as)

                        commands_dict[command_number] = [start,
                                                         end,
                                                         repr(command)]


                for key, value in sorted(commands_dict.items()):
                    yield (task.pid, key, value[0], value[1], value[2])


    def render_text(self, outfd, data):
        self.table_header(outfd, [
            ("pid", "6"),
            ("counter", "6"),
            ("started", "22"),
            ("ended", "22"),
            ("command", "")
        ])

        for entry in data:
            self.table_row(outfd, entry[0],entry[1],entry[2],entry[3],entry[4])


class ZshProfile32():
    """Profile to parse internal zsh data structures."""

    __abstract = True

    # types come from zsh's zsh.h
    zsh_vtype_32 = {
        "histent": [48, {
            "down": [16, ["pointer", ["histent"]]],
            "ftim": [28, ["long"]],
            "histnum": [40, ["long long"]],
            "node": [0, ["hashnode"]],
            "nwords": [36, ["int"]],
            "stim": [24, ["long"]],
            "up": [12, ["pointer", ["histent"]]],
            "words": [32, ["pointer", ["short"]]],
            "zle_text": [20, ["pointer", ["char"]]]
        }],
        "hashnode": [12, {
            "flags": [8, ["int"]],
            "nam": [4, ["pointer", ["char"]]],
            "next": [0, ["pointer", ["hashnode"]]]
        }]
    }

    def __init__(self, version=None, **kwargs):

        # only one version is supported currently, so we always use the same
        # vtypes
        self.zshprofile = self.zsh_vtype_32



class ZshProfile64():
    """Profile to parse internal zsh data structures."""

    __abstract = True

    # types come from zsh's zsh.h
    zsh_vtype_64 = {
        "histent": [88, {
            "down": [32, ["pointer", ["histent"]]],
            "ftim": [56, ["long"]],
            "histnum": [80, ["long"]],
            "node": [0, ["hashnode"]],
            "nwords": [72, ["int"]],
            "stim": [48, ["long"]],
            "up": [24, ["pointer", ["histent"]]],
            "words": [64, ["pointer", ["short"]]],
            "zle_text": [40, ["pointer", ["char"]]]
        }],
        "hashnode": [24, {
            "flags": [16, ["int"]],
            "nam": [8, ["pointer", ["char"]]],
            "next": [0, ["pointer", ["hashnode"]]]
        }]
    }

    def __init__(self, version=None, **kwargs):

        # only one version is supported currently, so we always use the same
        # vtypes
        self.zshprofile = self.zsh_vtype_64
