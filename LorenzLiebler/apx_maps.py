
# Approxis Memory Carving - apx_maps
#
# Large portions of this file have been adopted from the
# original proc_maps implementation of Andrew Case.
#

"""
@author:       Lorenz Liebler
@contact:      lorenz.liebler@h-da.de
"""

PAGE_SIZE = 4096 

import operator
import volatility.obj as obj
import volatility.utils as utils

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address


class matched_set():
    def __init__(self):
      self.elements = {}

    def do_sort(self):
      self.elements = sorted(self.elements.items(), key=operator.itemgetter(1), reverse=True)

    def insert(self, result):
      #result.start = None
      #result.end   = None
      count = self.elements.get(result.fname, None)
      if count is None:
        self.elements[result.fname] = result.len
      else:
        self.elements[result.fname] = count+result.len

    def __repr__(self):
      return(str(self.elements))

class tree_node():
    """ Simple search structure for carved ranges """

    def __init__(self, s, e, n):
      self.start = s
      self.end   = e
      self.len   = self.end - self.start
      self.fname = n

    def is_in_range(self, value):
      global PAGE_SIZE
      return (self.start <= value and value <= self.end+PAGE_SIZE)

    def is_smaller(self,value):
      return value < self.start

    def __repr__(self):
      return str((self.start,self.end,self.fname))



class linux_apx_maps(linux_pslist.linux_pslist):
    """Gathers process memory maps"""

    def __init__(self, config, *args, **kwargs):
      linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
      self._config.add_option('APXLOGS',  short_option = 'L', default = None, help = 'file (path) to approxis log', action = 'store', type = 'str')


    def bin_search(self, sorted_list, start_range):
      first = 0
      last = len(sorted_list) - 1
      while first <= last:
        mid = (first + last) // 2
        if sorted_list[mid].is_in_range(start_range):
          return sorted_list[mid]
        else:
          if sorted_list[mid].is_smaller(start_range):
            #print("last")
            last = mid - 1
          else:
            first = mid + 1
            #print("first")
        #print((first,last))
      return False


    def read_logs(self):
      self.comp_list = []

      log_lines = open(self._config.APXLOGS).readlines()
      last_start, last_end, last_fname = None, None, None
      for ll in log_lines:
        start_end, fname = ll.split("|")
        start, end       = map(int, start_end.split("-"))

        fname = fname.replace("\n","")

        if last_fname == fname and last_end == start:
          # Overlapping sequences
          last_end = end
        else:
          if last_start is not None:
            self.comp_list.append(tree_node(last_start,last_end, last_fname))
          last_fname = fname
          last_start = start
          last_end   = end

      #self.comp_list.append(tree_node(last_start, last_end, last_fname))
      #print(" - read in  "+str(len(log_lines)))
      #print(" - read out "+str(len(self.comp_list)))
      #print(self.comp_list)
      #print(" - - - - - - - - - - - ")
      #search = self.bin_search(self.comp_list,2146554194)
      #print(search)
      #if search:
      #  print("found")
      #print(" - - - - - - - - - - - ")
      #search = self.bin_search(self.comp_list,2146554195)
      #print(search)
      #if search:
      #  print("found")
      #exit()


    def calculate(self):
        global PAGE_SIZE
        self.read_logs()
        linux_common.set_plugin_members(self)
        tasks = linux_pslist.linux_pslist.calculate(self)
        phys_addr_space = utils.load_as(self._config, astype = 'physical')

        for task in tasks:
            if task.mm:
                for vma in task.get_proc_maps():
                  (fname, major, minor, ino, pgoff) = vma.info(task)
                  t_start, t_end = vma.vm_start, vma.vm_end
                  cur_start, cur_end = None, None
                  p_res, p_all = 0, 0
                  file_offset_start, file_offset_end = 0x0, 0x0
                  proc_as = task.get_process_address_space()

                  # ##########################################################
                  # Ooutput vectors and running parameters
                  vma_one_hot = ""
                  vma_trans_offsets = []
                  vma_trans_range = []
                  vma_to_file = []
                  matched_files = matched_set()

                  # ##########################################################
                  # We process the ranges on page-size
                  while t_start < t_end:
                    p_all += 1
                    temp = proc_as.translate(t_start)
                    if temp != None:
                      p_res += 1
                      temp_file = proc_as.base.translate(temp)
                      vma_trans_offsets.append((t_start,temp,temp_file))
                      vma_to_file.append(temp_file)
                      vma_one_hot += "1"
                      
                      result = self.bin_search(self.comp_list,temp_file)
                      if result:
                        matched_files.insert(result)

                      # First Start
                      if cur_start == None:
                        cur_start = temp
                        cur_end = temp
                      else:
                        cur_end = temp
                    else:
                      vma_one_hot += "0"
                      if cur_start != None:
                        vma_trans_range.append((cur_start,cur_end))
                        cur_start, cur_end = None, None
                    t_start += PAGE_SIZE

                  if cur_start != None:
                    vma_trans_range.append((cur_start,cur_end))
                  
                  vma_file = {}
                  matched_files.do_sort()
                  vma_file["FOffsets"] = str(matched_files)
                  vma_file["PAllocs"]  = str(p_res)+"/"+str(p_all)
                  yield task, vma, vma_file


    def unified_output(self, data):
        return TreeGrid([("Offset",Address),
                        ("Pid", int),
                         ("Name",str),
                       ("Start", Address),
                       ("End", Address),
                       ("Flags", str),
                       ("Pgoff", Address),
                       ("Major", int),
                       ("Minor", int),
                       ("Inode", int),
                       ("Path", str),
                       ("PAllocs", str),
                       ("FOffsets", str)],
                        self.generator(data))

    def generator(self, data):
        for task, vma, vma_file in data:
            (fname, major, minor, ino, pgoff) = vma.info(task)
            yield (0, [Address(task.obj_offset),
                       int(task.pid),
                       str(task.comm),
                Address(vma.vm_start),
                Address(vma.vm_end),
                str(vma.vm_flags),
                Address(pgoff),
                int(major),
                int(minor),
                int(ino),
                str(fname),
                str(vma_file["PAllocs"]),
                str(vma_file["FOffsets"])])


    def render_text(self, outfd, data):
        self.table_header(outfd, [
          #("Offset","#018x"),
                                  ("Pid", "8"),
                                  ("Name","20"),
                                  ("Start", "#010x"),
                                  ("End",   "#010x"),
                                  #("Flags", "6"),
                                  #("Pgoff", "[addr]"),
                                  #("Major", "6"),
                                  #("Minor", "6"),
                                  #("Inode", "10"),
                                  ("File Path", "80"),
                                  ("PAllocs", "10"),
                                  ("FOffsets", ""),                    
                                 ]) 

        for task, vma, vma_file in data:
          (fname, major, minor, ino, pgoff) = vma.info(task)
          if not vma_file["PAllocs"].startswith("0/"):
            self.table_row(outfd, 
                #task.obj_offset,
                task.pid,
                task.comm,
                vma.vm_start,
                vma.vm_end,
                #str(vma.vm_flags),
                #pgoff,
                #major,
                #minor,
                #ino,
                fname,
                str(vma_file["PAllocs"]),
                str(vma_file["FOffsets"]))
        for task, vma, vma_file in data:
          (fname, major, minor, ino, pgoff) = vma.info(task)
          if vma_file["PAllocs"].startswith("0/"):
            self.table_row(outfd, 
                #task.obj_offset,
                task.pid,
                task.comm,
                vma.vm_start,
                vma.vm_end,
                #str(vma.vm_flags),
                #pgoff,
                #major,
                #minor,
                #ino,
                fname,
                str(vma_file["PAllocs"]),
                str(vma_file["FOffsets"]))
