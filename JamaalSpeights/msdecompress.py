import volatility.win32.tasks as tasks
import volatility.plugins.common as common 
import volatility.commands as commands
import volatility.utils as utils
import volatility.scan as scan
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.taskmods as taskmods
import volatility.cache as cache

import re
import tempfile
import os 
from binascii import *
import ctypes
from ctypes import*
import sys
import struct

class MsCarverDecompressor(object):

    """Controls data, options and text formatting"""    
    def __init__(self, config, proc, procspace, pages, outfd, *args, **kwargs):
        self.config = config
        self.proc = proc
        self.procspace = procspace
        self.pages = pages
        self.libpath = os.path.join(os.path.dirname(self.config.MSLIB_PATH),os.path.basename(self.config.MSLIB_PATH))
        self.nt = cdll.LoadLibrary(self.libpath) 
        self.outfd = outfd

    def lznt1(self):

        # // lznt1 uses an interesting method to delimit compressed data
        # // 0xBXXX, with XXX being 0 to F (3 bytes) followed by zero in the next byte.
        # // bitmasks are used to determin data lenth, compression bits etc...
        pattern = re.compile(b"[\x01-\xFF][\xB0-\xBF]")
        pid = str(self.proc.UniqueProcessId)
        for page,size in self.pages:
            pid = str(self.proc.UniqueProcessId)
            fh = tempfile.TemporaryFile()
            fh.write(self.procspace.zread(page,size))
            ofp = fh.tell()
            fh.seek(0,os.SEEK_END)
            fhsize = fh.tell()
            fh.seek(0)
            if fhsize: 
                pagebuff = fh.read()
                fh.close()
                scale = 16
                num_of_bits = 16        
                lastoffset = -1
                offsetlist = []
                nsize = 0
                iscompressed = 0 
                lzntindex  = [m.start() for m in re.finditer(pattern, pagebuff)]
                headerlist = []
                for m in re.finditer(pattern, pagebuff):
                    lzntheader = m.start()
                    if lzntheader+2 <= len(pagebuff):
                        cheader = "0X%04X" % struct.unpack("<H", pagebuff[lzntheader:lzntheader+2])
                        headerint = int(cheader,16)
                        csize =  (int(cheader,16)+3) & 0x0FFF
                        if (headerint >= 0xB001 and headerint <= 0xBFFF) or (headerint >= 0x3000 and headerint <= 0x3FFF):
                            CompressedBuffer = create_string_buffer(pagebuff[lzntheader:lzntheader+csize])
                            CompressedBufferSize = ctypes.c_int(len(CompressedBuffer.raw))
                            UncompressedBuffer = create_string_buffer(0x1000)
                            UnCompressedBufferSize = ctypes.c_int(0x1000)
                            ucdatalen = self.nt.lznt1_uncompressed_size(CompressedBuffer,CompressedBufferSize)
                            lznt1chunkrtn = self.nt.lznt1_decompress_chunk(byref(CompressedBuffer,2),byref(CompressedBuffer,csize),UncompressedBuffer,byref(UncompressedBuffer,UnCompressedBufferSize.value))

                            if lznt1chunkrtn >= 0 and ucdatalen >= 0:
                                tcompressedbuff = pagebuff[lzntheader:lzntheader+csize]
                                tdecompressedbuff = UncompressedBuffer.raw[:csize]
                                minsize = self.config.SET_MINSIZE
                                if tcompressedbuff not in tdecompressedbuff:
                                    if len(CompressedBuffer.raw) > minsize: 
                                        checkheader = headerint & ucdatalen 
                                        checkheader += 1 
                                        if lznt1chunkrtn / 4096 == 1:
                                            if len(headerlist) == 0:
                                                headerlist.append(lzntheader)
                                                headerlist.append(lzntheader+csize)
                                                UncompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(lzntheader) + "_lznt1__UncompressedBuffer.bin"
                                                #outfd.write("")
                                                f = open(os.path.join(self.config.DUMP_DIR, UncompressedFile), 'wb')
                                                f.write(UncompressedBuffer.raw)
                                                #self.outfd.write("Decompressing data at offset: {0} of page {1} for Pid {3} \n".format(hex(lzntheader), hex(page), pid))
                                                self.outfd.write("Decompresing data for PID: {0}, Process: {1}, Page: {2}, Offset: {3}\n".format(pid,self.proc.ImageFileName,hex(page), hex(lzntheader)))
                                                #outfd.write(self.pktstring)
                                                f.close()
                                                if self.config.DUMP_COMPRESSED:
                                                    CompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(lzntheader) + "_lznt1__CompressedBuffer.bin"
                                                    f = open(os.path.join(self.config.DUMP_DIR, CompressedFile), 'wb')
                                                    f.write(CompressedBuffer.raw)
                                                    f.close()
                                            else:
                                                if lzntheader in headerlist:
                                                    headerlist.append(lzntheader+csize)
                                                    headerlist.append(lzntheader+csize)
                                                    headerlist.sort()
                                                    first_lzntheader = headerlist[0]
                                                    UncompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(first_lzntheader) + "_lznt1__UncompressedBuffer.bin"
                                                    f = open(os.path.join(self.config.DUMP_DIR, UncompressedFile), 'ab')
                                                    f.write(UncompressedBuffer.raw)
                                                    f.close()
                                                    if self.config.DUMP_COMPRESSED:
                                                        CompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(first_lzntheader) + "_lznt1__CompressedBuffer.bin"
                                                        f = open(os.path.join(self.config.DUMP_DIR, CompressedFile), 'ab')
                                                        f.write(CompressedBuffer.raw)
                                                        f.close()
                                                else:
                                                    if lzntheader not in headerlist:
                                                        headerlist = []
                                                        #f = open(pid + "_" +hex(page)+"_"+str(lzntheader)+"_lznt1__UncompressedBuffer.bin",'wb')\
                                                        UncompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(lzntheader) + "_lznt1__UncompressedBuffer.bin"
                                                        f = open(os.path.join(self.config.DUMP_DIR, UncompressedFile), 'wb')
                                                        f.write(UncompressedBuffer.raw)
                                                        f.close()
                                                        if self.config.DUMP_COMPRESSED:
                                                            CompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(lzntheader) + "_lznt1__CompressedBuffer.bin"
                                                            f = open(os.path.join(self.config.DUMP_DIR, CompressedFile), 'wb')
                                                            f.write(CompressedBuffer.raw)
                                                            f.close()
                                        else:
                                            if lzntheader in headerlist:
                                                headerlist.append(lzntheader+csize)
                                                headerlist.sort()
                                                first_lzntheader = headerlist[0]
                                                UncompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(first_lzntheader) + "_lznt1__UncompressedBuffer.bin"
                                                f = open(os.path.join(self.config.DUMP_DIR, UncompressedFile), 'ab')
                                                f.write(UncompressedBuffer.raw)
                                                f.close()
                                                if self.config.DUMP_COMPRESSED:
                                                    CompressedFile = pid + "_" + self.proc.ImageFileName + "_" + hex(page) + "_" + hex(first_lzntheader) + "_lznt1__CompressedBuffer.bin"
                                                    f = open(os.path.join(self.config.DUMP_DIR, CompressedFile), 'ab')
                                                    f.write(CompressedBuffer.raw)
                                                    f.close()


class MsCarveDisplayControl(object):
    """Controls data, options and text formatting"""    
    def __init__(self, config, *args, **kwargs):
        self.config = config         
        #self.ms_algorithm_list = ["lznt1","xpress","xpressh"]
        self.ms_algorithm_list = ["lznt1"]
       
    def runconfig(self):
        """check and setup configuration options upon initlization"""
        if self.config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)\nExample: -A lznt1 --dump-dir outdir")
        
        if not os.path.isdir(self.config.DUMP_DIR):
            debug.error(self.config.DUMP_DIR + " is not a directory")

        if self.config.MSLIB_PATH == None:
            debug.error("Please specify the path to libMSCompression.so\nExample: -P /home/user/mscompress/libMSCompression.so")

        if self.config.MSLIB_PATH:
            if os.path.isfile(self.config.MSLIB_PATH):
                self.libpath = os.path.join(os.path.dirname(self.config.MSLIB_PATH),os.path.basename(self.config.MSLIB_PATH))
                self.nt = cdll.LoadLibrary(self.libpath) 
                if self.nt:
                    try:
                        # // Simple way to test to see if nt.lznt1_decompress_chunk to make sure 
                        # // the proper lib is being used 
                        self.nt.lznt1_decompress_chunk
                    except:
                        debug.error("Please validation you are using the modified version of MS-Compress which exports nt.lznt1_decompress_chunk")
            else:
                debug.error("Please specify the path to libMSCompression.so\nExample: -P ~/mscompress/libMSCompression.so")

        if self.config.COMPRESS_ALGO == None:
            debug.error("Please specify one of the following algorithms:\nlznt1, xpress or xpressh (-A lznt1)")

        if self.config.COMPRESS_ALGO.lower() not in self.ms_algorithm_list:
            print self.config.COMPRESS_ALGO, self.ms_algorithm_list

            debug.error("Please specify only one of the following algorithms:\nlznt1, xpress or xpressh (-A lznt1)")

        if self.config.SET_MINSIZE < 5:
            debug.error("Please specify a minimum size of at least 5 using the -M option")



class MsDecompress(taskmods.DllList):
    """Carves and dumps Lznt1, Xpress and Xpress huffman Compressioned data blocks in a processes pagespace""" 
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)        
        config.remove_option("OFFSET")
        config.add_option('DUMP-DIR', short_option = 'D', default = None,       
                          cache_invalidator = False,
                          help = 'Directory in which to dump carved files')
        config.add_option('COMPRESS-ALGO', short_option = 'A', default = None, type="string",
                          help = 'Specify the compression algorithm to carve (lznt1,xpress,xpressh: -A lznt1"')
        config.add_option("DUMP-COMPRESSED", short_option = 'C', default = False, action = 'store_true', 
                        help = 'Dumps the compressed data segment along with the decompressed segment')
        config.add_option("SET-MINSIZE", short_option= 'M',  default=20,  type="int",
                        help = 'Specify the minimum byte size of compressed data blocks to carve.  Default is 20')    
        config.add_option('MSLIB-PATH', short_option = 'P', default = None, type="string",
                          help = 'Path to libMSCompression.so file')
        self.config = config                    


    def calculate(self):
        addr_space = utils.load_as(self._config)
        self.mscarvecontrol = MsCarveDisplayControl(self.config)
        self.mscarvecontrol.runconfig()

        for proc in tasks.pslist(addr_space):
            #process_space = proc.get_process_address_space()
            yield proc 
    
    def render_text(self, outfd, data):
        for proc in data:
            procspace = proc.get_process_address_space()
            pages = procspace.get_available_pages()
            decompressobj = MsCarverDecompressor(self.config,proc,procspace,pages,outfd)
            if self.config.COMPRESS_ALGO == "lznt1":
                decompressobj.lznt1()
            # if self.config.COMPRESS_ALGO == "xpress":
            #     decompressobj.xpress()
            # if self.config.COMPRESS_ALGO ==  "xpressh":
            #     decompressobj.xpressh()