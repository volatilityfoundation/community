from unicorn import *
from capstone import *
from unicorn.x86_const import *
from capstone.x86 import *
import os

fs_base = 0x0
fs_size = 0x10000

stack_size  = 0x150000
stack_base = 0xeeee0000

reg_index = { 'eax'    : UC_X86_REG_EAX,
              'ebp'    : UC_X86_REG_EBP,
              'ebx'    : UC_X86_REG_EBX,
              'ecx'    : UC_X86_REG_ECX,
              'edi'    : UC_X86_REG_EDI,
              'edx'    : UC_X86_REG_EDX,
              'eflags' : UC_X86_REG_EFLAGS,
              'eip'    : UC_X86_REG_EIP,
              'esi'    : UC_X86_REG_ESI,
              'esp'    : UC_X86_REG_ESP,
              'rax'    : UC_X86_REG_RAX,
              'rcx'    : UC_X86_REG_RCX,
              'rdx'    : UC_X86_REG_RDX,
              'rbx'    : UC_X86_REG_RBX,
              'rsi'    : UC_X86_REG_RSI,
              'rdi'    : UC_X86_REG_RDI,
              'rsp'    : UC_X86_REG_RSP,
              'rbp'    : UC_X86_REG_RBP,
              'r8'     : UC_X86_REG_R8,
              'r9'     : UC_X86_REG_R9,
              'r10'    : UC_X86_REG_R10,
              'r11'    : UC_X86_REG_R11,
              'r12'    : UC_X86_REG_R12,
              'r13'    : UC_X86_REG_R13,
              'r14'    : UC_X86_REG_R14,
              'r15'    : UC_X86_REG_R15,
              'r8d'    : UC_X86_REG_R8D,
              'r9d'    : UC_X86_REG_R9D,
              'r10d'   : UC_X86_REG_R10D,
              'r11d'   : UC_X86_REG_R11D,
              'r12d'   : UC_X86_REG_R12D,
              'r13d'   : UC_X86_REG_R13D,
              'r14d'   : UC_X86_REG_R14D,
              'r15d'   : UC_X86_REG_R15D,
              'r8w'    : UC_X86_REG_R8W,
              'r9w'    : UC_X86_REG_R9W,
              'r10w'   : UC_X86_REG_R10W,
              'r11w'   : UC_X86_REG_R11W,
              'r12w'   : UC_X86_REG_R12W,
              'r13w'   : UC_X86_REG_R13W,
              'r14w'   : UC_X86_REG_R14W,
              'r15w'   : UC_X86_REG_R15W,
              'r8b'    : UC_X86_REG_R8B,
              'r9b'    : UC_X86_REG_R9B,
              'r10b'   : UC_X86_REG_R10B,
              'r11b'   : UC_X86_REG_R11B,
              'r12b'   : UC_X86_REG_R12B,
              'r13b'   : UC_X86_REG_R13B,
              'r14b'   : UC_X86_REG_R14B,
              'r15b'   : UC_X86_REG_R15B} 
              

class shemulator:

    def __init__(self,
                 proc_space,
                 step_through,
                 max_instructions,
                 dis_md = 32,
                 dump_regs = ['eax', 'ebx', 'ecx', 'edx'],
                 reg_vals = {'eax': 0xaaaa,
                             'ebx': 0xbbbb,
                             'ecx': 0xcccc,
                             'edx': 0xdddd },
                 dump_on_inst = 0,
                 dump_blocks = 0,
                 verb = 1,
                 patch = {},
                 brkpnt = [],
                 dump_code = ''):

        if dis_md == 64:
            self.disasm_mode = UC_MODE_64
        else:
            self.disasm_mode = UC_MODE_32
        self.stop_processing = -1
        self.stack_base_written = False
        self.basicBlocks = []
        

        # Controls if the user is given control at every step of the emulation
        self.step = step_through

        self.max_instr = max_instructions

        print('Initial setting of the PAS to value')
        print(proc_space)
        self.space = proc_space

        # List of variables to dump the values of, either after each instruction, or after each basic block
        self.regDump = dump_regs

        # Controls if registers are dumped after instructions (if 1) or after basic blocks (if 0)
        self.dumpOnInst = dump_on_inst

        # Controls if we print out the addresses of all basic blocks reached at the end
        self.dumpBlocks = dump_blocks

        # Dictionary of register-value pairs. Listed registers are initialized to the given value.
        self.regVal = reg_vals

        # Controls if the disassembly is printed during emulation
        self.verbose = verb

        # Dictionary of address-value pairs. When any of the listed addresses are mapped into memory, after the true code is written,
        # the user-supplied patches are written at the corresponding address
        # For example, if the user wanted to write 0000 to address 0x1234, and 41 to address 0x5678 they would input
        # patch = {0x1234:'\x00\x00', 0x5678: '\x41'}
        self.patchInst = patch

        # Contains a list of addresses to set breakpoints on
        self.breakPoint = brkpnt

        # Controls if we dump all the code we map into memory into text files. If dump != '', make a directory named dump to put all the files in.
        self.dumpCode = dump_code
        if dump_code != '':
            os.mkdir(dump_code)


    # Initialize non-problematic registers to 0. Unsure if this is strictly necessary.
    def reg_init(self, uc):
        uc.reg_write(UC_X86_REG_EAX, 0x0)
        uc.reg_write(UC_X86_REG_EBX, 0x0)
        uc.reg_write(UC_X86_REG_ECX, 0x0)
        uc.reg_write(UC_X86_REG_EDX, 0x0)

    # Prints out registers listed in regDump
    def print_regs(self, uc, reg_array):
        for reg in reg_array:
            print('%s: %x' %(reg, uc.reg_read(reg_index[reg])))

    # Given a dictionary of register-value pairs, write the value to the corresponding register
    def set_regs(self, uc, reg_dict):
        for reg in reg_dict:
            uc.reg_write(reg_index[reg], reg_dict[reg])

            
    # Given an address, set a breakpoint at that address
    def set_break(self, addr):
        self.breakPoint.append(addr)

    # Given a dictionary of {0xaddress:'\xco\xde'}, update the patch dictionary. Will only patch instructions that
    # have not been mapped into memory yet
    def set_patch(self, uc, newPatch):
        self.patchInst.update(newPatch)
        for k in newPatch:
            uc.mem_write(k, newPatch[k])

    # Toggle the verbosity
    def set_verbose(self, v):
        self.verbose = v

    # Toggle stepping through execution
    def set_step(self, s):
        self.step = s

    # print out the starting addresses of each basic block encountered
    def print_blocks(self):
        for block in self.basicBlocks:
            print('%x'%block)
        
    def within_stack(self, address):
        return (stack_base - stack_size) <= address <= (stack_base + stack_size)


    # This function is executed after each emulated instruction.
    def hook_code(self, uc, address, size, step):

        # Decrement the instruction counter
        self.max_instr -= 1

        # If verbose was selected, disassemble with capstone and print the address|hex|instruction
        if self.verbose:
            try:
                asm = uc.mem_read(address, size)
            except Exception as e:
                print("Could not disassemble, hit exception %s" %e)
                asm = 0

            if asm:
                asm = ''.join(map(chr,asm))
                cs = Cs(CS_ARCH_X86, self.disasm_mode)
                Asm = list(cs.disasm(asm,size))

                for ins in Asm:
                    print(">>0x{:x}\t{:{w}}\t{:{w2}} {:{w}}".format(address, asm.encode('hex'), ins.mnemonic, ins.op_str, w = 16, w2 = 8))

        # If the user wanted to step through the emulation, give them the power
        # Otherwise, if the user set a breakpoint at this address, hold for input.
        if self.step or address in self.breakPoint:
            if address in self.breakPoint:
                self.breakPoint.remove(address)
                self.step = 1
            inpt = raw_input()
            while inpt and self.step:
                # type "exit" to stop stepping through code
                if inpt == 'exit':
                    self.max_instr = 0
                    self.step = 0
                    break
                # type "print register" to print the value of the register
                # example: "print eax" returns the value stored in eax
                elif inpt.startswith('print'):
                    inpt_list= inpt.split()
                    if len(inpt_list) > 1 and inpt_list[1] in reg_index:
                        reg = inpt_list[1]
                        print('%s: %x' %(reg, uc.reg_read(reg_index[reg])))
                # type "set register = value" to store the value in the given register
                # example: "set eax = 10" stores 10 in eax
                elif inpt.startswith('set'):
                    inpt_list= inpt.split()
                    if len(inpt_list) > 3 and inpt_list[1] in reg_index and inpt_list[2] == '=':
                        reg = inpt_list[1]
                        # handle hex values vs integer values
                        if inpt_list[3].startswith('0x'):
                            val = int(inpt_list[3], 16)
                        else:
                            val = int(inpt_list[3])
                        uc.reg_write(reg_index[reg], val)
                # type "max_instr + number" to increase the max_instructions count by number
                # example: "max_instr + 8" increases the number of instructions to step through by 8
                elif inpt.startswith('max_instr + '):
                    inpt_list= inpt.split()
                    if len(inpt_list) > 2 and inpt_list[2].isdigit():
                        self.max_instr += int(inpt_list[2])
                # type "step = 0" or "step = 1" to stop or start stepping
                elif inpt == 'step = 0':
                    self.set_step(0);
                elif inpt == 'step = 1':
                    self.set_step(1);
                # type "verbose = 0" or "verbose = 1" to set or unset verbose mode
                elif inpt == 'verbose = 0':
                    self.set_verbose(0)
                elif inpt == 'verbose = 1':
                    self.set_verbose(1)
                # type "break = address" to set a breakpoint at address
                # example: "break = 0xabcd" sets a breakpoint at address 0xabcd
                elif inpt.startswith('break = '):
                    inpt_list= inpt.split()
                    if len(inpt_list) > 2:
                        brk_address = int(inpt_list[2], 16)
                        self.set_break(brk_address)
                inpt = raw_input()

        # Dump the requested registers, if desired
        if self.regDump and self.dumpOnInst:
            self.print_regs(uc, self.regDump)

        # Unicorn doesn't like to take no for an answer, you have to kind of break the emulation to get it to stop.
        # We do that here.
        if self.max_instr <= 0:
          self.stop_processing = address
          try:
            uc.mem_unmap(address & ~0xfff, 0x1000)
          except:
            pass
          return

        # Don't execute at address 0
        if address == 0: 
            uc.mem_unmap(0, 0x1000)
            self.stop_processing = address
            return

        # Don't execute on the stack
        if self.within_stack(address):
            print "execution on stack. unmapping it"
            self.stop_processing = address
            try:
                uc.mem_unmap(address & ~0xfff, 0x1000)
            except:
                pass
            return

        if self.disasm_mode == UC_MODE_32:
            # And finally, don't execute at huge addresses
            if address > 0xf0000000:
                print("executing above 0xf0..: %x" % address)
                self.stop_processing = True
                try:
                    uc.mem_unmap(address & ~0xfff, 0x1000)
                except:
                    pass

                return

        # this is purely for smear/corruption cases I encountered
        if size > 100000000:
            return


    # This is called after emulation hits a new basic block
    def hook_block(self, uc, address, size, user_data):
        if self.verbose:
            print("Hit a new basic block at %x" % address)

        # Keep track of the starting address of each basic block
        if address != 0:
            self.basicBlocks.append(address)

        # If we're dumping registers, but not after each instruction, do it now
        if self.regDump and not self.dumpOnInst:
            self.print_regs(uc, self.regDump)

    # This is called at each memory access
    def hook_mem_access(self, uc, access, address, size, value, user_data):

        # If we're writing the stack base, record this so we can continue emulation later if we read from it
        if access == UC_MEM_WRITE:
            op = "write"
            if address == stack_base:
                self.stack_base_written = True

        # If we're reading the stack base, and it hasn't been written, exit
        elif access == UC_MEM_READ:
            op = "read"
            if address == stack_base and self.stack_base_written == False:
                self.stop_processing = address

    # Everytime unicorn doesn't have the code we want to emulate in its address space, call this
    def badmem(self, uc, access, address, size, value, user_data):
        print("Access to unmapped memory %s | %s | %s" % (hex(address), hex(size), access))

        # All those times we set this value were just to do this. This actually just kills the emulation
        if self.stop_processing == address:
            return

        if self.max_instr <= 0:
            return

        if self.space == None:
            exit()

        # Unicorn will only successfully map page-aligned addresses, so map the whole page.
        pageSize = 0x1000
        
        pageBase = address & (~(pageSize-1))
        
        # map a page into the emulated address space at the specified address
        try:
            uc.mem_map(pageBase, pageSize)
        except:
            print("unable to map into memory %x | %x" % (pageBase, pageSize))
            return False

        # Read from the memory sample where requested
        pageCts = self.space.read(pageBase, pageSize)
        if pageCts == None:
            # fill in the page just to help progress
            uc.mem_write(pageBase, "\xc3" * pageSize)
            print("Unable to read %s bytes at %s" % (hex(pageSize), hex(pageBase)))
            return True

        # map into emulator address space
        uc.mem_write(pageBase, pageCts)

        if self.dumpCode != '':
            cfname = '%x.txt' %pageBase
            cfname = os.path.join(self.dumpCode, cfname)
            cfile = open(cfname, 'w')
            cfile.write(pageCts)
            cfile.close()

        # After writing the memory into unicorn, write in any user-supplied patches
        # User supplied code must be a single string of the form '\xAB\xCD\xEF\xGH' and so on
        for patch_addr in self.patchInst:
            if patch_addr >= pageBase and patch_addr <= pageBase + pageSize:
                uc.mem_write(patch_addr, self.patchInst[patch_addr])

        return True
    
    def emu(self, address, length = 4096):

        # Most things here were more or less lifted from Andrew Case's HookTracer plugin,
        # Specifically from the analyze_address function.
        # The purpose of this code is to set up the emulation environment.
 

        # Here we read in code at the specified address

        #code = self.space.read(address, length)
            
        #if not code:
        #    length = 0xfff - (address & 0xfff)
        #    code = space.read(address, length)

        #    if not code:
        #        print("Unable to read code from address %x" % address)
        #        return

        # We save the code into a text file for easier reading into unicorn's address space, and to make patching it easier
        #cfname = '%x.txt' %address
        #cfile = open(cfname, 'w')
        #cfile.write(code)

        # This is the initialization of the emulator
        mu = Uc(UC_ARCH_X86, self.disasm_mode)

        # If the user wanted to start with some initial register states, do that now, otherwise just set some to 0
        if self.regVal:
            self.set_regs(mu, self.regVal)
        else:
            self.reg_init(mu)

        # Set up unicorn's address space and stack before emulation starts.
        pageSize = 0x1000
        pageBase = address & (~(pageSize - 1))

        
        mu.mem_map(fs_base, fs_size)
        mu.mem_write(fs_base, "\xc3\xc3\xc3\xc3")
        mu.mem_write(fs_base+4, '\x00' * (fs_size-4))
        
        mu.mem_map(stack_base - stack_size, stack_size)
        mu.mem_write(stack_base - stack_size, '\x00'*stack_size)
        mu.mem_map(stack_base, stack_size)
        mu.mem_write(stack_base, '\x00'*stack_size) 
        mu.reg_write(UC_X86_REG_ESP, stack_base)
        
        # Initialize several basic hooks
        # Eventually want to choose which to add based on user input
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        mu.hook_add(UC_HOOK_MEM_READ, self.hook_mem_access)
        mu.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
        mu.hook_add(UC_HOOK_BLOCK, self.hook_block)

        # All of the logic to handle bad memory is explicitly lifted from hooktracer (with minor changes to variable names)
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.badmem)
        mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self.badmem)
        mu.hook_add(UC_HOOK_MEM_WRITE_INVALID, self.badmem)
        mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.badmem)

        try:
            mu.emu_start(address, length)
            
        except Exception as e:
            print("Ended on an exception: %s" %e)

        if self.dumpBlocks:
            self.print_blocks()

        
