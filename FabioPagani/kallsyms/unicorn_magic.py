from unicorn import *
from unicorn.x86_const import *

def hook_mem_invalid(uc, access, address, size, value, user_data):
    # print("Mem_invalid @ 0x%x" % address)
    return True

def align_page(a):
    return a & ~0xfff

def read_str(uc, address):
    s = b""
    while b"\x00" not in s:
        s += uc.mem_read(address, 1)
        address+=1
    return s[:-1]

def hook_code64(uc, address, size, user_data):
    ksyms, callback_addr = user_data
    # print(">>> Tracing instruction at 0x%x, callback at 0x%x " % (address, callback_addr))
    if address == callback_addr:
        sym_name = read_str(uc, uc.reg_read(UC_X86_REG_RSI)).decode("utf-8")
        sym_address = int(uc.reg_read(UC_X86_REG_RCX))

        # print("FOUND: 0x%x %s" % (sym_address, sym_name))
        ksyms.append((sym_address, sym_name))
        uc.reg_write(UC_X86_REG_RAX, 0)

def extract_symbols(dump, kallsyms_on_each_va, kallsyms_on_each_pa):
    ksyms = []
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # We read 16mb before and 16mb after, is should be enough to cover all the kernel .text and data.
    load_va = align_page(kallsyms_on_each_va - 2**24)
    load_pa = align_page(kallsyms_on_each_pa - 2**24)
    mem = dump[load_pa:load_pa+2**25]

    mu.mem_map(load_va, len(mem))
    mu.mem_write(load_va, mem)

    # Map the zero page for gs:0x28 accesses
    mu.mem_map(0, 4096)
    mu.mem_write(0, b"\x00"*4096)

    # Setup the stack...
    STACK = 0x200000
    STACK_SIZE = 0x100000
    mu.mem_map(STACK - STACK_SIZE, STACK)
    mu.reg_write(UC_X86_REG_RSP, STACK)

    mu.reg_write(UC_X86_REG_GS, 0x1000)
    # Inject our fake callback function, which consists only of a ret
    callback_addr = load_va
    mu.mem_write(callback_addr, b"\xc3")
    mu.reg_write(UC_X86_REG_RDI, callback_addr)

    mu.hook_add(UC_HOOK_CODE, hook_code64, (ksyms, callback_addr))
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)

    try:
        mu.emu_start(kallsyms_on_each_va, kallsyms_on_each_va+0x20000)
    except unicorn.UcError:
        # print("unicorn throw an exception, we should be done here..")
        pass

    return ksyms
