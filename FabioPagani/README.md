## Introduction

This Volatity Plugin Contest submission contains two contributions to
the Volatility framework and to the memory forensics fields. The first
contributions contains several new Volatility plugins to list tasks
and kernel modules under Linux. The second one is instead a novel way
to extract the kallsyms from a memory dump in an automated way.

## Plugins to list module and kallsyms

As a side effect of our latest paper - where we constructed and studied a directed graph of kernel structs [1] - we were able to find new ways to list Linux processes and kernel modules.
As you know (even better than me!) being able to reach the same information from different ways is crucial if smearing affects a memory dump or DKOM attacks were performed.
The directory `new_plugins` contains the following novel plugins:

1) `cgrp_dfl_pslist` and `css_set_pslist`: they list all the threads in the dump by traversing cgroup related structs
2) `inode_pslist`: lists every process that has at least one memory mapped file
3) `workqueues`: lists every kernel workers (which are part of the process list)
4) `terminated_tasks`: lists terminated tasks by deferencing certain field of task_struct and signal_struct which are not update when a task dies (e.g task_struct.last_wakee)
5) `mod_tree`: walks a latch tree rooted at the kernel symbol `mod_tree` to list kernel modules

All of this plugins works with a normal Volatility profile, except `workqueues` that needs few new structs definitions. For this reason, we included in this submission also an updated `module.c` file.


## Kallsyms extraction

Imagine that you have a memory dump but - for whatever reason - the profile has an invalid or corrupted System.map file!
There have been few attempts in the past to automatically extract this information from a memory dump [2][3].
Unfortunately these approaches assume to know where the kernel is loaded in the virtual and physical address space, thus failing when KASLR is enabled.
Moreover, they are able to extract only the ksymtab - which contains a limited subset of kernel symbols (the ones exported with EXPORT_SYMBOL macro).
With this contributions we show a reliable and automated way to extract the kernel kallsyms - which are stored in kernel memory in a compressed form.

In a nutshell our approach locates, extracts and executes the function `kallsyms_on_each_symbol` from a memory dump. This function takes care of uncompressing the kallsyms and accepts a function pointer as parameter - which gets called every time a kallsym is uncompressed!

More specifically, our approach can be divided in the following steps:
1) First of all we find the physical location of the string "kallsyms_on_each_symbols\x00"
2) Then we search in the dump for a candidate ksymtab. This table contains several `struct kernel_symbols` which contains two fields: `value` and `name`. The first contains the virtual address of the symbol, while the latter is a pointer to a string representing the name of the symbol. For this reason, finding a candidate symtab is a matter of searching for a sequence (longer than a threshold) of pairs of kernel addresses.
3) At this point, we use the following insight: KASLR randomize the virtual and physical space at a page granularity. This means that the correct ksymtab should contain at least one `struct kernel_symbol` where the page offset of the name field matches the page offset of the physical location of the string (found at step 1)).
4) When we find such a `kernel_symbol`, since the kernel is mapped contigously, to find the physical address of the value field we can just do: string physical address + (value virtual address - name virtual address)
5) At this point we know the virtual address of the kallsyms_on_each_function and its physical address: we are ready to extract the sorrounding of this address, load the in Unicorn and execute the function!

I tried the script against several versions of the kernel and it worked flawlessy even when on the dumps of The Art Of Memory Forensics :)

### Limitations and Future Work:
First of all, this works only if the kernel was compiled with CONFIG_MODULES - otherwise the kallsyms are never created in the first place.

Moreover, the latest versions of the kernel introduced CONFIG_HAVE_ARCH_PREL32_RELOCATIONS. This makes everything more tricky `struct kernel_symbol` does not contain virtual addresses anymore but only offsets. Therefore, while we can still find the physical address of the function in the dump, we miss its virtual address. I have the strong feeling that by analyzing the code we can still find the correct virtual address (maybe with some small bruteforcing involved?), but I did not have time tothes this.

Finally, this function can also list the installed modules symbols (it calls `module_kallsyms_on_each_symbol`). The problem here is that the memory where this information resides must be correctly loaded in the emulator (modules area is not contigous to the kernel code, so extracting more memory from the dump is not enough). But from the ksymtab we know where `init_level4_pgt` or `init_top_pgt` are - so we could walk the page tables and set everything up correctly in the emulator!

## Conclusion
I really believe that memory forensics on Linux will be "the next big thing" in this field. This submission steps the game up, with new plugins to analyze a memory dump and a robust, fast and generic (kernels up to 10 years ago should be supported) approach to extract the kallsyms. For these reasons, I really belive that this submission deserves to win this year contest ;-)


### References
[1] https://www.usenix.org/system/files/sec19-pagani.pdf
[2] https://github.com/emdel/ksfinder
[3] https://github.com/psviderski/volatility-android/blob/master/volatility/plugins/linux/auto_ksymbol.py