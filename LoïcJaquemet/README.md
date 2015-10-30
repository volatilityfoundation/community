
The submission should include 

 * the source code, 
 * memory sample demonstrating the capabilities
 * description of how the extension is used
 * a write up describing the motivation for the work 
 * why it should win the contest 
 * a signed "Individual Contributor License Agreement" (please request a copy prior to your submission).

If you submit multiple plugins, please specify if they should be evaluated as an individual or multiple entries

Source Code
===========

1. https://github.com/trolldbois/volatility_plugins
2. pip install haystack # https://github.com/trolldbois/python-haystack/
3. pip install ctypeslib2 # https://github.com/trolldbois/ctypeslib
4. pip install python-Levenshtein # 
 
Memory sample
=============

The example below are based on 

 * zeus.img image from http://malwarecookbook.googlecode.com/svn-history/r26/trunk/17/1/zeus.vmem.zip
 * http://secondlookforensics.com/linux-memory-images/centos-6.3-x86_64-LiveDVD-clean.mem.bz2

Usage
=====

1. Install volatility as per instructions
2. `git clone https://github.com/trolldbois/volatility_plugins.git`
3. `vol.py --plugins=volatility_plugins/src/ -f <path_to_memory_dump> haystack -p <pid> -r <record name> -c <constraint_file>`

Plugins:

    * haystackheap: optimised plugin to search for HEAP. please use the constraints file as indicated. 
    * haystacksearch: generic search for record in all memory space (very slow)
    * haystackallocated: search for record in allocated memory chunks only (somewhat experimental)
    * haystackshow: load and show the value of a record if loaded from a specific address
    * haystackreverse: reverse all allocated structure to file and guesstimate the field type of each structure.
    * haystackreversestrings: reverse all strings from allocated memory.


For example, to search for all records that could ba a WinXP x86 Heaps in the zeus.vmem image process 1668 and 856:

    zeus.img image from http://malwarecookbook.googlecode.com/svn-history/r26/trunk/17/1/zeus.vmem.zip

We will use haystackheap to print out the PID and the address of HEAPs. This is a search not using the PEB, 
but only the constraints that a HEAP should have. 

    $ vol.py --plugins=src -f ~/outputs/vol/zeus.vmem haystackheap -r haystack.allocators.win32.winxp_32.HEAP -c examples/winxpheap.constraints -p 1668

    ************************************************************************
    Pid:   1668
    Record HEAP at 0x250000
    Record HEAP at 0x150000
    Record HEAP at 0x3f0000
    Record HEAP at 0xba0000
    Record HEAP at 0xb70000
    Record HEAP at 0x1620000
    Record HEAP at 0x1eb0000
    Record HEAP at 0x1ec0000
    Record HEAP at 0x7f6f0000
    
Now we use different set of constraint on the values of the HEAP fields. Surprising fantom HEAP appears.

    $ vol.py --plugins=src -f ~/outputs/vol/zeus.vmem haystackheap -r haystack.allocators.win32.winxp_32.HEAP -c examples/winxpheap-relaxed.constraints -p 1668

    ************************************************************************
    Pid:   1668
    Record HEAP at 0x250000
    Record HEAP at 0x150000
    Record HEAP at 0x3f0000
    **Record HEAP at 0x730000**
    **Record HEAP at 0x860000**
    Record HEAP at 0xba0000
    Record HEAP at 0xb70000
    Record HEAP at 0x1620000
    Record HEAP at 0x1eb0000
    Record HEAP at 0x1ec0000
    **Record HEAP at 0x5d09d000**
    **Record HEAP at 0x769f7000**
    Record HEAP at 0x7f6f0000

You can now compare the content of these HEAPs to better understand why ? (this is a fictitious useless scenario)

    $ vol.py --plugins=src -f ~/outputs/vol/zeus.vmem haystackshow -r haystack.allocators.win32.winxp_32.HEAP -p 1668 -a 0x1eb0000 

    ************************************************************************
    Pid:   1668
    Record HEAP at 0x1eb0000
    Record content:
    [# --------------- 0x0 
    { # <struct__HEAP at 0x1eb0000>
    "Entry": { # <struct__HEAP_ENTRY at 0x???>
    [..]
    "Signature": 4009750271L, # c_uint
    "Flags": 4098L, # c_uint
    [..]
    "Segments": [
	0x01eb0640,
	0x01fc0000,
	[..]
    "LockVariable": 0x01eb0608,
    "CommitRoutine": 0x00000000,
    "FrontEndHeap": 0x01eb0688,
    "FrontHeapLockCount": 0, # c_ushort
    "FrontEndHeapType": 1, # c_ubyte
    "LastSegmentIndex": 1, # c_ubyte
    }]

and a phantom one:

    $ vol.py --plugins=src -f ~/outputs/vol/zeus.vmem haystackshow -r haystack.allocators.win32.winxp_32.HEAP -p 1668 -a 0x730000 

    ************************************************************************
    Pid:   1668
    Record HEAP at 0x730000
    Record content:
    [# --------------- 0x0 
    { # <struct__HEAP at 0x730000>
    "Entry": { # <struct__HEAP_ENTRY at 0x???>
    [..]
    "Signature": 4009750271L, # c_uint
    "Flags": 9L, # c_uint
    [..]
    "Segments": [
        0xbc5d0608,
    [..]
    "LockVariable": 0x00000000,
    "CommitRoutine": 0xbf8b810a,
    "FrontEndHeap": 0x00000000,
    "FrontHeapLockCount": 0, # c_ushort
    "FrontEndHeapType": 0, # c_ubyte
    "LastSegmentIndex": 0, # c_ubyte
    }]

Now this can be applied to any type of records in a process memory.

The haystackallocated plugin should accelerate searches for record present in allocated memory chunks.
The plugin work for windows XP and 7, 32 and 64 bits. Not perfect for Linux images as some bugs exists.

If you want to search for more that just HEAP structures provided by haystack or in this repository,
you can use ctypeslib to generate your own structures from your favorite C headers. 

You might want to look at https://github.com/trolldbois/ctypeslib to produce your own records.
Keep in mind you might want to generate ctypes for a different architecture than your own.

For example, to list all OpenSSL cipher session context records from a process 

    $ vol.py --plugins=volatility_plugins/src -f somelinux.img -r examples.records_openssl_32.struct_evp_cipher_ctx_st -c examples/openssl.constraints 


And finally , if you are adventurous, you can try to reverse a process' memory:

    $ vol.py --plugins=src -f ~/outputs/vol/zeus.vmem haystackreverse -p 856
    
    [..]
    
You will find a few folders named zeus.vmem_856/ with the produce of the reverse in there.

Interesting files are named headers_values.py

Based on that a lot of plugins can be made, like a strings extractor. 
HaystackReverseStrings is an string extractor.
But instead of parsing the whole memory dumps, it only looks at strings contained into the process 
valid memory allocations.
 

    $ vol.py --plugins=src -f ~/outputs/vol/zeus.vmem haystackreversestrings -p 856

    ************************************************************************
    Pid:    856
    856,0xbf000,0x8 bytes,u'\x...0\n'
    856,0x92020,0x30 bytes,u'C:\\WINDOWS\\setupapi.log\x00'
    856,0xa4028,0x54 bytes,u'Network Location Awareness (NLA) Namespace'
    856,0xb408c,0xac bytes,u'MSAFD NetBIOS [\\Device\\NetBT_Tcpip_{AD92BA6E-D818-40B8-BC01-D4D8A59937A1}] SEQPACKET 2'
    856,0xb428c,0x22 bytes,'%SystemRoot%\sys...m32\mswsock.dll'
    [..]

Motivation for this work
========================

These plugins are an interface between the Volatility framework and the haystack framework.

While Volatility establishes a forensic framework to analyse a system's RAM, the haystack framework is intended to 
analyse a process's RAM, allowing a analyst to search for defined structures in a process's memory.

Most process's memory are composed from a graph of record, linked by pointers fields. The limited space value of these
fields and others constraints allows for the haystack framework to easily identify all instances of 
a record type in memory.

 
Why it should win the contest
=============================

These plugins are an opening of the next level of forensics, into a process's structured memory.

They open the way to the possibility of searching in memory for a new type of signature.
Not signatures that are bytes-based.
But signatures that are representing the graph that results from memory allocation by malware.

Plus it also pretty easy to extract SSL session keys, passphrases, binary data as long as the record types are known.

So this integration and plugins are also a basis for future plugins to easily 'search' for structures, without to have
to guess the location of such records. The records type themselves are usually sufficient.