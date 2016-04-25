Volatility plugin: bitlocker
============================

This plugin finds and extracts BitLocker Full Volume Encryption Key (FVEK)
which can be used to decrypt BitLocker volumes.

Currently only Windows Vista/7 memory images are supported.


Example use case
----------------

Evidence #1: John's computer HDD binary image: John_HDD.dd

Evidence #2: John's computer memory dump: John_Win7SP1x64.raw

1) Determine the offset of encrypted BitLocker volume. In the following example
it's the second NTFS partition starting from sector 718848. Note the "-FVE-FS-"
signature.

```
$ mmls John_HDD.dd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

     Slot    Start        End          Length       Description
00:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
01:  -----   0000000000   0000002047   0000002048   Unallocated
02:  00:00   0000002048   0000718847   0000716800   NTFS (0x07)
03:  00:01   0000718848   0031455231   0030736384   NTFS (0x07)
04:  -----   0031455232   0031457279   0000002048   Unallocated
$
$ hexdump -C -s $((718848*512)) -n 16 John_HDD.dd
15f00000  eb 58 90 2d 46 56 45 2d  46 53 2d 00 02 08 00 00  |.X.-FVE-FS-.....|
15f00010
```

2) Use bitlocker plugin to extract FVEK. It's convenient to use optional
argument *--dump-dir* in order to specify the directory in which cipher ID
(first 2 bytes) and FVEK (64 bytes) will be saved.

```
$ export VOLATILITY_LOCATION=file://./John_Win7SP1x64.raw
$ export VOLATILITY_PROFILE=Win7SP1x64
$
$ python vol.py bitlocker --dump-dir ./keys
Volatility Foundation Volatility Framework 2.5

Cipher: AES-128 + Elephant diffuser (0x8000)
FVEK: 2140c8afcbb835127b3b5b97fdcc8b846b7d97fba0c5a2e9dbfef97e263272fa4543af87702c4cee4252eaaa0b7fdc2a96c54aace6e90642a4bbece8afc430c2
FVEK dumped to: ./keys/0xfa80018fe8c0.fvek

```

3) Use extracted FVEK to decrypt the volume using dislocker in FUSE mode.

```
$ sudo dislocker-fuse -V John_HDD.dd -k ./keys/0xfa80018fe8c0.fvek -o $((718848*512)) -- /mnt/ntfs
$
$ sudo mount -o loop,ro /mnt/ntfs/dislocker-file /mnt/clear
$
$ ls -lh /mnt/clear
total 730M
lrwxrwxrwx 2 root root   60 Jul 14  2009 Documents and Settings -> /mnt/clear/Users
-rwxrwxrwx 1 root root 730M Nov  4 09:39 pagefile.sys
drwxrwxrwx 1 root root    0 Jul 13  2009 PerfLogs
drwxrwxrwx 1 root root 4.0K Nov  4 09:58 ProgramData
drwxrwxrwx 1 root root 4.0K Apr 12  2011 Program Files
drwxrwxrwx 1 root root 4.0K Nov  4 07:01 Program Files (x86)
drwxrwxrwx 1 root root    0 Nov  4 07:04 Recovery
drwxrwxrwx 1 root root    0 Nov  4 09:57 $Recycle.Bin
drwxrwxrwx 1 root root 4.0K Nov  4 07:05 System Volume Information
drwxrwxrwx 1 root root 4.0K Nov  4 09:56 Users
drwxrwxrwx 1 root root  24K Nov  4 09:58 Windows
```
