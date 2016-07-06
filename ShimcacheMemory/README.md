--------------------------------------------------------------------------------
Submitters
--------------------------------------------------------------------------------
Author(s): Fred House (Mandiant, a FireEye Company) - Twitter: @0xF2EDCA5A
           Andrew Davis (Mandiant, a FireEye Company)
           Claudiu Teodorescu (Mandiant, a FireEye Company) - Twitter: @cteo13
           
Date:   2015-09-29

Description: 
  Parses the Windows Application Compatibility Database (aka, ShimCache) from
  the module or process memory that contain the database.

--------------------------------------------------------------------------------
How to use
--------------------------------------------------------------------------------
1) Capture system memory

   NOTE: During testing of this plugin on Windows XP, at least one tool 
         (specifically, DumpIt.exe) did not correctly dump the process memory 
         for winlogon.exe. As a result, the shim cache in memory could not be 
         parsed. A memory image of the same system taken with FTK Imager parsed 
         without issue.
   
2) Run the "shimcachemem" plugin. The following command writes the shim cache
   contents to standard output:

   ```> python vol.py -f Win2012R2x64.raw --profile=Win2012R2x64 --kdbg=0xf801a185b9b0 shimcachemem```

   The following command writes the output to a CSV file:

   ```> python vol.py -f Win2012R2x64.raw --profile=Win2012R2x64 --kdbg=0xf801a185b9b0 shimcachemem --output=csv --output-file=Win2012R2x64.csv```

3) In addition to the output format, the plugin supports the following options:

```
   ---------------------------------------------------------------------------
   | -c | --clean_file_paths | Strips UNC path prefixes ("\\??\") and replaces |
   |    |                    | SYSVOL with "C:". Intended an a convenience for |
   |    |                    | analysts.                                       |
   |    |                    |                                                 |
   | -P | --print_offset     | Prints the virtual and physical offset of each  |
   |    |                    | shim cache entry. Intended to facilitate        |
   |    |                    | additional forensic analysis of the memory      |
   |    |                    | image.                                          |
   |    |                    |                                                 |
   | -i | --ignore_win_apps  | On Windows 10, the shim cache contains entries  |
   |    |                    | for Windows apps, which are in a format that is |
   |    |                    | not parsed by this plugin. This option excludes |
   |    |                    | these entries from the output.                  |
   |    |                    |                                                 |
   |    | --system_name      | An optional system name to add as a column to   |
   |    |                    | the output.                                     |
   |    |                    |                                                 |
    ---------------------------------------------------------------------------
```

--------------------------------------------------------------------------------
Motivation
--------------------------------------------------------------------------------
Shim cache is a highly valuable forensic artifact used to identify evidence of 
file execution. In addition to recording potential file executions, the cache is 
ordered, meaning that an analyst can identify other files that may have executed 
before or after a file of interest.

Most forensic tools that parse the shim cache rely on the cache stored in the 
Windows registry. The cache in the registry is only updated when a system is 
shutdown so this approach has the disadvantage of only parsing cache entries 
since the last shutdown. On systems that are not rebooted regularly (e.g., 
production servers) an analyst must either use out-of-date shim cache data or
request a system reboot.

This plugin parses the shim cache directly from the module or process containing
the cache, thereby providing analysts access to the most up-to-date cache. The 
plugin supports Windows XP SP2 through Windows 10 on both 32 and 64
bit architectures.
