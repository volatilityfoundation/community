
This is a rough quantitative analysis of how well `sqlitefind` can recover
database rows.

Data files are in the `data/` directory. The large files like memory dumps and
databases are not in the repository. **You can download the large files
[here](https://msbrown.net/sqlitefind/).**

Memory dumps were accomplished using virsh dump:

    # virsh dump --domain <machine name> --memory-only --file <name>.img


Test Database
=============

Gathering Data
--------------

  1. Create database `test_db.sqlite` using `create_test_db.py` script.
  2. Reboot Ubuntu VM.
  3. Open `test_db.sqlite` with the `sqlite3` command.
  4. Execute "SELECT * FROM TESTTABLE;".
  5. Take memory snapshot.

Data files:

  * `testdb_snapshot.img` - Memory snapshot
  * `test_db.sqlite` - Database file

Analysis
--------

Files generated:

  * `recovered_testtable.csv`

The `sqlitefindtables` command correctly finds the schema for the table "testtable":

    $ volatility --profile=LinuxUbuntu16045x64
                 -f data/testdb_snapshot.img sqlitefindtables
    Name           Column Type String
    ...
    testtable      id:null,int; i:int; even:bool,null; odd:bool,null; s:string,null
    ...

Entering the schema into the `sqlitefind` command we can recover the rows:

    $ volatility --profile=LinuxUbuntu16045x64 \
                 -f data/testdb_snapshot.img sqlitefind \
                 -c "id:null,int; i:int; even:bool,null; odd:bool,null; s:string,null" \
                 --output=csv --output-file=data/recovered_testtable.csv
    Outputting to: data/recovered_testtable.csv
    Needle Size: 4

How many of the rows did we recover?

    $ wc -l data/recovered_testtable.csv
    1048

Subtracting out the CSV header, we found 1047 rows. Our database has 1000 rows
in it, so how many actually look like data we inserted?

    $ grep "This is testtable row" data/recovered_testtable.csv | wc -l
    1001

That's strange, we found an extra row! The culprit is one spurious row that
ends with garbage data (here, the syntax `\0xaa` means the byte `0xaa`):

    "347","347","0","1","This is testtable row 3\0xc3\0x97\0xc3\0xbf"

What about things that don't look like our data:

    $ grep -v "This is testtable row" data/recovered_testtable.csv | wc -l
    47

Most of these are found because there are places in memory that look like a
database row, but are't. NULL is a particularly common value because the serial
type for NULL is 0x00. There could also be a table in memory with a similar
schema that we find. In a table with few columns like this, spurious matches
are also more likely. In any case, these spurious matches usually don't look
like interesting data to a human.

Final result:

  * 1047 Rows found
  * 1000 / 1000 True positives found
  * 47 False Positives


Fresh Boot
==========

An Ubuntu12.04 VM was booted to the GUI and then a memory snapshot was taken to
see what we find without explicitly opening a database.  See
`data/fresh_boot.img`.

Interestingly, we can find an sqlite database in memory after startup:

    $ volatility -f data/fresh_boot.img sqlitefindtables
    Name           Column Type String
    uri            id:null,int; value:string,null
    interpretation id:null,int; value:string,null
    manifestation  id:null,int; value:string,null
    payload        id:null,int; value:blob,null
    storage        id:null,int; value:string,null; state:null,int;
                   icon:string,null; display_name:string,null
    text           id:null,int; value:string,null
    mimetype       id:null,int; value:string,null
    actor          id:null,int; value:string,null
    schema_version schema:string,null; version:null,int
    mappings       timestamp:null,int; device:string,null; profile:string,null
    properties     device_id:string,null; property:string,null; value:string,null
    devices        device_id:string,null; device:string,null

The database might have something to do with the GUI, or another service that
runs on startup. To find out, you could print the offsets in memory that the
table schemas were found, then map that back to a process.

There's currently a limitation that keeps us from searching for these rows
though. Every one of them has a needle size of one byte, which would take a
long time to search. YARA raises an error if we have more than 1000000 matches
in one search, and currently the searching is done in blocks of 10 kilobytes.
This can result in too many matches with small needles.  More work is needed to
make searching for small needles work.
