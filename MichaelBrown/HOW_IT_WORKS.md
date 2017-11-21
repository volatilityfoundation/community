
How it Works
============

Given a schema, it sqlitefind searches for a section of the row header that matches those types. The steps are:

  1. Build needle - Based on column types given, figure out what to search for.
  2. Search memory - Finds all instances of needle in memory.
  3. Parse row - Perform checks to make sure this is actually row data. Return
        the data if it looks good.

Build Needle
------------

For details on database format, see: [SQLite Database File
Format](https://www.sqlite.org/fileformat2.html)

Each row in an sqlite database looks like this:

    Payload Length (varint)
    Row ID (varint)
    Header:
        Header Length (varint)
        Field 1 Serial Type (varint)
        Field 2 Serial Type (varint)
        ...
    Field 1 (size determined by corresponding type in header)
    Field 2 (size determined by corresponding type in header)
    ...

The varint format is extensively used, which takes up 1 to 9 bytes and
represents a 64-bit twos-compliment integer. The exact encoding is not
important, you just need to know that varint encodes both its own length and an
integer.

The header defines how big each of the fields are by a number called the
[Serial Type](https://www.sqlite.org/fileformat2.html#record_format). The
fields follow immediately afterward. Some of the fields could be zero length
too, like the Serial Types 0x08 and 0x09, which just mean the value is 0 or 1.

The idea for building our needle is to search for the header based on prior
information about the types the fields might have. There is one caveat to this:
string and blob types can take up more than one byte in the header. Because the
varint that stores strings and blobs also encode a length, they can take 1-9
bytes. To get around this, we just search for the largest part of the header
that has a fixed length. For example:

    bool;      null,float;  string;     bool
    (08 | 09)  (00 | 07)    var length  (08 | 09)

The needle would be `(08 | 09)  (00 | 07)`, because it's the longest part of the
header that has fixed length. That means "either the byte 0x08 or 0x09,
followed by either the byte 0x00 or 0x07".

The routine that builds the needle also returns where the needle is relative to
the beginning of the record. i.e. it specifies how many varints to count
forwards or backwards and how many bytes to count forwards or backwards to get
to the record. This is what allows the needle to be anywhere in the header. In
the future it will be possible to have a needle located in the beginning of the
actual column data.

Search Memory
-------------

A yara rule is compiled for the needle so searching can be done quickly. The
address space is broken into blocks and yara is called for each. There may be
many matches of our needle that do not actually correspond to a row. False
positives are (mostly) removed in the next step, but the number of yara matches
greatly affects how fast the search is.

Parse Row
---------

Each match is given to the `parse_record` function, which either returns the
data in the row, or raises an error. There are many checks to make sure the
data is actually a row. The types are also checked, since the needle may not
include all columns.

sqlite_master Table
-------------------

The `sqlite_master` table is a special table in sqlite that stores the schemas
for all other tables. The `sql` field stores the sql statement to create the
table. The `sqlitefindtables` command searches for this table, then parses
the sql to get the schema.

The table looks like this:

    CREATE TABLE sqlite_master (
        type TEXT,
        name TEXT,
        tbl_name TEXT,
        rootpage INTEGER,
        sql TEXT
    );

There is a slight problem with searching for this table though: every field
except one is `TEXT`! Since there is only one field that has a fixed length in
the header, our needle size will be 1, making this completely impractical.

Fortunately, there is a better needle. For the kind of entries we're looking
for, the `type` field is always "table". Our needle can just be "table", then
we count backwards over all of the varints in the header to get to the
beginning.
