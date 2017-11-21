
SqliteFind is a Volatility plugin for finding sqlite database rows. It can automatically find database schemas in `sqlite_master` tables, and recover database rows from memory.

  * [Tutorial](TUTORIAL.md)
  * [How it works](HOW_IT_WORKS.md)


Installing
==========

"sqlitefind.py" must be in the plugin path and "sqlitetools.py" must be
importable. You should either add this directory to your volatility plugin
path, or add a link to these files inside the volatility plugin folder.

Requires the YARA Python API. Try installing the pip package "yara-python".
Running "import yara" should work in the Python shell.


Basic Usage
===========

Find tables:

    $ volatility -f <memory file> sqlitefindtables

Recover table rows:

    $ volatility -f <memory file> sqlitefind -t <table name>

For a guided tour, see the [Tutorial](TUTORIAL.md).

See below for the common options, or use `--help` for a complete list of
options.


sqlitefindtables Command
========================

Searches for an `sqlite_master` table and shows the schemas found in them.

    $ volatility -f <memory file> sqlitefindtables

Use `-R`/`--raw-sql` to output the schema in raw SQL.


sqlitefind Command
==================

Searches for database rows in memory, given the table schema. There are a few
ways to specify the schema. You can specify the table name, in which case the
schema matching the table name will be searched for in an `sqlite_master`
table:

    $ volatility -f <memory file> sqlitefind -t <table name>

Alternatively, you can specify the table schema manually:

    $ volatility -f <memory file> sqlitefind 
                 -c "id:int,null; place_name:string; visited:bool"

Schema strings are output from `sqlitefindtables`, so you can just copy from
there and modify if needed. Each column, separated by a semicolon, is a comma
separated list of types. If a column starts with `name:`, then `name` is used
as the column name. You can use the following types:

  * `?` - Specifies unknown, could be any type.
  * `bool` - Assumes schema format 4 or higher is used. If older schema, use
             "int8".
  * `null` - Fields cannot be NULL by default, don't forget to add this if
             needed.
  * `notnull` - Negates a previous "null".
  * `int`
  * `int<n bits>` - `<n bits>` must be one of 8, 16, 24, 32, 48, 64
  * `float`
  * `string` / `blob`
  * `timestamp` - Same as `int64`.
  * `<serial type>` - A serial type number as defined by the [Sqlite file
                    format](https://www.sqlite.org/fileformat2.html#record_format).

One thing to notice is that **NULL is not allowed by default**. Make sure to
add `null` to your type list if it is a possible value.


Output Format
-------------

You can include different values in the output using the "-O" option, which is
a comma separated list of:

  * `values` - A field for each sqlite column.
  * `all_values` - One field that is a list of every sqlite column.
  * `address` - Address the sqlite row was found in memory.
  * `all_types` - A list of types for each column in this row. Each type will
                  be an integer serial type.

For example, to show the memory address of the row followed by the values:

    $ volatility -f <memory file> sqlitefind \
                 -c "int,null; string; bool" \
                 -O "address,all_values"

CSV output is also supported, using "--output=csv":

    $ volatility -f <memory file> sqlitefind \
                 -c "id:int,null; field1:string; field2:bool" \
                 -O "address,values" \
                 --output=csv --output-file=data.csv


Limitations
===========

Needle Size - Based on the table schema, we may not be able to find a suitable
sequence of bytes to search for. The smaller the needle size, the slower the
search will take.

Large Records - If a record does not fit in one B-Tree cell, it will be either
missed or corrupted. This is because the rows are searched without using any
database header information. If a row is large enough to be split between
multiple pages, we can only find the data from the first page. After that,
we will either read garbage data, or encounter an error and assume that it's
not a real row.

False positives - There are a lot of checks to make the data parsed is actually
a row, but especially when there are not many columns, false positives can be
found. Usually false positives are easy to recognize by hand. They typically
contain many NULL values (None) and strings will contain nonsensical data.


About
=====

Written by Michael Brown as a project for the Computer Forensics class taught
by Fabian Monrose at the University of North Carolina Chapel Hill. Feel free to contact me at [michael@msbrown.net](mailto:michael@msbrown.net), or start an issue on [GitHub](https://github.com/mbrown1413/SqliteFind).

The idea of searching for sqlite database rows in memory is based on Dave
Lassalle's (@superponible) [firefox volatility
plugins](https://github.com/superponible/volatility-plugins), which can find
firefox and chromium data in memory. I wanted to generalize the idea so no code
would need to be updated when a schema changes, and any sqlite database could
be recovered.
