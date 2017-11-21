"""
Volatility commands for finding sqlite database rows in memory.

    sqlitefindtables: Find table schemas by searching for sqlite_master table.
    sqlitefind: Find database rows given a table name or schema.
"""

import csv

from volatility.scan import BaseScanner
from volatility.commands import Command
from volatility import utils
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex
import volatility.debug as debug

import yara

import sqlitetools

PREDEFINED_TABLES = {
    "firefox_cookies": "id:int,null; baseDomain:string; originAttributes:string; name:string; value:string; host:string; path:string; expiry:int; lastAccessed:int; creationTime:int; isSecure:bool; isHttpOnly:bool; appId:int; inBrowserElement:bool",
    "sqlite_master": "type:string; name:string; tbl_name:string; rootpage:int; sql:string",
}

class SqliteFind(Command):

    def __init__(self, config, *args, **kwargs):
        super(SqliteFind, self).__init__(config, *args, **kwargs)
        config.add_option('TABLE-NAME', short_option="t", default=None,
            help="Searches for the schema of the given table name in the "
            "sqlite_master table, then uses that schema to find rows of that "
            "table.")
        config.add_option('COL-TYPES', short_option='c', default=None,
            help='Descriptor of types each column can have') # TODO: Better help
        config.add_option('OUTPUT-COLS', short_option='O', default="values",
            help='What fields to include in the output. Comma separated list '
                'of any of the values: "all_values" - all of the row\'s values '
                'in one field; "values" - Row\'s values in separate fields; '
                '"address" - Address of row in memory; "all_types" - List of all '
                'serial types in one field; "row_id" - Sqlite rowid that is '
                'unique within a table.')
        config.add_option('PREDEFINED-TABLE', short_option="P", default=None,
            choices=PREDEFINED_TABLES.keys(),
            help='Choose column types from a set of predefined tables. Use '
                'this instead of "-c" if the table you are searching for is '
                'already predefined.')
        config.add_option('HEURISTICS', short_option="H", default=False,
            action="store_true",
            help="Try to refine column types based on the column name.")
        config.add_option('PRINT-NEEDLE', default=False, action="store_true",
            help="Print information about the search needle instead of "
                "performing search.")

        self.searcher = sqlitetools.RowSearch(self.schema)
        print "Needle Size: {}".format(self.searcher.needle.size)
        if self.searcher.needle.size < 3:
            print "WARNING: Needle size is small. Things may run slowly."

    def calculate(self):
        if self._config.PRINT_NEEDLE:
            needle = sqlitetools.RowSearch(self.schema, verbose=True)
            return

        address_space = utils.load_as(self._config, astype="physical")
        for address, row_id, types, values in self.searcher.find_records(address_space):
            yield address, row_id, types, values

    @property
    def schema(self):
        if hasattr(self, "_schema"):
            return self._schema

        if (self._config.TABLE_NAME,
            self._config.COL_TYPES,
            self._config.PREDEFINED_TABLE).count(None) != 2:
                debug.error("Exactly one of the following options should be "
                    "used: --table-name (-t), --col-types (-c), "
                    "--predefined-table (-P)")

        if self._config.TABLE_NAME is not None:

            # Use SqliteFindTables command to search for sqlite_master table.
            table_finder = SqliteFindTables(self._config)
            col_type_str = None
            some_table_found = False
            for table_name, needle_size, schema in table_finder.calculate(self._config.HEURISTICS):
                some_table_found = True
                #TODO: For now, we just find the fist matching table.
                if table_name.lower() == self._config.TABLE_NAME.lower():
                    col_type_str = schema
                    break
            if not some_table_found:
                debug.error("No sqlite_master table found. Either there are "
                    "no databases in memory, or the master table is not "
                    "present. If you know the table schema you want to search "
                    "for, you can specify --col-types (-c), or use "
                    "--predefined-table (-P).")
            if col_type_str is None:
                debug.error('Could not find table {} in sqlite_master. Try '
                    "using the sqlitefindtables command to search for "
                    "tables.".format(self._config.TABLE_NAME))

        if self._config.COL_TYPES is not None:
            col_type_str = self._config.COL_TYPES
        if self._config.PREDEFINED_TABLE is not None:
            col_type_str = PREDEFINED_TABLES[self._config.PREDEFINED_TABLE]

        self._schema = sqlitetools.TableSchema.from_str(col_type_str, self._config.HEURISTICS)
        return self._schema

    @property
    def col_names(self):
        return self.schema.col_names

    def format_output_fields(self, datum):
        """
        Given an item returned from `calculate()`, returns the list of fields
        for this row.
        """
        address, row_id, types, values = datum
        for field_desc in self._config.OUTPUT_COLS.split(','):
            if field_desc == "all_values":
                yield str(values)
            elif field_desc == "values":
                for value in values:
                    yield str(value)
            elif field_desc == "address":
                yield Address(address)
            elif field_desc == "all_types":
                yield str(types)
            elif field_desc == "row_id":
                yield row_id

    def get_output_fields(self):
        """Returns a list of column names for the output."""
        for field_desc in self._config.OUTPUT_COLS.split(','):
            if field_desc == "all_values":
                yield "Values", str
            elif field_desc == "values":
                for name in self.col_names:
                    yield name, str
            elif field_desc == "address":
                yield "Address", Address
            elif field_desc == "all_types":
                yield "Types", str
            elif field_desc == "row_id":
                yield "Row ID", int
            else:
                debug.error('Unknown field "{}"'.format(field_desc))

    def unified_output(self, data):
        return TreeGrid(
            list(self.get_output_fields()),
            self.generator(data)
        )

    def generator(self, data):
        for datum in data:
            yield (0, list(self.format_output_fields(datum)))

    def render_csv(self, outfd, data):
        header_row = []
        for field_name, field_type in self.get_output_fields():
            header_row.append(field_name)
        outfd.write(', '.join(header_row))
        outfd.write('\n')

        for d in data:
            fields = list(self.format_output_fields(d))
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(fields)


class SqliteFindTables(Command):

    def __init__(self, config, *args, **kwargs):
        super(SqliteFindTables, self).__init__(config, *args, **kwargs)
        config.add_option('RAW-SQL', short_option='R', default=False,
            action="store_true",
            help='Return a raw CREATE TABLE sql statement instead of column '
                'type string')

    def calculate(self, use_heuristics=False):
        address_space = utils.load_as(self._config, astype="physical")

        # Special needle: the first field, "type", is always equal to "table"
        # for the entries we're looking for.
        #
        # You might think a better needle is looking for "CREATE TABLE" in the
        # "sql" field, but we can't count backwards over other text fields to
        # get to the beginning of the record.
        needle = sqlitetools.Needle(
            yara.compile(source='rule r1 { strings: $a = "table" condition: $a }'),
            size=5,
            varint_offset=-8,
            byte_offset=0,
        )
        schema = sqlitetools.TableSchema.from_str(PREDEFINED_TABLES["sqlite_master"])
        searcher = sqlitetools.RowSearch(schema, needle)

        for address, row_id, types, values in searcher.find_records(address_space):
            sql = values[4]
            try:
                table_name, table_schema = sqlitetools.TableSchema.from_sql(sql, use_heuristics)
            except sqlitetools.SqlParsingError as e:
                continue
            if table_name != values[2]:
                continue

            needle_size = sqlitetools.RowSearch(table_schema).needle.size

            if self._config.RAW_SQL:
                yield table_name, needle_size, sql
            else:
                yield table_name, needle_size, str(table_schema)

    def unified_output(self, data):
        return TreeGrid([
                ("Name", str),
                ("Needle Size", int),
                ("Column Type String", str),
            ],
            self.generator(data)
        )

    def generator(self, data):
        for name, needle_size, col_type_str in data:
            yield (0, [str(name), needle_size, str(col_type_str)])

    def render_csv(self, outfd, data):
        if self._config.RAW_SQL:
            outfd.write('Name, Needle Size, SQL\n')
        else:
            outfd.write('Name, Needle Size, Column Type String\n')
        for row in data:
            csv.writer(outfd,quoting=csv.QUOTE_ALL).writerow(row)
