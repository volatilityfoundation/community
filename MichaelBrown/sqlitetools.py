"""
Parsing tools for sqlite records.

These tools are aimed at reading rows from a database file when parts of the
file are missing or corrupted. It does not depend on reading the database
header information, but it it helpful to have prior knowledge about the column
types.

Limitations:

  * If a record does not fit in one B-Tree leaf cell, it will be either missed
    or corrupted.
  * False positives can be found (i.e. data that looks like a row but isn't).

To understand the code, it will be useful to be familiar with the sqlite3
format, in particular the serial types (integers representing the type of a
column) and the storage structure of rows. The sqlite format is described here:

    https://www.sqlite.org/fileformat2.html

"""

import struct
import string
from collections import namedtuple

import yara
import volatility


class SqliteParseError(Exception):
    pass

class SqlParsingError(Exception):
    def __init__(self, sql, *args):
        self.sql = sql
        super(SqlParsingError, self).__init__(*args)


#######################################
########## Type Definitions ###########
#######################################

class Type(object):

    def __init__(self, *names, **kwargs):
        """
        Required:
            names: The names that this type could be called in an SQL
                statement. For example, a boolean could either be referred to
                as "bool" or "boolean".
            serial_types: List of integer serial types that this type may be
                stored as. None means there are too many serial types to
                enumarate, (i.e. string, blob).
            size_func: A function that takes a serial type integer and returns
                the length of the data storage.
            decode_func: A function that takes a serial type integer and a data
                buffer, and returns a decoded value that represents the data.
        Optional:
            serial_type_test - A function that takes a serial type integer and
                returns True if this type can be stored as that serial type.
                Used when `serial_types` is None for strings and blobs. If not
                given, falls back to testing membership of `serial_types`.
        """
        self.names = names
        for attr in 'serial_types serial_type_test size_func decode_func'.split():
            setattr(self, attr, kwargs.pop(attr, None))
        if kwargs:
            raise ValueError("Extraneous kwargs {}".format(kwargs))

    def __str__(self):
        return self.name

    @property
    def name(self):
        return self.names[0]

    def matches_stype(self, stype):
        """
        Returns boolean indicating if this type can have the given serial type.
        """
        if self.serial_type_test:
            return self.serial_type_test(stype)
        else:
            return stype in self.serial_types

    def size(self, stype):
        """How many bytes the storage data for this type is."""
        if self.size_func:
            return self.size_func(stype)

    def decode(self, stype, buf, start=0):
        """Returns the value of the data in `buf` starting at `start`."""
        l = self.size(stype)
        buf = buf[start:start+l]
        if len(buf) < l:
            raise SqliteParseError("Not enough bytes in buffer to decode column")
        value = self.decode_func(stype, buf)
        return value, l

    def matches_str(self, s):
        """Returns True if the sql type string refers to this type."""
        #TODO: Matches with numbers, like "varchar(100)"
        for name in self.names:
            if s == name:
                return True
        if self.names[0] == "string" and s.startswith("varchar"):
            return True
        if self.names[0] == "blob" and s.startswith("blob"):
            return True
        return False

    def __repr__(self):
        return "<SqliteType {}>".format(self.name)

    @classmethod
    def from_int(cls, stype):
        """Return the appropriate type given a serial type."""
        for t in TYPES:
            if t.matches_stype(stype):
                return t

    @classmethod
    def from_str(cls, s):
        """Return the appropriate type given an sql type."""
        #TODO: Matches with numbers, like "varchar(100)"
        s = s.lower()
        for t in TYPES:
            if t.matches_str(s):
                return t
        raise ValueError('Unrecognized type in schema: "{}"'.format(s))

def _reserved_stype_error(*args):
    raise SqliteParseError("Reserved stype used")

# Serial type meanings taken directly from:
#   https://www.sqlite.org/fileformat2.html#record_format
TYPES = (
    Type("null",
        serial_types = (0,),
        size_func = lambda stype: 0,
        decode_func = lambda stype, buf: None,
    ),
    Type("bool", "boolean",
        serial_types = (8, 9),
        size_func = lambda stype: 0,
        decode_func = lambda stype, buf: 0 if stype == 8 else 1,
    ),
    Type("int", "integer",
        serial_types = (1, 2, 3, 4, 5, 6, 8, 9),
        size_func = lambda stype: {
                1: 1,
                2: 2,
                3: 3,
                4: 4,
                5: 6,
                6: 8,
                8: 0,
                9: 0,
            }[stype],
        decode_func = lambda stype, buf: parse_twos_comp_bytes(buf),
    ),
    Type("float",
        serial_types = (7,),
        size_func = lambda stype: 8,
        decode_func = lambda stype, buf: \
            struct.unpack('>d', ''.join(buf[start:start+8]))[0],
    ),
    Type("blob",
        serial_types = None,
        serial_type_test = lambda stype: stype >= 12 and stype & 1 == 0,
        size_func = lambda stype: (stype-12) / 2,
        decode_func = lambda stype, buf: buf.encode('string_escape')
    ),
    Type("string", "text", "longvarchar", "varchar",
        serial_types = None,
        serial_type_test = lambda stype: stype >= 13 and stype & 1 == 1,
        size_func = lambda stype: (stype-13) / 2,
        decode_func = lambda stype, buf: buf.encode('string_escape')
    ),
    Type("reserved",
        serial_types = (10, 11),
        size_func = _reserved_stype_error,
        decode_func = _reserved_stype_error,
    ),
    Type("?", "any", "unknown",
        serial_types = None,
        serial_type_test = lambda stype: True,
        size_func = None,
        decode_func = None,
    ),
    Type("timestamp",
        serial_types = (6,),
        size_func = lambda stype: 8,
        #TODO: Parse into datetime object
        decode_func = lambda row_id, stype, buf: parse_twos_comp_bytes(buf),
    ),
    Type("primarykey",
        serial_types = (0,),
        size_func = lambda stype: 0,
        # Primary keys are always NULL, their value is the row_id.
        # Decoding handled specially, replaced with row_id in `parse_record()`.
    ),
)

###################################
########## Table Schema ###########
###################################

class TableSchema(object):
    """
    Stores the schema for a table including any possible types that each column
    is expected to have.
    """

    def __init__(self, type_sets, col_names, use_heuristics=False):
        """
        `type_sets`: A list where each item is a set of Type objects. This is
            the set of possible types for each column.
        `col_names`: A list of names for each column. If a name is None it will
            be given a name based on its column number.
        `use_heuristics`: If True, reduces the number of possible types using
            heuristics based on the table name.
        """
        if use_heuristics:
            type_sets = apply_heurstics(type_sets, col_names)

        self.type_sets = type_sets
        self._col_names = list(col_names)
        for i in range(len(self.type_sets)-len(self._col_names)):
            self._col_names.append(None)
        for i in range(len(self._col_names)-len(self.type_sets)):
            self.type_sets.append(None)

    def __len__(self):
        return self.n_cols

    @property
    def n_cols(self):
        return len(self.type_sets)

    @property
    def col_names(self):
        for i, name in enumerate(self._col_names):
            if name is None:
                yield "Col {}".format(i)
            else:
                yield name

    def col_is_primary_key(self, col_num):
        type_set = self.type_sets[col_num]
        return len(type_set) == 1 and list(type_set)[0].name == "primarykey"

    def __str__(self):
        result = []
        for name, types in zip(self._col_names, self.type_sets):
            types_str = ','.join(str(t) for t in types)
            if name == None:
                result.append(types_str)
            else:
                result.append("{}:{}".format(name, types_str))
        return '; '.join(result)

    def __iter__(self):
        for type_set in self.type_sets:
            yield type_set

    @classmethod
    def from_str(cls, s, use_heuristics=False):
        types = []
        names = []
        for col_str in s.split(';'):

            if ':' in col_str:
                names.append(col_str[:col_str.index(':')])
                col_str = col_str[col_str.index(':')+1:]
            else:
                names.append(None)

            type_set = set()
            for t in col_str.split(','):
                t = t.strip()
                type_set.add(Type.from_str(t))
            types.append(type_set)

        return TableSchema(types, names, use_heuristics)

    @classmethod
    def from_sql(cls, sql, use_heuristics):
        if not all([c in string.printable for c in sql]):
            raise SqlParsingError(sql, "SQL contains non-printable characters")
        if not sql.startswith("CREATE TABLE "):
            raise SqlParsingError(sql, 'Did not begin with "CREATE TABLE "')
        if not sql.index('('):
            raise SqlParsingError(sql, 'Could not find "("')
        table_name = sql[len("CREATE TABLE "):sql.index('(')].strip()

        col_part = _crop_matching_paren(sql, sql.index('('))
        if col_part is None:
            raise SqlParsingError(sql, "Couldn't find matching parenthesis")

        #TODO: Don't split on comma inside parenthesis "(blah, blah)".
        #      This can happen with uniqueness constraints.
        names = []
        type_sets = []
        for col_str in col_part.split(","):
            col_str = col_str.strip()
            words = col_str.split()
            if len(words) < 2:
                raise SqlParsingError(sql, "Not enough words for a column name and type")
            names.append(words[0])
            type_str = words[1].lower()
            try:
                t = Type.from_str(type_str)
            except ValueError:
                raise SqlParsingError(sql, 'Unrecognized SQL type: "{}"'.format(type_str))
            type_set = set([t])
            if "NOT NULL" not in col_str:
                type_set.add(Type.from_str("null"))

            if "PRIMARY KEY" in col_str:
                type_set = set([Type.from_str("primarykey")])

            type_sets.append(type_set)

        return table_name, TableSchema(type_sets, names, use_heuristics)

def _crop_matching_paren(s, start):
    """
    Return substring within two matching parenthesis, given the position of the
    open parenthesis.
    """
    assert s[start] == '('

    p_count = 0
    end = None
    for i, c in enumerate(s[start+1:]):
        if c == '(':
            p_count += 1
        elif c == ')':
            p_count -= 1
        if p_count == -1:
            end = start+i+1
            break

    if end is None:
        return None
    assert s[end] == ')'
    return s[start+1 : end]

def apply_heurstics(type_sets, col_names):
    new_type_sets = []
    for type_set, col_name in zip(type_sets, col_names):
        col_name = col_name.lower()

        if ("date" in col_name or "time" in col_name) and Type.from_str("int") in type_set:
            new_set = set([Type.from_str("timestamp")])

        else:
            new_set = type_set.copy()

        new_type_sets.append(new_set)
    return new_type_sets


##################################################
########## Record Parsing And Encoding ###########
##################################################

def parse_record(buf, start=0, schema=None):
    """
    Reads a record in `buf` at position `start`. Return a tuple of serial types
    and a tuple of corresponding values. Many checks are made to validate that
    the data is indeed a record. If any of these checks fail, a
    `SqliteParseError` is raised.

    `start` should be the offset inside `buf` of the record payload length,
    which is the field directly before the row id and header length.

    If given, `schema` is a `TableSchema` object representing the expected
    types of the row. If the observed types do not match, SqliteParseError is
    raised.
    """
    i = start  # i always points to the next byte in buf to parse

    # Payload length
    payload_len, l = parse_varint(buf, i)
    i += l

    # Row ID
    row_id, l = parse_varint(buf, i)
    i += l

    # Header length
    header_start = i
    header_len, l = parse_varint(buf, i)
    i += l

    # Check: Header length
    if header_len < 2:
        raise SqliteParseError("Header length {} too small".format(header_len))
    if schema:
        # Each varint takes 1 to 9 bytes. There is one varint storing the
        # header length, then one for each column.
        max_header_len = 9 * (1 + schema.n_cols)
        min_header_len = 1 * (1 + schema.n_cols)
        if header_len > max_header_len:
            raise SqliteParseError("Header length of {} is too long for {} "
                                   "cols".format(header_len, schema.n_cols))
        if header_len < min_header_len:
            raise SqliteParseError("Header length of {} too short for {} "
                                   "cols".format(header_len, schema.n_cols))

    # Column types
    serial_types = []
    while i < header_start + header_len:
        stype, l = parse_varint(buf, i)
        i += l
        serial_types.append(stype)

    # Check: types
    for n, (serial_type, type_set) in enumerate(zip(serial_types, schema)):

        if type_set is None or serial_type in type_set:
            continue

        col_matched = False
        for t in type_set:
            if t.matches_stype(serial_type):
                col_matched = True
                break

        if not col_matched:
            raise SqliteParseError("Serial type for col {} was {}, not "
                    "one of the expected {}".format(n, serial_type,
                                                    type_set))

    # Check: Record Length
    if i != header_start + header_len:
        raise SqliteParseError("Record header was not the correct length.")

    # Check: n_cols
    if schema and len(serial_types) != schema.n_cols:
        raise SqliteParseError("Expected {} columns, got "
                               "{}".format(schema.n_cols, len(serial_types)))

    # Parse columns
    values = []
    for n, stype in enumerate(serial_types):
        if schema and schema.col_is_primary_key(n):
            value, l = row_id, 0  # Primary keys take on value of row_id
        else:
            value, l = Type.from_int(stype).decode(stype, buf, i)
        if l < 0:
            #TODO: Not sure what the technically correct thing to do when a
            #      varint encoding a type in the header is negative.
            raise SqliteParseError("Negative string/blob length")
        i += l
        values.append(value)

    # Check: payload length
    actual_payload_len = i - header_start
    if actual_payload_len != payload_len:
        raise SqliteParseError("Payload length field does not match actual "
                               "length of payload. payload_len={}, actual "
                               "length={}".format(payload_len, actual_payload_len))

    return row_id, serial_types, values

def count_varints(buf, start=0, n=1, backward=False):
    """
    Start at a varint at `start` in `buf` and return `n` varints forward or
    backward.

    `start` must point to the first byte of a varint already, or if `backward`
    is True then it must point one byte after a varint ends. Returned is an
    index into `buf` that is `n` varints backwards or forwards from `start`.

    `SqliteParseError` may be raised if the varints are not valid in some way.
    """
    if n < 0:
        n = -n
        backward = not backward
    elif n == 0:
        return start

    if not backward: raise NotImplementedError()  #TODO

    pos = start
    for i in range(n):
        pos -= 1

        # If the last byte of a varint has bit 0x80 set, it must be a nine byte
        # varint.
        nine_byte = False
        if ord(buf[pos]) & 0x80:
            nine_byte = True

        for j in range(8):
            if ord(buf[pos-1]) & 0x80 != 0x80:
                break
            pos -= 1

        if nine_byte and j+1 != 9:
            raise SqliteParseError("Varint ended with 0x80 bit set but was "
                                   "not 9 bytes.")

    return pos

def parse_varint(buf, start=0):
    """Returns (varint integer value, size of varint 1-9)."""
    bits = []
    for i in range(9):
        if start+i >= len(buf):
            raise SqliteParseError("Ran off end of buffer while reading varint")
        byte = ord(buf[start+i])

        # Lower 7 bits are part of the int value
        # Last byte all 8 bits are part of the int value
        for j in range(8 if i==8 else 6, -1, -1):
            bits.append((byte >> j) & 1)

        # Highest bit indicates if there is another byte following
        if byte & 0x80 != 0x80:  # No more bytes
            break

    x = int(''.join(map(str, bits)), 2)  # Convert bits into an integer
    return twos_comp(x, 64), i+1

def encode_varint(i):
    """Return string of bytes encoding `i` into a varint."""
    varint_bits = []
    i_bits = encode_twos_comp_bits(i, 64)

    if len(i_bits) > 7:
        raise NotImplementedError()  #TODO

    return chr(int('0' + i_bits, 2))

def twos_comp(uint, n_bits):
    if uint >> (n_bits - 1):  # Negative
        return -( (~(uint - 1)) & ((1 << n_bits) - 1) )
    else:
        return uint  # Positive

def parse_twos_comp_bytes(buf, n_bits=None):
    """Return the integer represented in two's compliment in `buf`."""
    if n_bits is None:
        n_bits = len(buf)*8

    num = 0
    digit_value = 1
    for byte in buf[::-1]:
        num += ord(byte) * digit_value
        digit_value *= 256

    return twos_comp(num, n_bits)

def encode_twos_comp_bits(i, n_bits):
    """Return the bits in two's compliment format of the signed integer `i`."""
    negative = False
    if i < 0:
        raise NotImplementedError()  #TODO

    if i >= (1 << (n_bits - 1)):
        raise ValueError("{} too large for {}-bit int".format(i, n_bits))

    return bin(i)[2:]


################################
########## Searching ###########
################################

# Needle
# `yara_rule`: A rule (created with `yara.compile()`) of what to search for.
# `size`: The length of the search string.
# `varint_offset`: The number of varints to count to get from the match to the
#     beginning of the record. Will usually be negative to count backwards.
# `byte_offset`: Number of bytes to count (after counting `varint_offset`
#     varints) to get to the beginning of the record.
Needle = namedtuple("Needle", "yara_rule size varint_offset byte_offset")

class RowSearch(object):

    def __init__(self, schema, needle=None, verbose=False):
        self.schema = schema

        if needle:
            self.needle = needle
        else:
            self.needle = _get_search_needle(self.schema, verbose)

    @property
    def n_cols(self):
        return self.schema.n_cols

    def find_records(self, address_space):
        found_rows = set()
        for buf, offset, absolute_offset in _search_addr_space(address_space, self.needle.yara_rule):
            try:

                # Count back a number of varints and bytes according to needle
                record_start = count_varints(buf, offset, self.needle.varint_offset) + self.needle.byte_offset

                row_id, types, values = parse_record(buf, record_start, self.schema)
                row = (tuple(types), tuple(values))
                if row not in found_rows:
                    found_rows.add(row)
                    yield absolute_offset, row_id, types, values

            except SqliteParseError as e:
                pass  # Match is not an actual record  :(

def _get_search_needle(schema, verbose=False):
    type_sets = list(schema)

    def verbose_print(string):
        if verbose:
            print string

    # Find start, length of needle
    # Our needle will be in the row header, but it can't overlap any string or
    # blob fields, since the varints representing those types can be more than
    # 1 byte.
    def can_use_col(type_set):
        for t in type_set:
            if not t.serial_types:
                return False
        return True
    usable_cols = map(can_use_col, type_sets)
    start, length = _longest_run(usable_cols)

    if start is None:
        verbose_print("Could not use any field for needle.")
        return Needle(None, 0, 0, 0)
    else:
        verbose_print("Needle start={} length={}".format(start, length))

    # Build yara hex string
    hex_str = []
    for types in type_sets[start:start+length]:
        hex_str.append('(')

        type_choices = []
        for t in types:
            for stype in t.serial_types:
                type_choices.append(hex(stype)[2:].zfill(2))
        hex_str.append(' | '.join(type_choices))

        hex_str.append(')')
    hex_str = ' '.join(hex_str)

    rule_str = "rule r1 {{ strings: $a = {{ {} }} condition: $a }}".format(hex_str)
    yara_rule = yara.compile(source=rule_str)

    verbose_print("Yara Rule: "+rule_str)

    # Our search puts us `start` varints into the header. There are `start`+3
    # varints (row id, payload length, header length) to count back until we
    # get to the start of the cell.
    return Needle(yara_rule, length, -start-3, 0)

def _longest_run(xs):
    """
    Return start index and length of the longest run in the list `xs` of items
    that evaluate to True. Return (None, None) if all items are False.
    """
    in_run = False
    run_start = None
    longest_run_len = None
    longest_run_start = None
    for i, x in enumerate(xs):

        if in_run and not x:
            in_run = False
        elif not in_run and x:
            in_run = True
            run_start = i

        if in_run:
            run_len = i - run_start + 1
            if run_len > longest_run_len:
                longest_run_len = run_len
                longest_run_start = run_start

    return longest_run_start, longest_run_len

def _search_addr_space(address_space, yara_rule):
    """Searches the address space using the given yara rule.

    Yields tuples of `(buf, position, absolute_offset)`, where `buf` contains
    the match, `buf[position]` is the start of the match, and `absolute_offset`
    is the absolute address within `address_space` that the match occured.
    """
    blocksize = 1024 * 1024 * 10
    overlap = 1024
    match_offsets = set()

    # Iterate over each valid run of memory
    pos = 0
    for run_pos, run_size in sorted(address_space.get_available_addresses()):

        # Read in blocks to save memory
        pos = max(run_pos, pos)
        while pos < run_pos+run_size:
            to_read = min(blocksize+overlap, run_pos+run_size - pos)

            # Read and search
            buf = address_space.zread(pos, to_read)
            if yara_rule is not None:

                try:  # Yara search
                    matched_rules = yara_rule.match(data=buf)

                # Reduce blocksize if too many matches were found (yara error 30)
                except yara.Error as e:
                    if e.message == "internal error: 30":
                        blocksize /= 2
                        continue
                    else:
                        raise

                if matched_rules:

                    # Calculate absolute offset of match and yield it
                    for str_pos, str_name, str_value in matched_rules[0].strings:
                        absolute_offset = str_pos + pos
                        if absolute_offset in match_offsets:
                            continue
                        match_offsets.add(absolute_offset)
                        yield buf, str_pos, absolute_offset

            else:  # Fall back to returning every byte if no yara rule given
                for i in range(len(buf)):
                    absolute_offset = i + pos
                    if absolute_offset in match_offsets:
                        continue
                    match_offsets.add(absolute_offset)
                    yield buf, i, absolute_offset

            pos += blocksize
