
import sys

import sqlite3

def main():
    dbname = sys.argv[1]

    with sqlite3.connect(dbname) as con:
        cur = con.cursor()

        cur.execute('DROP TABLE IF EXISTS testtable')
        cur.execute('CREATE TABLE testtable (id INT, i INT NOT NULL, even BOOLEAN, odd BOOLEAN, s TEXT)')

        for i in range(1000):
            text = "This is testtable row {}".format(i)
            cur.execute('INSERT INTO testtable VALUES (?, ?, ?, ?, ?)',
                    (i, i, i%2==0, i%2==1, text))

if __name__ == "__main__":
    main()
