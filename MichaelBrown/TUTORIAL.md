

Data Files
==========

Download the data files:

  * [firefox.img](https://msbrown.net/sqlitefind/data/firefox.img.zip) - Memory snapshot
  * [firefox_places.sqlite](https://msbrown.net/sqlitefind/data/firefox_places.sqlite) - Places database

In case you want to reproduce this, here are the steps taken to generate
the data files:

  1. Boot an Ubuntu VM.
  2. Open firefox and go to "example.com".
  3. Take memory snapshot.
  4. Copy `places.sqlite` in the firefox profile directory.


Finding Table Schemas
=====================

Each database stores an `sqlite_master` table that contains, among other
things, the schema for each table. Use `sqlitefindtables` command to find
`sqlite_master` tables and extract the schema:

    $ python vol.py -f firefox.img sqlitefindtables
    Name                    Needle Size Column Type String
    uri                               1 id:primarykey; value:null,string
    interpretation                    1 id:primarykey; value:null,string
    manifestation                     1 id:primarykey; value:null,string
    payload                           1 id:primarykey; value:blob,null
    storage                           1 id:primarykey; value:null,string; state:null,int; icon:null,string; display_name:null,string
    text                              1 id:primarykey; value:null,string
    mimetype                          1 id:primarykey; value:null,string
    actor                             1 id:primarykey; value:null,string
    schema_version                    2 schema:primarykey; version:null,int
    moz_downloads                     3 id:primarykey; name:null,string; source:null,string; target:null,string; tempPath:null...eferredApplication:null,string; preferredAction:int; autoResume:int; guid:null,string
    moz_deleted_logins                1 id:primarykey; guid:null,string; timeDeleted:null,int
    moz_disabledHosts                 1 id:primarykey; hostname:null,string
    moz_logins                        5 id:primarykey; hostname:string; httpRealm:null,string; formSubmitURL:null,string; user...ted:null,int; timeLastUsed:null,int; timePasswordChanged:null,int; timesUsed:null,int
    moz_keywords                      1 id:primarykey; keyword:null,string
    moz_bookmarks                     5 id:primarykey; type:null,int; fk:null,int; parent:null,int; position:null,int; title:n... folder_type:null,string; dateAdded:null,int; lastModified:null,int; guid:null,string
    moz_hosts                         2 id:primarykey; host:string; frecency:null,int; typed:int; prefix:null,string
    moz_historyvisits                 6 id:primarykey; from_visit:null,int; place_id:null,int; visit_date:null,int; visit_type:null,int; session:null,int
    moz_places                        6 id:primarykey; url:null,string; title:null,string; rev_host:null,string; visit_count:n...ed:int; favicon_id:null,int; frecency:int; last_visit_date:null,int; guid:null,string
    expiration_notify                 3 id:primarykey; v_id:null,int; p_id:null,int; url:string; guid:string; visit_date:null,int; expected_results:int
    prefs                             3 id:primarykey; groupID:null,int; settingID:int; value:blob,null
    settings                          1 id:primarykey; name:string
    groups                            1 id:primarykey; name:string
    webappsstore2                     1 scope:null,string; key:null,string; value:null,string; secure:null,int; owner:null,string
    mappings                          1 timestamp:null,int; device:null,string; profile:null,string
    properties                        0 device_id:null,string; property:null,string; value:null,string
    devices                           1 device_id:primarykey; device:null,string
    moz_deleted_formhistory           2 id:primarykey; timeDeleted:null,int; guid:null,string
    moz_formhistory                   3 id:primarykey; fieldname:string; value:string; timesUsed:null,int; firstUsed:null,int; lastUsed:null,int; guid:null,string
    moz_openpages_temp                2 url:primarykey; open_count:null,int
    moz_hosts                         5 id:primarykey; host:null,string; type:null,string; permission:null,int; expireType:null,int; expireTime:null,int; appId:null,int; isInBrowserElement:null,int

For each table found, the output contains:

  * `Name`: The name of the table. The ones that start with "moz\_" are the
            firefox tables we're interested in.
  * `Needle Size`: How many bytes the search string will be if we want to find
            this column. Usually, the larger it is, the faster the search will
            be, but the value of the needle matters too, as we'll see later.
  * `Column Type String`: The name and possible types for each column. Each
            column is separated by semicolons, and each column contains
            `<name>:<type list>`.


Finding Table Rows
==================

We'll see if we can recover the `moz_places` table using the `sqlitefind`
command. We'll use `--output=csv` because it's easier to read the output:

    $ python vol.py -f firefox.img sqlitefind -t moz_places --output=csv
    Needle Size: 6
    id,  url,  title,  rev_host,  visit_count,  hidden,  typed,  favicon_id,  frecency,  last_visit_date,  guid
    "19","http://example.com/","Example Domain","moc.elpmaxe.","2","0","1","None","2200","1481564460988099","_Fv9IX1cGpN4"
    "18","https://news.ycombinator.com/","Hacker News","moc.rotanibmocy.swen.","1","0","0","11","2000","1471970845483557","-yx4LJ_nbk3G"
    "17","http://news.ycombinator.com/","None","moc.rotanibmocy.swen.","1","1","1","None","2000","1471970845142035","P27DxOuKc3J7"
    "16","ftp://ftp.cadsoft.de/eagle/program/6.5/eagle-lin-6.5.0.run","eagle-lin-6.5.0.run","ed.tfosdac.ptf.","0","0","0","None","0","1380622374491105","ycrhk8hqi0sX"
    "15","http://www.cadsoftusa.com/download-eagle/","Download - Get the latest Version of EAGLE PCB Design Software","moc.asutfosdac.www.","1","0","0","10","2000","1380622365629820","E0XPgeLbUnt7"
    "14","http://www.cadsoftusa.com/download-eagle","None","moc.asutfosdac.www.","1","1","1","None","2000","1380622365381702","-KeXb16T97q3"
    "13","place:type=6&sort=14&maxResults=10","None","None","0","1","0","None","0","None","CWG5QZhdrc8a"
    "12","place:folder=BOOKMARKS_MENU&folder=UNFILED_BOOKMARKS&folder=TOOLBAR&queryType=1&sort=12&maxResults=10&excludeQueries=1","None","None","0","1","0","None","0","None","-iROkc9lesaB"
    "11","place:sort=8&maxResults=10","None","None","0","1","0","None","0","None","3f9S-ybPqxJQ"
    "10","http://www.mozilla.com/en-US/about/","None","moc.allizom.www.","0","0","0","9","140","None","v954m52YaKnY"
    "9","http://www.mozilla.com/en-US/firefox/community/","None","moc.allizom.www.","0","0","0","8","140","None","Xs7LXVlVstLO"
    "8","http://www.mozilla.com/en-US/firefox/customize/","None","moc.allizom.www.","0","0","0","7","140","None","gwKXiRtxDDpU"
    "7","http://www.mozilla.com/en-US/firefox/help/","None","moc.allizom.www.","0","0","0","6","140","None","9IHO08GS4hHN"
    "6","https://one.ubuntu.com/","None","moc.utnubu.eno.","0","0","0","5","140","None","hFRAM7INfaC-"
    "5","http://www.debian.org/","None","gro.naibed.www.","0","0","0","4","140","None","0oIWVysSUYPa"
    "4","https://answers.launchpad.net/ubuntu/+addquestion","None","ten.daphcnual.srewsna.","0","0","0","3","140","None","pxZ5_DLZREbU"
    "3","http://wiki.ubuntu.com/","None","moc.utnubu.ikiw.","0","0","0","2","140","None","Yw2G4M6G5AMh"
    "2","http://www.ubuntu.com/","None","moc.utnubu.www.","0","0","0","1","140","None","CWrQcMgXMC46"
    "1","http://www.mozilla.com/en-US/firefox/central/","None","moc.allizom.www.","0","0","0","None","140","None","JNfsKR8d0Y7b"
    "19","http://example.com/","Example Domain","moc.elpmaxe.","1","0","1","None","2000","1471970854178187","_Fv9IX1cGpN4"
    "19","http://example.com/","Example Domain","moc.elpmaxe.","2","0","1","None","2000","1481564460988099","_Fv9IX1cGpN4"
    "18","https://news.ycombinator.com/","Hacker News","moc.rotanibmocy.swen.","1","0","0","11","2000","1471970845483557","-yx4LJ_n$D\x00\x00"
    "1","http://www.mozilla.z\x13\xe9\xec\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00b\xa4n3\x00\x00\x00\x00\xd7\xfd","None","\xfb#\xbbK\x02g\xa0\xa0\x0e\x96\x0e""\x8d\xf5\xaf\xcc","0","0","0","None","-26731","None","\x00\x00\x00\x00w\x93\xdb\xe0\x00\x00\x00\x00"

Success! We got some useful data. But there's something off about it,
especially the last row. It looks pretty similar to another row, but then
turns to garbage data, with non-printable characters.


Dealing with Duplicates
=======================

If you look carefully at the rows we found for the `moz_places` table, there
are a few with duplicate ids. "1" and "18" both appear twice, while "19"
appears 3 times. The last row, a duplicate "1", looks like complete junk with
non-printable characters in it, but the other duplicates look completely
normal.

These appear to be memory artifacts, but how do we tell the real for the fake?
Let's have `sqlitefind` output the memory address for each row also, using the
`--output-cols` option:

    $ python vol.py -f firefox.img sqlitefind -t moz_places --output=csv --output-cols=address,values
    Needle Size: 6
    Address, id,  url,  title,  rev_host,  visit_count,  hidden,  typed,  favicon_id,  frecency,  last_visit_date,  guid
    "54657031","19","http://example.com/","Example Domain","moc.elpmaxe.","2","0","1","None","2200","1481564460988099","_Fv9IX1cGpN4"
    "55482793","18","https://news.ycombinator.com/","Hacker News","moc.rotanibmocy.swen.","1","0","0","11","2000","1471970845483557","-yx4LJ_nbk3G"
    "55482891","17","http://news.ycombinator.com/","None","moc.rotanibmocy.swen.","1","1","1","None","2000","1471970845142035","P27DxOuKc3J7"
    "55482977","16","ftp://ftp.cadsoft.de/eagle/program/6.5/eagle-lin-6.5.0.run","eagle-lin-6.5.0.run","ed.tfosdac.ptf.","0","0","0","None","0","1380622374491105","ycrhk8hqi0sX"
    "55483105","15","http://www.cadsoftusa.com/download-eagle/","Download - Get the latest Version of EAGLE PCB Design Software","moc.asutfosdac.www.","1","0","0","10","2000","1380622365629820","E0XPgeLbUnt7"
    "55483264","14","http://www.cadsoftusa.com/download-eagle","None","moc.asutfosdac.www.","1","1","1","None","2000","1380622365381702","-KeXb16T97q3"
    "55483359","13","place:type=6&sort=14&maxResults=10","None","None","0","1","0","None","0","None","CWG5QZhdrc8a"
    "55483421","12","place:folder=BOOKMARKS_MENU&folder=UNFILED_BOOKMARKS&folder=TOOLBAR&queryType=1&sort=12&maxResults=10&excludeQueries=1","None","None","0","1","0","None","0","None","-iROkc9lesaB"
    "55483565","11","place:sort=8&maxResults=10","None","None","0","1","0","None","0","None","3f9S-ybPqxJQ"
    "55483617","10","http://www.mozilla.com/en-US/about/","None","moc.allizom.www.","0","0","0","9","140","None","v954m52YaKnY"
    "55483697","9","http://www.mozilla.com/en-US/firefox/community/","None","moc.allizom.www.","0","0","0","8","140","None","Xs7LXVlVstLO"
    "55483789","8","http://www.mozilla.com/en-US/firefox/customize/","None","moc.allizom.www.","0","0","0","7","140","None","gwKXiRtxDDpU"
    "55483881","7","http://www.mozilla.com/en-US/firefox/help/","None","moc.allizom.www.","0","0","0","6","140","None","9IHO08GS4hHN"
    "55483968","6","https://one.ubuntu.com/","None","moc.utnubu.eno.","0","0","0","5","140","None","hFRAM7INfaC-"
    "55484035","5","http://www.debian.org/","None","gro.naibed.www.","0","0","0","4","140","None","0oIWVysSUYPa"
    "55484101","4","https://answers.launchpad.net/ubuntu/+addquestion","None","ten.daphcnual.srewsna.","0","0","0","3","140","None","pxZ5_DLZREbU"
    "55484201","3","http://wiki.ubuntu.com/","None","moc.utnubu.ikiw.","0","0","0","2","140","None","Yw2G4M6G5AMh"
    "55484269","2","http://www.ubuntu.com/","None","moc.utnubu.www.","0","0","0","1","140","None","CWrQcMgXMC46"
    "55484334","1","http://www.mozilla.com/en-US/firefox/central/","None","moc.allizom.www.","0","0","0","None","140","None","JNfsKR8d0Y7b"
    "229620056","19","http://example.com/","Example Domain","moc.elpmaxe.","1","0","1","None","2000","1471970854178187","_Fv9IX1cGpN4"
    "328507223","19","http://example.com/","Example Domain","moc.elpmaxe.","2","0","1","None","2000","1481564460988099","_Fv9IX1cGpN4"
    "328507305","18","https://news.ycombinator.com/","Hacker News","moc.rotanibmocy.swen.","1","0","0","11","2000","1471970845483557","-yx4LJ_n$D\x00\x00"
    "368074726","1","http://www.mozilla.z\x13\xe9\xec\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00b\xa4n3\x00\x00\x00\x00\xd7\xfd","None","\xfb#\xbbK\x02g\xa0\xa0\x0e\x96\x0e""\x8d\xf5\xaf\xcc","0","0","0","None","-26731","None","\x00\x00\x00\x00w\x93\xdb\xe0\x00\x00\x00\x00"

The `--output-cols=` option lets you configure what information is output. The
default is just `values`, which outputs each of the database fields. Use
`--help` to get more info, and other nifty options.

Most of the rows seem to be clumped together around the same addresses...
except the duplicates! Although this isn't a perfect method, it correctly
identifies the duplicates in this case. You can check `firefox_places.sqlite`
to see that those are actually the correct rows (although some changed a bit
between when I took the snapshot and copied the database file).


Needles Matter
==============

Let's try another table, `moz_historyvisits`:

    $ python vol.py -f firefox.img sqlitefind -t moz_historyvisits --output=csv
    Needle Size: 6
    id,  from_visit,  place_id,  visit_date,  visit_type,  session
    "7","None","None","None","None","None"
    "0","None","None","None","None","None"
    "86","12374025","None","None","None","None"
    "58","None","None","None","None","None"
    ....

Okay, so it takes a lot longer. Actually I don't know how long because I
stopped it after a while. It also outputs what seems like bad data, with mostly
just "None" (translated from NULL field values). What's happening here is that
0x00 is a really common in memory, and we're finding a lot of things that look
like database rows, because 0x00 is the NULL type in sqlite. This also makes it
slow because a lot of potential matches are found by yara that just get thrown
out later by the sqlite parsing code.

Fortunately, we can can tweak things. If you look at the output of
`sqlitefindtables`, you'll see the table definition used:

    id:primarykey; from_visit:int,null; place_id:int,null; visit_date:int,null; visit_type:int,null; session:int,null

This schema string has database columns separated by a semicolon. Each
column has a name, and a list of types that the column might contain.

Although this table definition allows NULL for most fields, in practice most
rows won't have NULL. Of course, this depends on the particular table you're
looking for, but we can at least try taking away NULL to see if it helps.
Here's our new table schema:

    id:primarykey; from_visit:int,null; place_id:int,null; visit_date:int,null; visit_type:int,null; session:int,null

Now we can use the `sqlitefind` command to search for this new table
definition. Instead of using `-t` to specify the table name, we use `-c` to
manually specify the schema:

    $ python vol.py -f firefox.img sqlitefind -c "id:primarykey; from_visit:int; place_id:int; visit_date:int; visit_type:int; session:int"
    Needle Size: 6
    id  from_visit  place_id  visit_date       visit_type  session
    6  0           19        1471970854178187 2           0
    5  4           18        1471970845483557 5           0
    4  0           17        1471970845142035 2           0
    3  2           16        1380622374491105 7           0
    2  1           15        1380622365629820 5           0
    1  0           14        1380622365381702 2           0
    7  0           19        1481564460988099 2           0
    2  1           15        1380622749007732 5           0

Perfect! We found what we're looking for. Notice that the needle didn't get any
larger, but the search still goes a lot faster. Apparently, size isn't
everything.

We can also use the `-c` option to search for tables when we know the schema
beforehand, even if we can't find the `sqlite_master` table defining their
schema.
