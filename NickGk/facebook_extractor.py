"""
@author:       Nick Gk (@ngkogkos)
@license:      The MIT License (MIT)
@contact:      ngkogkos@protonmail.com
"""

# Volatility's stuff
import volatility.commands as commands
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.obj as obj
from volatility.renderers.html import HTMLRenderer, JSONRenderer

# Auxiliary modules
from hashlib import sha1
from datetime import datetime
import json
import pprint
import struct

# TO-DO:
#


def isprintable(s, codec='utf8'):
    """Checks where a character is Printable or not."""
    try:
        s.decode(codec)
    except UnicodeDecodeError:
        return False
    else:
        return True


class FacebookScanner(scan.BaseScanner):
    """Scans for needles inheriting from BaseScanner."""
    checks = []

    def __init__(self, needles=None):
        self.needles = needles
        self.checks = [("MultiStringFinderCheck", {'needles': needles})]
        scan.BaseScanner.__init__(self)

    def scan(self, address_space, offset=0, maxlen=None):
        for offset in scan.BaseScanner.scan(self, address_space,
                                            offset, maxlen):
            yield offset


class FacebookFindOwner():
    """Finds the Facebook Account Owner's ID."""

    def findowner(self, address_space):
        start_tag = "/auth/user_data/fb_me_user{\"uid\":\""
        stop_tag = "\",\"first_name\":\""
        # Maintain a list of possible Owners!
        uniqueOwnerIDs = []

        scanner = FacebookScanner(needles=[start_tag])
        for offset in scanner.scan(address_space):
            fb_buff = address_space.read(offset+len(start_tag), 256)
            iter1 = 0
            while iter1 < len(fb_buff):
                # Make sure that the owner's ID weren't found again,
                # and also it is numerical and not some random rubbish
                if fb_buff[iter1:iter1+len(stop_tag)] == stop_tag and \
                            fb_buff[:iter1].isdigit() and \
                            fb_buff[:iter1] not in uniqueOwnerIDs:
                        uniqueOwnerIDs.append(fb_buff[:iter1])
                iter1 += 1
        # This is in case more than 1 people logged in
        # into facebook prior capturing the RAM dump
        if len(uniqueOwnerIDs) > 1:
            print "Found more than one possible Owner IDs: ",
            print uniqueOwnerIDs
            return "multipleids"
        elif len(uniqueOwnerIDs) == 1:
            return uniqueOwnerIDs[0]
        else:
            return "unknown"


class FacebookGrabInfo(commands.Command):
    """Carves the memory dump for Owner's personal info JSON struct."""

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)

        config.add_option('format', short_option=None,
                          default='pretty', type='str',
                          help='Choose how this plugin should output the JSON results:\n'
                          'Accepted values: pretty, visualizer')

        config.add_option("OID", short_option=None,
                          default=None, type='str',
                          help='Facebook ID of the logged in account aka owner\'s ID')

    def calculate(self):
        profileJsons = []

        address_space = utils.load_as(self._config, astype='physical')
        start_tag = "/auth/user_data/fb_me_user{\"uid\":\""
        id_tag = "{\"uid\":\""
        # There are 2 possible byte sequences that this JSON structure
        # ends with in memory, so define both
        stop_tag1 = "profile_picture_is_silhouette\":false}"
        stop_tag2 = "profile_picture_is_silhouette\":true}"

        if self._config.OID is None:
            ownerID = FacebookFindOwner().findowner(address_space)
            if ownerID == "unknown":
                print "Could not find the owner's ID... Try to provide it with the oid paremeter!"
                return "iderr"
            elif ownerID == "multipleids":
                print "Please specify the owner's id with the oid parameter, because multiple IDs were found!"
                return "iderr"
        elif self._config.OID is not None:
            ownerID = self._config.OID

        scanner = FacebookScanner(needles=[start_tag])
        for offset in scanner.scan(address_space):
            fb_buff = address_space.read(offset+len(start_tag)-len(id_tag), 4096)
            idoffset = fb_buff[len(id_tag):].find("\"")
            jsonOwnerID = fb_buff[len(id_tag):len(id_tag)+idoffset]

            if ownerID != jsonOwnerID:
                # Found JSON structure from different account,
                # so just continue looking
                continue

            iter1 = 0
            while iter1 < len(fb_buff):
                if fb_buff[iter1:iter1+len(stop_tag1)] == stop_tag1 or \
                   fb_buff[iter1:iter1+len(stop_tag2)] == stop_tag2:
                    # Use a generic exception handler, because of
                    # random JSON looking artifacts or corrupted ones
                    try:
                        tmpJsonDes = json.loads(fb_buff[:iter1+len(stop_tag1)])
                        tempJson = fb_buff[:iter1+len(stop_tag1)]
                        if tempJson not in profileJsons:
                            profileJsons.append(tempJson)
                    except Exception as e:
                        break
                iter1 += 1

        # Yield only the longest json which will probably have more information
        try:
            return max(profileJsons, key=len)
        except Exception as e:
            return "err"

    def render_text(self, outfd, data):

        if data == "iderr":
            return

        if data == "err":
            print "[ERROR] Couldn't find Facebook's user info JSON structure in dump.."
            return

        if self._config.FORMAT == "pretty":
            pprint.pprint(json.loads(data))
        elif self._config.FORMAT == "visualizer":
            print data
            print "\n[!] " + "You should definitely paste the above JSON data " \
                  "in an online JSON visualizer, like http://jsonviewer.stack.hu/"
        else:
            pprint.pprint(json.loads(data.next()))

        return


class FacebookContacts(commands.Command):
    """Finds possible Facebook contacts"""

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)

        config.add_option("OID", short_option=None,
                  default=None, type='str',
                  help='Facebook ID of the logged in account aka owner\'s ID')

        self.contactsList = {}

    def calculate(self):
        address_space = utils.load_as(self._config, astype='physical')
        if self._config.OID is None:
            ownerID = FacebookFindOwner().findowner(address_space)
        elif self._config.OID is not None:
            ownerID = self._config.OID

        # fbcontacts_tag = ("\x22\x75\x73\x65\x72\x5F\x6B\x65\x79\x22\x3A"
        #                  "\x22\x46\x41\x43\x45\x42\x4F\x4F\x4B\x3A")
        fbcontacts_tag = "\"user_key\":\"FACEBOOK:"
        contactsScanner = FacebookScanner(needles=[fbcontacts_tag, ])

        for offset in contactsScanner.scan(address_space):
            contacts_buff = address_space.read(offset - (512/2), 512)

            citer = 0
            f1 = False
            f2 = False

            # Find JSON's starting and ending offsets
            while citer < 512:

                if contacts_buff[citer:citer + 9] == "{\"email\":":
                    conJsonStart = citer
                    f1 = True

                if contacts_buff[citer:citer + 9] == ",\"name\":\"":
                    conJsonEnd = citer + 9
                    f2 = True

                citer += 1

            # Make sure this is a full JSON and not a corrupted one
            if not (f1 and f2):
                continue

            for c in range(conJsonEnd, len(contacts_buff)):
                if contacts_buff[c] == '"':
                    conJsonEnd = c + 2

            # Sanity check in case start offset
            # is higher than the end offset
            if conJsonStart >= conJsonEnd:
                continue

            con = contacts_buff[conJsonStart:conJsonEnd]
            try:
                contactData = json.loads(con)
                # Make sure its not a duplicate finding!
                if not contactData.get("user_key") in self.contactsList:
                    self.contactsList[contactData.get("user_key")] = contactData
                    if contactData.get("user_key").split(":")[1] == ownerID:
                        contactOwnerID = contactData.get("user_key").split(":")[1] + " [OWNER]"
                    else:
                        contactOwnerID = contactData.get("user_key").split(":")[1]

                    contact = (contactOwnerID,
                               contactData.get("email"),
                               contactData.get("name"))
                    yield contact
            # Handle this exception more properly?
            except Exception as e:
                continue

    def render_text(self, outfd, data):
        self.table_header(outfd, [("User Key", "30"),
                                  ("Email", "50"),
                                  ("Name", "")])

        for uk, e, n in data:
            try:
                self.table_row(outfd, uk, e, n)
            except Exception as e:
                print "[ERROR] Something went bad: User Key: " + uk + ", Email: " + e + ", Name: " + n

    def render_csv(self, outfd, data):
        for uk, e, n in data:
            outfd.write("{0},{1},{2}\n".format(uk, e, n))


class FacebookMessages(commands.Command):
    """Carves the memory for every message exchanged between the Owner and another contact"""

    def convertToTimestamp(self, dt):
        """Convert a human readable datetime in timestamp"""
        diff = dt - datetime(1970, 1, 1)
        return int(diff.total_seconds())

    def convertUnixTime(self, nsec):
        """ Convert unix epoch time in nanoseconds to a date string """
        try:
            time_val = struct.pack("<I", nsec // 1000000000)
            time_buf = addrspace.BufferAddressSpace(self._config, data=time_val)
            time_obj = obj.Object("UnixTimeStamp", offset=0,
                                  vm=time_buf, is_utc=True)
            return time_obj
        except Exception as e:
            return None

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)

        config.add_option("OID", short_option=None,
                          default=None, type='str',
                          help='(Owner ID) Facebook ID of the logged in account aka owner\'s ID')

        config.add_option('CID', short_option=None,
                          default=None, type='str',
                          help='[Required] (Contact ID) Facebook ID of 2nd party chatting with the owner')

        config.add_option('STRIP-DUPLICATES', short_option=None,
                          action='store_true', dest='duplicates',
                          help='Do not display duplicate messages')

        config.add_option('BUFFER', short_option='b',
                          default=1024, type='int',
                          help='Look up chunk size for messages')

        config.add_option('LOWYEAR', short_option=None,
                          default=2013, type='int',
                          help='Low year boundary')

        config.add_option('HIGHYEAR', short_option=None,
                          default=2017, type='int',
                          help='High year boundary')

    def calculate(self):

        address_space = utils.load_as(self._config, astype='physical')
        msgsDict = {}
        foundItemsHashes = []

        if self._config.OID is None:
            ownerID = FacebookFindOwner().findowner(address_space)
            if ownerID == "unknown":
                print "Could not find the owner's ID... Try to provide it with the oid paremeter!"
                return
            elif ownerID == "multipleids":
                print "Please specify the owner's id with the oid parameter, because multiple IDs were found!"
                return
        elif self._config.OID is not None:
            ownerID = self._config.OID

        if not self._config.CID:
            print "The --cid argument is required!"
            return
        contactID = self._config.CID

        fbchat_stop_tag = "{\"email\":\""
        fbchat_start_tag = "ONE_TO_ONE:" + contactID + ":" + ownerID + "t"
        scanner = FacebookScanner(needles=[fbchat_start_tag])
        # Begin looking for possible messages
        for offset in scanner.scan(address_space):
            # Special case which could happen if needles are
            # found in the very beginning of memory dump
            if offset < self._config.BUFFER:
                fb_buff = address_space.read(0+len(fbchat_start_tag), offset)
            else:
                fb_buff = address_space.read(offset+len(fbchat_start_tag), self._config.BUFFER)
            # Build 2 timestamp lowyear and highyear variables
            # for later usage
            lowdt = datetime(int(self._config.LOWYEAR), 1, 1)
            lowdt = self.convertToTimestamp(lowdt)

            highdt = datetime(int(self._config.HIGHYEAR)+1, 1, 1)
            highdt = self.convertToTimestamp(highdt)

            iter1 = 0
            boundByTimestampFlag = False
            # Find the leftmost starting point of a message
            while iter1 < len(fb_buff):
                # If this is true it is very possible for this to be the unix
                # timestamp and hence the message begins from this offset
                try:
                    if any(not isprintable(fb_buff[iter1 + 0 + x]) for x in range(8)):
                        timestamp = fb_buff[iter1:iter1+8]
                        # Convert timestamp to int miliseconds
                        timestamp = int(timestamp.encode("hex"), 16)
                        # Check whether this messages timestamp is inside the specified time period
                        if int(str(timestamp)[:10]) >= lowdt and \
                                int(str(timestamp)[:10]) <= highdt:
                            boundByTimestampFlag = True
                            # Move i +8 positions ahead
                            # since the unix timestamp is 8bytes
                            iter1 += 8
                            break
                except Exception as e:
                    break

                iter1 += 1

            # If the above limitations weren't met
            # continue looking for messages
            if not boundByTimestampFlag:
                continue

            # Find the rightmost ending point of a message
            # In other words try to "capture" the message artifact
            # inside left and right expected string sequences
            boundByRightTagFlag = False
            iter2 = iter1
            while iter2 < len(fb_buff):

                if fb_buff[iter2:iter2 + len(fbchat_stop_tag)] == fbchat_stop_tag:
                    boundByRightTagFlag = True
                    break

                iter2 += 1

            if not boundByRightTagFlag:
                continue

            # Find the sender of the message
            iter3 = iter2 + len(fbchat_stop_tag)
            fbchat_name_tag = ",\"name\":\""
            flag3found = False
            while iter3 < len(fb_buff):
                if fb_buff[iter3:iter3+len(fbchat_name_tag)] == fbchat_name_tag:
                    contactName = fb_buff[iter3+len(fbchat_name_tag):].split("\"", 1)[0]
                    flag3found = True
                    break
                iter3 += 1

            if not flag3found:
                continue

            # Only if dupes argument is strictly enabled, then avoid
            # displaying duplicate messages!
            if self._config.duplicates:
                # Calculate the SHA1 of message and if it
                # has been already found DO NOT yield it
                msgSHA1 = sha1(fb_buff[iter1:iter2]).hexdigest()
                # If this message is already stored, keep looking
                if msgSHA1 in foundItemsHashes:
                    continue
                else:
                    foundItemsHashes.append(msgSHA1)

            # Store in the Dictionary a list that contains the contact name
            # and the message sent by him!
            msgsDict[timestamp] = [contactName, fb_buff[iter1:iter2]]

        # Yield results sorted by time!
        for k in sorted(msgsDict):
            dt = self.convertUnixTime(k)
            if dt is not None:
                yield msgsDict[k][0], dt, msgsDict[k][1]

    def render_text(self, outfd, data):
        # Leaving the Message column without size specified,
        # will allow Volatility to render it properly
        # by finding the max Message record size
        self.table_header(outfd, [("User Name", "40"),
                                  ("Timestamp", "28"),
                                  ("Message", "")])

        for un, t, m in data:
            try:
                self.table_row(outfd, un, t, m)
            except Exception as e:
                print "[ERROR] Something went bad: User Name: " + un + ", Timestamp: " + t + ", Message: " + m

    def render_csv(self, outfd, data):
        for un, t, m in data:
            outfd.write("{0},{1},{2}\n".format(un, t, m))
