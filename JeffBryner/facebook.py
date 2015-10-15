# Volatility facebook plugin
#
# Copyright (C) 2013 Jeff Bryner (jeff@jeffbryner.com)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#
"""
@author:       Jeff Bryner (p0wnlabs)
@license:      GNU General Public License 2.0 or later
@contact:      jeff@jeffbryner.com
@organization: p0wnlabs.com
"""

import volatility.timefmt as timefmt
import volatility.obj as obj
import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks
import os
import re
import HTMLParser
import lxml.html
import time
import json
from hashlib import sha1
import tempfile
import binascii
#pylint: disable-msg=C0111

uescapes = re.compile(r'(?<!\\)\\u[0-9a-fA-F]{4}', re.UNICODE)
def uescape_decode(match): return match.group().decode('unicode_escape')

safestringre=re.compile('[\x00-\x1F\x80-\xFF]')
def safestring(badstring):
        """makes a good strings out of a potentially bad one by escaping chars out of printable range"""
        return safestringre.sub('',badstring)

class FaceBook(commands.Command):
    """Retrieve facebook artifacts from a memory image"""
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,help = 'Operate on these Process IDs (comma-separated) rather than all browser processes',action = 'store', type = 'str')
    
    def calculate(self):
        """Calculate and carry out any processing that may take time upon the image"""
        # Load the address space
        addr_space = utils.load_as(self._config)

        # Call a subfunction so that it can be used by other plugins
        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() in("iexplore.exe","firefox","firefox.exe","chrome","chrome.exe"):
                yield proc

    def render_text(self, outfd, data):
        """Renders the data as text to outfd"""
        startTime=time.time()
        outfd.write('searching for browser processes...\n')
        #fb regexes
        fbHeadlinere=re.compile(r"""(<li.{1,100}uiUnifiedStory.{1,1000}?uiStreamMessage.{1,5000}?</li>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        fbCommentre=re.compile(r"""(<li.{1,100}uficomment.{1,3000}?uficommentActions.{1,2048}</li>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        fbMessagere=re.compile(r"""(\{"message_id.{1,1024}fbid.{1,1024}?body.{1,5000}?message"\})""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        fbProfilere=re.compile(r"""(\{"id":.{1,50}name.{1,50}thumbSrc.{1,1024}?is_friend.{1,50}?social_snippets.{1,50}?\})""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        fbCookiere=re.compile(r"""c_user=([0-9]{1,100})?;""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        hParser=HTMLParser.HTMLParser()
        encoding="ascii"
        #debug file to dump html into 
        #fdebug=codecs.open('fbhtml.html','w',encoding,'ignore')
        #any profiles we find along the way
        fbProfiles=dict()
        fbCookieUIDs=list()
        
        for proc in data:
            if proc.UniqueProcessId:
                pid = proc.UniqueProcessId
                if not self._config.PID ==None and str(pid) not in list(self._config.PID.split(',')):
                    #skip this browser pid
                    continue                    
                outfd.write('found browser pid: {0}, {1}\n'.format(pid,proc.ImageFileName))
                foundItemsHashes=list()
                procSpace = proc.get_process_address_space()
                pages = procSpace.get_available_pages()
                if pages:
                    f=tempfile.TemporaryFile() 
                    for p in pages:
                        procdata = procSpace.read(p[0], p[1])
                        if procdata == None:
                            if self._config.verbose:
                                outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(p[0], proc.obj_offset, p[1]))
                        else:
                            dataDecoded= procdata.decode(encoding,'ignore')
                            f.write(dataDecoded.replace('\x00',''))
                    
                    #now read back in the memory for this process looking for facebook artifacts
                    f.seek(0)
                    browserData=f.read()
                    outfd.write('examining {0} bytes\n'.format(len(browserData)))
                    f.close()
                    
                    #fbProfile json entries.
                    for fbProfile in fbProfilere.finditer(browserData):
                        fbjson=hParser.unescape(fbProfile.group(1).encode('ascii','ignore'))
                        fbjson=uescapes.sub(uescape_decode,fbjson)
                        safefbjson=safestring(fbjson)
                        try:
                            fbProfiles[json.loads(safefbjson)['id']]=safefbjson
                        except ValueError as e:
                            outfd.write("Value error parsing json for facebook profile: {0}\n".format(e))
                            outfd.write("{0}\n".format(binascii.b2a_base64(fbjson)))
                            pass

                    #fbCookies that could match a fb profile entry and tell us who this user is
                    for fbCookie in fbCookiere.finditer(browserData):
                        if fbCookie.group(1) not in fbCookieUIDs:
                            fbCookieUIDs.append(fbCookie.group(1))
                    
                    #Who is the likely user of this? 
                    for fbCookie in fbCookieUIDs:
                        if fbCookie in fbProfiles.keys():
                            outfd.write('Likely facebook user json structure: {0}\n'.format(fbProfiles[fbCookie]))
                        
                    #comments on posts
                    for fb in fbCommentre.finditer(browserData):
                        ##clean up unicode, escapes, html
                        fbhtml=hParser.unescape(fb.group(1).encode('ascii','ignore'))
                        fbhtml=uescapes.sub(uescape_decode,fbhtml)

                        #supress duplicates
                        #convert to lower and remove spaces, newlines, etc to get hash of html
                        try:
                            thisHash=sha1(re.sub('[\n ]','',fbhtml.encode('ascii','ignore').lower())).hexdigest()
                            if thisHash in foundItemsHashes:
                                continue
                            else:
                                foundItemsHashes.append(thisHash)
                        except ValueError as e:
                            outfd.write("Exception while hashing found comment : {0}".format(e))
                            pass
                        
                        #parse comment
                        doc=lxml.html.fromstring(fbhtml)
                        try:
                            fbAuthor='Unknown'
                            for pSource in doc.find_class('UFICommentActorName'):
                                fbAuthor=pSource.text_content()
                            
                            fbPostDate='Unknown'
                            #post full date
                            fbdate=doc.find('.//abbr')
                            if fbdate !=None and 'title' in fbdate.attrib.keys():
                                fbPostDate=fbdate.attrib.get('title').encode('ascii','ignore')
                            
                            fbLink='Unknown'
                            fblink=doc.find_class('uiLinkSubtle')
                            if fblink!=None and  'href' in fblink[0].attrib.keys():
                                fbLink=fblink[0].attrib.get('href').encode('ascii','ignore')
                            
                            fbComment='Unknown'
                            for pComment in doc.find_class('UFICommentContent'):
                                #ugly div/span/span with no classes..grab text_content and remove the author later
                                fbComment=pComment.text_content()
                                
                            outfd.write('Date: {0} comment on {1}\n'.format(fbPostDate,fbLink))
                            outfd.write ('\tAuthor: {0}\n'.format(fbAuthor))
                            outfd.write('\tText:{0}\n'.format(fbComment.replace(fbAuthor,'').strip()))
                        except AttributeError as e:
                            pass
                        
                    #direct messages
                    for fb in fbMessagere.finditer(browserData):
                        #supress duplicates
                        #convert to lower and remove spaces, newlines, etc to get hash of html
                        try:
                            thisHash=sha1(re.sub('[\n ]','',fb.group(1).encode('ascii','ignore').lower())).hexdigest()
                            if thisHash in foundItemsHashes:
                                continue
                            else:
                                foundItemsHashes.append(thisHash)
                        except ValueError as e:
                            outfd.write("Exception while hashing found message : {0}".format(e))
                            pass                        
                        
                        try:                                                       
                            fbdm=json.loads(fb.group(1).encode('ascii','ignore'))
                            fbdmAuthor=fbdm['author']
                            fbdmEmail=fbdm['author_email']
                            fbdmBody=fbdm['body']
                            fbdmDate=fbdm['timestamp_datetime']
                            fbdmid=fbdm['message_id']
                            outfd.write('Date: {0} messageID: {1} from: {2} {3}\n\tText: {4} \n'.format(fbdmDate,fbdmid,fbdmAuthor,fbdmEmail,fbdmBody ))
                        except ValueError as e:
                            pass
                    
                    #posts/headlines
                    for fb in fbHeadlinere.finditer(browserData):
                        #clean up unicode, escapes, html
                        fbhtml=hParser.unescape(fb.group(1).encode('ascii','ignore'))
                        fbhtml=uescapes.sub(uescape_decode,fbhtml)

                        #some hits are quote escaped, unescape them: 
                        if '\\"' in fbhtml:
                            fbhtml=fbhtml.replace('\\"','\"')
                       
                        #supress duplicates
                        #convert to lower and remove spaces, newlines, etc to get hash of html
                        try:
                            thisHash=sha1(re.sub('[\n ]','',fbhtml.encode('ascii','ignore').lower())).hexdigest()
                            if thisHash in foundItemsHashes:
                                continue
                            else:
                                foundItemsHashes.append(thisHash)
                        except ValueError as e:
                            outfd.write("Exception while hashing found headline : {0}".format(e))
                            pass
                        
                        #parse entries
                        doc=lxml.html.fromstring(fbhtml)
                        try:
                            postdate='Unknown'
                            permalink='Unknown'
                            postsource='Unknown'
                            #post link/source
                            for pSource in doc.find_class('uiStreamSource'):
                                postsource=pSource.text_content()
                            #post full date
                            fbdate=doc.find('.//abbr')
                            if fbdate !=None and 'title' in fbdate.attrib.keys():
                                postdate=fbdate.attrib.get('title').encode('ascii','ignore')
                                #get the permalink url:                                 
                                for i in fbdate.iterancestors():
                                    if i.tag=='a':
                                        permalink=i.attrib.get('href')
                                        if 'facebook.com' not in permalink.lower():
                                            permalink="https://www.facebook.com" + permalink
                                        break
                            outfd.write('Date: {0} {1} url: {2}\n'.format(postdate,postsource,permalink))
                        
                            #author
                            for author in doc.find_class('actorDescription'):
                                authorlinks=''
                                for l in author.iterlinks():
                                    authorlinks+='\t{0}'.format(l[2])                            
                                outfd.write('\tAuthor: {0}\t{1}\n'.format(author.text_content().encode('ascii','ignore'),authorlinks))
                            #likes
                            for passiveContent in doc.find_class('uiStreamPassive'):
                                outfd.write('\t\tText: {0}\n'.format(passiveContent.text_content().encode('ascii','ignore')))
                            #images
                            for img in doc.findall('.//img'):
                                if 'alt' in img.attrib.keys():
                                    outfd.write('\t\timg: {0} {1}\n'.format(img.attrib.get('src').encode('ascii','ignore'),img.attrib.get('alt').encode('ascii','ignore')))
                                else:
                                    outfd.write('\t\timg: {0}\n'.format(img.attrib.get('src').encode('ascii','ignore')))
                            #posts
                            for content in doc.find_class('userContent'):
                                outfd.write('\t\tText: {0}\n'.format(content.text_content().encode('ascii','ignore')))
                        except AttributeError as e:
                            outfd.write("Exception while parsing: {0}".format(e))
                            pass                            
                        
        endTime=time.time()
        outfd.write("{0} seconds\n".format(endTime-startTime))
