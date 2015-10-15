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
from hashlib import sha1
import tempfile

#pylint: disable-msg=C0111

uescapes = re.compile(r'(?<!\\)\\u[0-9a-fA-F]{4}', re.UNICODE)
def uescape_decode(match): return match.group().decode('unicode_escape')

def findHTMLClass(adoc,astring):
    """
    generator to yield lxml.html doc descendants based on substring class matches
    i.e. <a href="something" class="tweet-timestamp js-permalink js-nav" title="3:11 PM - 11 May 13" ><span class="_timestamp js-short-timestamp js-relative-timestamp" data-time="1368310273" data-long-form="true">2m</span></a>
    matches doc,'timestamp'
    """
    for c in adoc.iterdescendants():
        if 'class' in c.attrib and astring in c.attrib['class']:
            yield c
        if len(c.getchildren())>0:
            findHTMLClass(c,astring)

class twitter(commands.Command):
    """Retrieve twitter artifacts from a memory image"""
    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,help = 'Operate on these Process IDs (comma-separated) rather than all browser processes',action = 'store', type = 'str')
    
    def calculate(self):
        """Calculate and carry out any processing that may take time upon the image"""
        # Load the address space
        addr_space = utils.load_as(self._config)
        #find some browsery processes
        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() in("iexplore.exe","firefox","firefox.exe","chrome","chrome.exe"):
                yield proc    

    def render_text(self, outfd, data):        
        """Search for artifacts in browser processes"""
        startTime=time.time()
        outfd.write('searching for browser processes...\n')
        tweetTextre=re.compile(r"""(<p.{1,20}tweet-text.*?</p>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        tweetHeaderre=re.compile(r"""(<div.{1,20}stream-item-header.*?</div>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        tweetProfilere=re.compile(r"""(<div.{1,20}mini-profile-stats-container.{1,1024}</div>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        tweetre=re.compile(r"""(<div.{1,20}stream-item-header.{1,1024}</div>.{1,1024}?<p.{1,20}tweet-text.{1,1500}?</p>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        tweetDMre=re.compile(r"""(<li.{1,20}dm-thread-item.{1,1024}.dm-thread-content.{1,1500}?</li>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        tweetDMConversationre=re.compile(r"""(<div.{1,20}js-dm-item.{1,1000}?</p>)""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        mozcookieUIDre=re.compile(r"""_twitter_sess.{1,700}twid=u%3D(.*?)%7""",re.IGNORECASE|re.DOTALL|re.UNICODE)
        h=HTMLParser.HTMLParser()
        encoding="ascii"
        
        
        for proc in data:
            if proc.UniqueProcessId:
                '''dump all availble pages to disk and use that file since some html structures cross page boundaries'''
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
                    
                    
                    #now read back in the memory for this process looking for artifacts
                    f.seek(0)
                    browserData=f.read()
                    f.close()
                    outfd.write('examining {0} bytes\n'.format(len(browserData)))
                    
                    #cookies that give away the logged in account#?
                    UIDs=list()
                    for tUID in mozcookieUIDre.finditer(browserData):
                        aUID=tUID.group(1).encode('ascii','ignore')
                        #lots of cookies in memory, only report different ones.
                        if aUID not in UIDs:
                            outfd.write('twitter cookie found for userid:{0}\n'.format(aUID))
                            UIDs.append(aUID)
                    
                    #profile (number of followers, folowwing,tweets)
                    for tProfile in tweetProfilere.finditer(browserData):
                        thtml=tProfile.group(1).encode('ascii','ignore')
                        #outfd.write("profile found\n")
                        #outfd.write(thtml)
                        p=lxml.html.fromstring(thtml)
                        pName='Unknown'
                        pTweets='Unknown # Tweets'
                        pFollowing='Unknown # Following'
                        pFollowers='Unknown # Followers'
                        try:
                            for a in p.findall('.//a'):
                                '''profile info is in the <a links'''
                                if 'data-nav' in a.attrib and a.attrib['data-nav']=='profile':
                                    pName=a.attrib['href'].replace('/','@')
                                    pTweets=a.text_content().replace('\n','')
                                if 'data-nav' in a.attrib and a.attrib['data-nav']=='following':
                                    pFollowing=a.text_content().replace('\n','')
                                if 'data-nav' in a.attrib and a.attrib['data-nav']=='followers':
                                    pFollowers=a.text_content().replace('\n','')
                        except AttributeError:
                            outfd.write("Exception while parsing tweet {0}".format(e))
                            pass
                        outfd.write('profile: {0}, {1} {2} {3}\n'.format(pName,pTweets,pFollowing,pFollowers))
                                
                            
                    #tweets
                    for tweet in tweetre.finditer(browserData):
                        thtml=tweet.group(1).encode('ascii','ignore')
                        #supress duplicates
                        #convert tweet to lower and remove spaces, newlines, etc to get hash of html
                        try:
                            thisHash=sha1(re.sub('[\n ]','',thtml.lower())).hexdigest()
                            #outfd.write("thtml hash: {0}\n".format(thisHash))
                            if thisHash in foundItemsHashes:
                                continue
                            else:
                                foundItemsHashes.append(thisHash)
                        except ValueError as e:
                            outfd.write("Exception while hashing tweet: {0}".format(e))
                            pass

                        doc=lxml.html.fromstring(thtml)
                        #defaults:
                        tweetTime='Unknown'
                        tweetRelativeTime='Unknown'
                        tweetAuthorName='Unknown'
                        tweetAuthorAccount='Unknown'
                        tweetContent='Unknown'
                        
                        #git the interesting bits
                        try:
                            tweetAuthorName=doc.find_class('fullname')[0].text.encode('ascii','ignore')
                            tweetAuthorAccount=doc.find_class('username')[0].find('.//b').text.encode('ascii','ignore')
                            tweetContent=doc.find_class('js-tweet-text')[0].text_content().encode('ascii','ignore')
                            #varieties of time stamping:                         
                            for r in findHTMLClass(doc,'timestamp'):
                                if 'title' in r.attrib:
                                    tweetTime=r.attrib.get('title').encode('ascii','ignore')
                                if r.tag=='span':
                                    tweetRelativeTime=r.text
                        except AttributeError as e:
                            outfd.write("Exception while parsing tweet {0}".format(e))
                            pass
                        outfd.write("{0} ({1})\t@{2}\t{3}\n".format(tweetTime,tweetRelativeTime,tweetAuthorAccount,tweetAuthorName))
                        outfd.write("\t\t{0}\n".format(tweetContent))

                    #direct message Headers (i.e. your list of conversations)
                    for tdm in tweetDMre.finditer(browserData):
                        thtml=tdm.group(1).encode('ascii','ignore')
                        #supress duplicates
                        #convert tweet to lower and remove spaces, newlines, etc to get hash of html
                        try:
                            thisHash=sha1(re.sub('[\n ]','',thtml.lower())).hexdigest()
                            #outfd.write("thtml hash: {0}\n".format(thisHash))
                            if thisHash in foundItemsHashes:
                                continue
                            else:
                                foundItemsHashes.append(thisHash)
                        except ValueError as e:
                            outfd.write("Exception while hashing tweet: {0}".format(e))
                            pass

                        doc=lxml.html.fromstring(thtml)
                        #defaults:                        
                        tweetTime='Unknown'
                        tweetAuthorName='Unknown'
                        tweetContent='Unknown'
                        tweetAuthorAccount='Unknown'
                        try:
                            if len(doc.find_class('fullname'))>0:
                                tweetAuthorName=doc.find_class('fullname')[0].text_content().encode('ascii','ignore')
                            if len(doc.find_class('username'))>0:
                                tweetAuthorAccount=doc.find_class('username')[0].text_content().encode('ascii','ignore')
                            if len(doc.find_class('js-tweet-text'))>0:
                                tweetContent=doc.find_class('js-tweet-text')[0].text_content().encode('ascii','ignore')
                            #get time and epoch and convert to readable time
                            if len(doc.find_class('_timestamp'))>0:
                                ttime=doc.find_class('_timestamp')[0]
                                tweetTime='{0} ({1})'.format(ttime.text_content(),time.ctime(float(ttime.attrib.get('data-time'))))                                                            
                        except IndexError as e:
                            outfd.write("Exception while parsing direct message {0}\n".format(e))
                            pass
                        outfd.write("{0} \t{1}\t{2}\n".format(tweetTime,tweetAuthorAccount,tweetAuthorName))
                        outfd.write("\t\tDM: {0}\n".format(tweetContent))
                    
                    #conversations (i.e. DM details..usually missing context of sender/receiver
                    for tconv in tweetDMConversationre.finditer(browserData):
                        #debug
                        #outfd.write("DMHTML: {0}\n".format(tconv.group(1).encode('ascii','ignore')))
                        thtml=tconv.group(1).encode('ascii','ignore')
                        #supress duplicates
                        #convert tweet to lower and remove spaces, newlines, etc to get hash of html
                        try:
                            thisHash=sha1(re.sub('[\n ]','',thtml.lower())).hexdigest()
                            #outfd.write("thtml hash: {0}\n".format(thisHash))
                            if thisHash in foundItemsHashes:
                                continue
                            else:
                                foundItemsHashes.append(thisHash)
                        except ValueError as e:
                            outfd.write("Exception while hashing tweet: {0}".format(e))
                            pass

                        doc=lxml.html.fromstring(thtml)
                        #defaults:
                        tweetTime='Unknown'
                        tweetDirection='Unknown'
                        tweetContent='Unknown'
                        tweetAuthorImage='Unknown'
                        try:
                            if len(doc.find_class('sent'))>0:
                                tweetDirection='Sent'
                            if len(doc.find_class('received'))>0:
                                tweetDirection='Received'
                            if len(doc.find_class('avatar'))>0:
                                tweetAuthorImage=doc.find_class('avatar')[0].attrib.get('src')
                            if len(doc.find_class('js-tweet-text'))>0:
                                tweetContent=doc.find_class('js-tweet-text')[0].text_content().encode('ascii','ignore')
                            #get time and epoch and convert to readable time
                            if len(doc.find_class('_timestamp'))>0:
                                ttime=doc.find_class('_timestamp')[0]
                                tweetTime='{0} ({1})'.format(ttime.text_content().strip(),time.ctime(float(ttime.attrib.get('data-time'))))
                        except IndexError as e:
                            outfd.write("Exception while parsing direct message {0}\n".format(e))
                            pass
                        outfd.write("{0} \t{1}\tAuthorImage: {2}\n".format(tweetTime,tweetDirection,tweetAuthorImage))
                        outfd.write("\t\tDM: {0}\n".format(tweetContent))
        endTime=time.time()
        outfd.write("{0} seconds\n".format(endTime-startTime))

