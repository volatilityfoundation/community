#
# author:
# Tran Vien Ha <tranvienha@gmail.com>
#

import traceback
import logging
import socket
import socks # you need to install pysocks (see above)
import requests
import json
import re
from urlparse import urlparse
import volatility.utils as utils
from volatility import renderers
from volatility.renderers.basic import Address, Hex
import volatility.plugins.netscan as netscan
import volatility.plugins.connscan as connscan
import volatility.plugins.taskmods as taskmods
import volatility.plugins.malware.malfind as malfind
import volatility.conf as conf
import volatility.debug as debug


logging.getLogger("urllib3").setLevel(logging.WARNING)

# Inherit from Dlllist for command line options
class osint(taskmods.DllList):
    """Check Url/ip extracted from memory against opensource intelligence platforms"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("WHITELIST-FILE", short_option = False, default = "whitelist.txt",
                          help = 'Domain in this list will be ignored',
                          action = 'store', type = 'str')
        config.add_option("SOCKS5-HOST", short_option = False, default = "127.0.0.1",
                          help = 'SOCKS5 proxy host',
                          action = 'store', type = 'str')
        config.add_option("SOCKS5-PORT", short_option = False, default = 9050,
                          help = 'SOCKS5 proxy port',
                          action = 'store', type = 'int')
        config.add_option("CHECK-TYPE", short_option = False, default = "url",
                          help = 'SOCKS5 proxy port',
                          action = 'store', type = 'str')
        
    def generator(self, data):
        for owner, bluecoat, virustotal, misp, url in data:
            yield (0, [str(owner),
                          str(bluecoat),
                          str(virustotal),
                          str(misp),
                          str(url)])

    def unified_output(self, data):
        print ("unified")
        tg = renderers.TreeGrid(
                          [("owner", str),
                           ("bluecoat", str),
                           ("virustotal", str),
                           ("misp", str),
                           ("url/Ip", str),
                           ], self.generator(data))
        return tg

    def render_text(self, outfd, data):
        self.table_header(outfd,
                          [("Owner", "40"),
                           ("Bluecoat", "40"),
                           ("VirusTotal", "10"),
                           ("MISP", "10"),
                           ("Url/Ip", "")
                           ])

        for owner, bluecoat, virustotal, misp, url in data:
            self.table_row(outfd, owner, bluecoat, virustotal, misp, url)

    def sitereview(self,url,socks5_host,socks5_port):
        try:
		    # Remove this if you don't plan to "deactivate" the proxy later
            default_socket = socket.socket

		    # Set up a proxy
            socks.set_default_proxy(socks.SOCKS5, socks5_host,socks5_port)
            socket.socket = socks.socksocket
            payload={'url':url}
            r = requests.post(self._config.SITEREVIEW_URL,data=payload)
            json_obj = json.loads(r.text)
            if r.text.find('error') != -1:
                return json_obj['error']
            category = re.findall('>([^(]*)<\/a>',json_obj['categorization'])
            return category[0]
        except:
            return "Error"

    def virustotal(self,url,socks5_host,socks5_port):
		try:    
		    # Remove this if you don't plan to "deactivate" the proxy later
		    default_socket = socket.socket

		    # Set up a proxy
		    socks.set_default_proxy(socks.SOCKS5, socks5_host, socks5_port)
		    socket.socket = socks.socksocket
		    payload={'resource':url,'apikey':self._config.VIRUSTOTAL_TOKEN}
		    r = requests.post(self._config.VIRUSTOTAL_URL,data=payload)            
		    json_obj = json.loads(r.text)
		    if json_obj['response_code'] == 0:
		        return "Not Found"
		    else:
		        return str(json_obj['positives']) + "/" + str(json_obj['total'])
		except:
		    return "Error"

    def misp(self,ioc,ioctype):
		try:
		    headers = {'Authorization': self._config.MISP_TOKEN}
		    r = requests.get(self._config.MISP_URL + ioc + "/" + ioctype,headers=headers)
		    eventid = re.findall('<Event><id>([^(]*)<\/id><orgc_id>',r.text)
		    if len(eventid) == 0:
		        return "Not Found"
		    else:
		        return eventid[0]
		except:
		    return "Error"

    def calculate_url(self):
        self._config.YARA_RULES = "/(http|https):\/\//"
        matches = malfind.YaraScan(self._config).calculate()
        seen = set()        
        for o, addr, hit, content in matches:
            whitelisted = False
            if o == None:
                owner = "(Unknown Kernel Memory)"
            elif o.obj_name == "_EPROCESS":
                owner = "Process {0} Pid {1}".format(o.ImageFileName,o.UniqueProcessId)
            else:
                owner = "kernel.{0:#x}.{1:#x}.dmp".format(o.obj_offset, addr)
        	
            urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',content)
            if len(urls) > 0:
                parsed_url = urlparse(urls[0])
                domain = "{uri.netloc}".format(uri=parsed_url)                
                with open(self._config.WHITELIST_FILE) as f:
                    for line in f:
                        if domain.endswith(line.strip()):
                            whitelisted = True                        
                            break

                if whitelisted:
                    continue

                if domain not in seen:
                    seen.add(domain)                    
                    bluecoat = self.sitereview (urls[0],self._config.SOCKS5_HOST, self._config.SOCKS5_PORT)
                    vt = self.virustotal(urls[0],self._config.SOCKS5_HOST, self._config.SOCKS5_PORT)
                    msp = self.misp(domain,"domain")
                    yield owner, bluecoat, vt, msp, urls[0]

    def calculate_ip(self):
        addr_space = utils.load_as(self._config)
        version = (addr_space.profile.metadata.get('major', 0), 
                   addr_space.profile.metadata.get('minor', 0))

        conns = []
        if version[0] == 5:
            data = connscan.ConnScan(self._config).calculate()
            for conn in data:
                element = []
                element.append(str(conn.RemoteIpAddress))
                element.append(conn.Pid)
                conns.append(element)
        else:
            data = netscan.Netscan(self._config).calculate()
            for net_object, proto, laddr, lport, raddr, rport, state in data:
                element = []
                element.append("{0}:{1}".format(raddr, rport))
                element.append(net_object.Owner.UniqueProcessId)
                conns.append(element)

        seen = set()        
        for remote,pid in conns:
            whitelisted = False
           
            owner = "Pid {0}".format(pid)
            
            
            ipaddr = remote.split(":")[0] 
            matches = re.findall('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',ipaddr)
            if len(matches) > 0:
                ip = matches[0]               
                with open(self._config.WHITELIST_FILE) as f:
                    for line in f:
                        if ip.endswith(line.strip()):
                            whitelisted = True                        
                            break

                if whitelisted:
                    continue

                if ip not in seen:
                    seen.add(ip)                    
                    bluecoat = self.sitereview (ip,self._config.SOCKS5_HOST, self._config.SOCKS5_PORT)
                    vt = self.virustotal(ip,self._config.SOCKS5_HOST, self._config.SOCKS5_PORT)
                    msp = self.misp(ip,"ip-dst")
                    yield owner, bluecoat, vt, msp, ip

    def calculate(self):
        if not self._config.SITEREVIEW_URL:
            print ("You must specify SITEREVIEW_URL in configuration file")
        if not self._config.VIRUSTOTAL_URL:
            print ("You must specify VIRUSTOTAL_URL in configuration file")

        if self._config.CHECK_TYPE == "url":
            data =  self.calculate_url()
        else: 
            data = self.calculate_ip()
        for owner, bluecoat, vt, msp, ip in data:
            yield owner, bluecoat, vt, msp, ip
