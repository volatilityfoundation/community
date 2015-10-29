# Volatility
# Copyright (c) 2015 Joe Greenwood (joe@4armed.com)
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.plugins.taskmods as taskmods
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.filescan as filescan
import volatility.plugins.modscan as modscan
import volatility.obj as obj
import volatility.plugins.common as common 
import volatility.plugins.handles as handles
import volatility.plugins.malware.malfind as malfind
import volatility.debug as debug

import re
import os
import string
import json
try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


watermark_table = {
     "LOuWAplu":'DEVEL',
     "B3lZ3bup":"VIRGIN",
     "pggnCxFn":"FAE-MASTER",
     "00yRHOTA":"CNI-OLD",
     "A3HnGRZU":"CNI-OLD",
     "069sWhEj":"MOI",
     "ppQTcH7f":"MOI",
     "169hWMEj":"MOACA",
     "A4XMK0ZC":"MOACA",
     "25GSdf2h":"PHOEBE-DEMO",
     "MezOpt1E":"PHOEBE-DEMO",
     "2ZaXtINx":"CUSAEM",
     "BW6TaVL3":"CUSAEM",
     "ej0gXMU0":"HT-HISTORY",
     "I74UlMGQ":"FAE-MARTINEZ",
     "45u8wvtB":"INTECH-CONDOR",
     "tyh3xhtE":"INTECH-CONDOR",
     "4qXth8Sd":"PP",
     "qjAibb2n":"PP",
     "nVdF0QEJ":"HT-ZEUS",
     "74FFGHrh":"INSA",
     "yp83YSYf":"INSA",
     "7UBPM2tM":"CSDN-02",
     "VAeifBoS":"CSDN-02",
     "7ux8M2tM":"CSDN-01",
     "7ggeqOWJ":"CSDN-01",
     "kXEg3Xmk":"FAE-INVERNIZZI",
     "GpY552Ob":"ZUEGG",
     "Qs5rund9":"FAE-HO",
     "AIQ6WcIW":"PMO",
     "dj9cQOnY":"PMO",
     "pmM1MzBY":"FAE-PARDO",
     "B16S0SHJ":"RCSSPA",
     "zraM1WcL":"RCSSPA",
     "B4y9gjKB":"NSS",
     "dFHGxGKB":"NSS",
     "YXcJ9OfQ":"HT-MINOTAURO",
     "CscR5f7w":"AZNS",
     "naU1EoaX":"AZNS",
     "De3elpjn":"MCDF",
     "cHmywO6d":"MCDF",
     "GDWwVyrq":"DOD",
     "XDnGCEOd":"DOD",
     "GErh2CTQ":"NISS-02",
     "K2Oriih1":"NISS-02",
     "HXcMQKsB":"ATI",
     "LMX8W5gs":"ATI",
     "HtAUfHdq":"IDA-TEST",
     "jEqfaEDY":"IDA-TEST",
     "JBq6sMVX":"CSH-PA",
     "hQz6Vi8X":"CSH-PA",
     "JZfKkrNd":"BSGO",
     "CFlu9oy4":"BSGO",
     "KY4pBxoC":"GNSE",
     "lGKtw6bT":"GNSE",
     "KdQdJeaC":"SIO-PROD",
     "fVs1guEh":"SIO-PROD",
     "Kwh80g9E":"EDQ",
     "k3axvXOU":"EDQ",
     "GJyCtgKp":"TIKIT",
     "JPsvQ8gC":"ARIEL-TEST",
     "M8GQZoCE":"TCC-GID",
     "B785HAZk":"TCC-GID",
     "MBe5kSWG":"ALFAHAD-TEST",
     "bfxlHjfq":"ALFAHAD-TEST",
     "60mABw5g":"FAE-SCARAFILE",
     "a0tkRcp9":"FAE-SOLIS",
     "NO7Sy8tl":"INTECH-TRIAL",
     "1NWqolH8":"INTECH-TRIAL",
     "NnkL7M2C":"MXNV",
     "Hh0QAgfW":"MXNV",
     "WRUrXrNa":"DUSTIN",
     "PxL2BITH":"ORF",
     "En2NjuLY":"ORF",
     "R4B1diMM":"MOD",
     "R24fJcS9":"MOD",
     "R4cCdi5M":"SCICO",
     "t6UT4mjA":"SCICO",
     "Ra6jeeCa":"THDOC",
     "h84S5mQ0":"THDOC",
     "ZCVLCEqz":"VIKIS",
     "S0l5nD1a":"CIS",
     "7MzsQQ1Q":"CIS",
     "Sg96gC96":"UAEAF",
     "QTHeaoZp":"UAEAF",
     "3OqZ1N5a":"FAE-FURLAN",
     "WCOUQarb":"SKA",
     "owecTr6a":"SKA",
     "cgRh7XBq":"PHANTOM",
     "WksS4Fba":"PANP",
     "XRHTHAnH":"PANP",
     "XTqDh8yF":"CNI-PROD",
     "pO6nkSqr":"CNI-PROD",
     "XidiPq2M":"CSH-VR",
     "eiS6YBT5":"CSH-VR",
     "Xn6PbS3f":"PHOEBE-PROD",
     "COyTQvQy":"PHOEBE-PROD",
     "Xt0DW33K":"FAE-MASTER",
     "Xuu5XSXT":"SSNS",
     "Wy1UFQJI":"SSNS",
     "ZY4eyq9p":"UZC",
     "Y0NccSeT":"UZC",
     "ZgLs9Knj":"MACC",
     "OOqg74ci":"MACC",
     "ZjvOuN3m":"TNP",
     "S6uzJslh":"TNP",
     "wTLzh8aW":"HT-ISS",
     "an5GeV3M":"PHOEBE-TEST",
     "9ahEKeA6":"PHOEBE-TEST",
     "d4vofCKS":"INTECH-FALCON",
     "wDZT8oVX":"INTECH-FALCON",
     "ebXMHVBX":"SIO-TEST",
     "f6ZkZl2l":"SIO-TEST",
     "ev68E732":"CBA",
     "MjehnWAw":"CBA",
     "f7Ch9Y1H":"PF",
     "BCd5hIGe":"PF",
     "ncosNDqS":"HON",
     "fj2mO5as":"SENAIN",
     "Tz0SKEPZ":"SENAIN",
     "h2zYJ264":"NISS-01",
     "5eGsPbIQ":"NISS-01",
     "hC37bvu2":"CNI-TEST",
     "AyqE5Y4c":"CNI-TEST",
     "iTJOF2Dm":"ARIEL-PROD",
     "hr2Sdm23":"KATIE",
     "7QpZptZe":"KATIE",
     "hrSddKc0":"MIMY",
     "vFUZeFJS":"MIMY",
     "igGf3d1j":"SDUC",
     "SPU9iiT2":"SDUC",
     "in3r0sCU":"MDNP",
     "8QsdUob1":"MDNP",
     "j4Dnq4lY":"KNB",
     "9qFkutny":"KNB",
     "j5DK3mx1":"BHR",
     "9oUPcrOR":"BHR",
     "j5ldda3C":"ROS-TEST",
     "M0jk12jf":"ROS-TEST",
     "j6dQqpsj":"ROS-PROD",
     "2Nwu3etc":"ROS-PROD",
     "j84fj1Ej":"GEDP",
     "RoioR4b0":"GEDP",
     "kJ3kVZXU":"PN",
     "wFhIjFzc":"PN",
     "kjmljtaV":"PGJEM",
     "QxWYLPBl":"PGJEM",
     "lBhEn16q":"SEGOB",
     "GzdDoUXV":"SEGOB",
     "z4L2khym":"HT-ZEUS-ARC",
     "nFGPKB8T":"IDA-PROD",
     "L729AvnN":"IDA-PROD",
     "MVtr5Bz6":"HT-TEST",
     "SWrT2dqY":"FAE-WOON",
     "O0lM7xp8":"SSPT",
     "EdME8ScH":"JASMINE",
     "paEr6KlM":"ALFAHAD-PROD",
     "eVXhktXV":"ALFAHAD-PROD",
     "q6OVLjoD":"AFP",
     "pIvB6RsU":"AFP",
     "cz3gDogq":"YUKI",
     "rMMNNu0g":"MKIH",
     "hfZs6emK":"MKIH",
     "eJFgTpWd":"SEPYF",
     "tXMxdi5M":"PEMEX",
     "6qYymLbd":"PEMEX",
     "vIByzgbS":"GIP",
     "M0qMiuNn":"GIP",
     "whP1Z114":"KVANT",
     "1dhAm3T6":"KVANT",
     "yIQVWBIW":"PCIT",
     "BTCYJM1a":"PCIT",
  }

CONFIDENCES = {
    0:"None",
    1:"Low",
    2:"Medium",
    3:"High",
    4:"Certain"
}
class AttributeHT(taskmods.DllList):
    """Find Hacking Team implants and attempt to attribute them using a watermark.
        - Scout implants  are found by dynamically generating Yara rules using the watermarks
        - Elite implants are found using a distinctly named mapped shared memory segment"""

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option('EXTRACT', short_option = 'e', default = 0,
                          help = 'Attempt to extract configuration data from memory',
                          action = 'store_true')
        config.add_option('DUMP-DIR', short_option = 'D', default = None,
                          cache_invalidator = False,
                          help = 'Directory in which to dump configuration files')
        config.add_option('ONLYELITE', short_option = 'E', default = 0,
                          help = 'Search for Elite Implants only',
                          action = 'store_true')
        config.add_option('ONLYSCOUT', short_option = 'S', default = 0,
                          help = 'Search for Scout Implants only',
                          action = 'store_true')

    def gen_yara_rules(self):
        """ Dynamically generate yara rules for each scout based on the watermark table """
        rules = {}
        count = 0
        rule_template = 'rule HT__SCOUT__%s__%i {strings: $a = \"%s\" $b = {46 00 49 00 52 00 53 00 54 00 5f 00 57 00 41 00 49 00 54} condition: $a and $b}'
        for i in watermark_table:
            dyn_rule = rule_template%(watermark_table[i].replace('-','_'),count,i)
            rules["namespace_" + watermark_table[i].replace('-','_')] = dyn_rule
        
        rules = yara.compile(sources = rules)

        return rules

    def get_vad_base(self, task, address):
        """ Get the VAD starting address """        

        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start

        # This should never really happen
        return None
        
    def find_scouts(self):
        """ Find all 'Scout' level implants using their distinctive watermarks - these index the configuration files, allowing us to obtain AES key information """
        scouts = []
        # Dynamically generate Yara rules from watermark
        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)
        
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        
        rules = self.gen_yara_rules()

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task = task, rules = rules)

            for hit, address in scanner.scan():
                hitdata = scanner.address_space.zread(address, 8)
                # Second hit from Yara rule is the 'FIRST_WI' string that we use to differentiate from Elite implants
                # This is a wide string, so the second character is a '\x00' - the first hit is on the watermark that we want to use.
                if hitdata[1] != "\x00": 
                    scouts.append({"watermark":hitdata, "confidence":4, "pid":str(task.UniqueProcessId), "task":task, "process_name":str(task.ImageFileName), "address_space":scanner.address_space, "address":address, "implant_type":"Scout", "threat_actor":hit.rule.split('__')[2]})

        return scouts
                

    def extract_scout_config(self, pid_list):
        """ Given a scout address space, parse the configuration """
        addr_space = utils.load_as(self._config)
        for i in pid_list:
            if i["implant_type"] == "Scout":
                """ First dump the process memory of the target process """
                task_space = i["task"].get_process_address_space()
                pe_dump = ""
                if task_space == None:
                    debug.error("Error: Cannot acquire process AS")
                elif i["task"].Peb == None:
                    # we must use m() here, because any other attempt to
                    # reference i["task"].Peb will try to instantiate the _PEB
                    debug.error("Error: PEB at {0:#x} is unavailable (possibly due to paging)".format(i["task"].m('Peb')))
                elif task_space.vtop(i["task"].Peb.ImageBaseAddress) == None:
                    debug.error("Error: ImageBaseAddress at {0:#x} is unavailable (possibly due to paging)".format(i["task"].Peb.ImageBaseAddress))
                else:
                    pe_file = obj.Object("_IMAGE_DOS_HEADER", offset = i["task"].Peb.ImageBaseAddress, vm = task_space)
                    # Do the actual dumping here
                    for offset, code in  pe_file.get_image(unsafe = True,
                                                  memory = True,
                                                  fix = False):
                       pe_dump+=code

                    # We now have a copy of the process memory - search for our tags
                

                    # Look for sync tag
                    if "S\x00y\x00n\x00c" in pe_dump:
                        sync_index = pe_dump.index("S\x00y\x00n\x00c")
                        # Get C2 server by hunting for IP Addresses near the 'Sync' tag
                        c2_server = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", pe_dump[sync_index-22:sync_index+10])
                        i["c2_server"] = c2_server[0]
                    
                    # Using watermark, get client AES encryption key
                    i["server_key"] = i["address_space"].zread(i["address"]-508, 32)
                    i["evidence_key"] = i["address_space"].zread(i["address"]-508+96, 32)
                    i["log_key"] = i["address_space"].zread(i["address"]-508+48, 32)

                    if self._config.DUMP_DIR == None:
                        debug.error("Please specify a dump directory (--dump-dir)")
                    if not os.path.isdir(self._config.DUMP_DIR):
                        debug.error(self._config.DUMP_DIR + " is not a directory")

                    # Create a dump configuration file
                    dump_file = "scout_configuration_" + i["pid"] + ".json"

                    config_file = {
                    "pid":i["pid"], 
                    "process_name":i["process_name"], 
                    "c2_server":i["c2_server"], 
                    "watermark":i["watermark"], 
                    "implant_type":i["implant_type"],
                    "threat_actor":i["threat_actor"],
                    "key_data":{"server_key":i["server_key"],
                        "evidence_key":i["evidence_key"],
                        "log_key":i["log_key"]
                        }
                    }
                    with open(os.path.join(self._config.DUMP_DIR, dump_file), 'w') as f:
                        f.write(json.dumps(config_file, indent=4))
                    i["config_file"] = os.path.join(self._config.DUMP_DIR, dump_file)


        return pid_list

    def find_elites(self):
        """ Find elite level implants using a distinctive shared memory region that the malware uses instead of a mutex"""
        infected_pids = []
        process_names = {}
        display_indicators = []
        p = handles.Handles(self._config)

        for handle in p.calculate():
            pid, handle, object_type, name = handle
            if object_type == "Section":
                if re.match("^[a-zA-Z0-9]{7,8}$", name): # HT Implants map a 7/8 character shared memory section to use instead of a Mutex
                    # Elite implants have two watermarks per PID, so neither PIDs nor watermarks are unique.
                    infected_pids.append({"pid":str(pid), "watermark":name, "confidence":1, "implant_type":"Elite"}) 

        # Now do post-processing of results
        if infected_pids:
            # Get a list of processes, so we can tie a name to a PID
            p = taskmods.PSList(self._config)
            for process in p.calculate():
                process_names[str(process.UniqueProcessId)] = str(process.ImageFileName)

            deletelist = []
            for i in infected_pids:
                ###  Do Confidence correlation. ###
                # If we have both a 7 and an 8 character watermark, this makes it more certain it's a HT elite implant
                pid = i["pid"]
                watermark = i["watermark"]
                # Search through all the other infected pid/name combinations for a 7 char version of our 8 char watermark
                searchlist = infected_pids
                if len(watermark) == 8:
                    for j in infected_pids:
                        compare_pid = j["pid"]
                        compare_watermark = j["watermark"]

                        if len(compare_watermark) == 7 and compare_pid == pid:
                            # We've found both a 7 char and 8 char version - we're more confident that this is HT
                            i["confidence"] = i["confidence"] + 1
                            # Remove the shorter version from the list (attributable watermarks are 8 chars)
                            deletelist.append(j)

                if i not in deletelist:
                    # Now see if the watermark can be attributed
                    if watermark in watermark_table:
                        i["threat_actor"] = watermark_table[watermark]
                        i["confidence"] = i["confidence"] + 1 # We've matched a Hacking Team client, we're pretty sure it's HT

                    # Tie process name to PID
                    if pid in process_names:
                        i["process_name"] = process_names[pid]
                    else:
                        i["process_name"] = "Not Found"
                    
                    # If we've got more than one infected process, it's more likely that we've found a HT infection, and this is typical of an Elite level implant
                    if len(infected_pids) > 1:
                        i["confidence"] = i["confidence"] + 1
                        i["implant_type"] = "Elite/Soldier"


            # Now delete the PIDS in the delete list
            for j in deletelist:
                del infected_pids[infected_pids.index(j)]

        return infected_pids

    def extract_elite_config(self, pid_list):
        configurations = {}

        target_pids = [t["pid"] for t in pid_list if t["implant_type"] != "Scout"]
        addr_space = utils.load_as(self._config)

        # Check all the things that could be wrong...
        if not has_yara:
            debug.error("Yara must be installed for this plugin")
        
        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        sources = {'namespace1':'rule HT_ELITE {strings: $a = {22 53 59 4e 43 22} condition: $a}'} # Search for "SYNC"

        rules = yara.compile(sources = sources)

        tasklist = [t for t in tasks.pslist(addr_space) if str(t.UniqueProcessId) in target_pids] # Only target Elite implants we've discovered - saves work and false positives
        for task in tasklist:
            scanner = malfind.VadYaraScanner(task = task, rules = rules)

            for hit, address in scanner.scan():
                hitdata = scanner.address_space.zread(address-768, 1024)
                
                # Now go backwards until we get to a binary character (i.e. the start of the ascii configuration file)
                binary_found = False
                start = address
                character = scanner.address_space.zread(start, 1)
                while character in string.printable:
                    start = start - 1
                    character = scanner.address_space.zread(start, 1)

                start = start + 1 # Avoids \x00 at beginning

                # Search forwards until we find the end of the ascii configuration file
                end = address
                character = scanner.address_space.zread(end, 1)
                while character in string.printable:
                    end = end + 1
                    character = scanner.address_space.zread(end, 1)
                
                config_file = scanner.address_space.zread(start, end - start)

                # Now try to parse the config file
                data = config_file
                try:
                    config  = json.loads(data)
                except:
                    # Our config isn't entirely intact - try to repair - this is not exact
                    # Count quotes
                    quotes = [i for i in data if i == "\""]

                    if len(quotes)%2 != 0:
                        data = "\"" + data

                    # Count Braces
                    right_braces = [i for i in data if i == "}"]
                    left_braces = [i for i in data if i == "{"]
                    if left_braces < right_braces:
                        data = "{" + data
                    elif left_braces > right_braces:
                        data = data + "}"

                    # Now try to decode again
                    try:
                        config = json.loads(data)
                        dump_file = "configuration_elite_"+str(task.UniqueProcessId)+"_"+hex(start)+".json"
                        config_file = json.dumps(config, indent=4)
                        config_json = True

                    except:
                        dump_file = "configuration_elite_"+str(task.UniqueProcessId)+"_"+hex(start)+".text"
                        config_json = False
                
                # Write config file out to directory
                with open(os.path.join(self._config.DUMP_DIR, dump_file), 'w') as f:
                        f.write(config_file)

                pid_dict = [i for i in pid_list if i["pid"] == str(task.UniqueProcessId)][0]
                index = pid_list.index(pid_dict)
                pid_list[index]["config_file"] = os.path.join(self._config.DUMP_DIR, dump_file)

                if config_json:
                    # Try to parse the json to extract the C2 server
                    try:
                        for action in config["actions"]:
                            if action["desc"] == "SYNC":
                                pid_list[index]["c2_server"] = action["subactions"][0]["host"]
                    except:
                        pid_list[index]["c2_server"] = None
                else:
                    pid_list[index]["c2_server"] = None

        # Now for the other pids that don't have a configuration file:
        for pid in pid_list:
            if "config_file" not in pid.keys():
                pid["config_file"] = None
                pid["c2_server"] = None

        return pid_list

    def calculate(self):
        addr_space = utils.load_as(self._config)

        p = handles.Handles(self._config)

        infected_pids = []

        if not self._config.ONLYELITE:
            infected_pids = self.find_scouts()

        if not self._config.ONLYSCOUT:
            infected_pids += self.find_elites()

        if self._config.EXTRACT and not self._config.ONLYELITE:
            infected_pids = self.extract_scout_config(infected_pids)

        if self._config.EXTRACT and not self._config.ONLYSCOUT:
            infected_pids = self.extract_elite_config(infected_pids)

        for pid in infected_pids:
            if self._config.EXTRACT:
                yield pid["pid"], pid["watermark"], pid["process_name"], pid["implant_type"], pid["threat_actor"], pid["confidence"], pid["c2_server"], pid["config_file"]
            else:
                yield pid["pid"], pid["watermark"], pid["process_name"], pid["implant_type"], pid["threat_actor"], pid["confidence"]

    def render_text(self, outfd, data):
        outfd.write("Hacking Team Galileo RCS Implant Detection - 4ARMED Ltd\n")

        if not self._config.EXTRACT: # We have an extra set of information if we've gathered the configuration files
            outfd.write("{0:<4} {1:<20} {2:<20} {3:<14} {4:<15} {5:<10}\n".format(
                    "PID", "Detected Watermark", "Process Name", "Implant Type", "Threat Actor", "Confidence (Low-Certain)"))

            for pid, watermark, name, implant_type, actor, confidence in data:
                outfd.write("{0:<4} {1:<20} {2:<20} {3:<14} {4:<15} {5}\n".format(
                        pid,
                        watermark,
                        name,
                        implant_type,
                        actor,
                        CONFIDENCES[confidence]
                        ))
        else:
            outfd.write("{0:<4} {1:<9} {2:<16} {3:<14} {4:<12} {5:<25} {6:<15} {7} \n".format(
                    "PID", "Watermark", "Process Name", "Implant Type", "Threat Actor", "Confidence (Low-Certain)", "C2 Server", "Configuration File"))

            for pid, watermark, name, implant_type, actor, confidence, c2_server, file_loc in data:
                outfd.write("{0:<4} {1:<9} {2:<16} {3:<14} {4:<12} {5:<25} {6:<15} {7}\n".format(
                        pid,
                        watermark,
                        name,
                        implant_type,
                        actor,
                        CONFIDENCES[confidence],
                        c2_server,
                        file_loc
                        ))

    def render_csv(self, outfd, data):
        outfd.write("Hacking Team Galileo RCS Implant Detection - 4ARMED Ltd\n")
        if not self._config.EXTRACT:
            outfd.write("{0},{1},{2},{3},{4},{5}\n".format(
                    "PID", "Detected Watermark", "Process Name", "Implant Type", "Threat Actor", "Confidence (Low-Certain)"))
            for pid, watermark, name, implant_type, actor, confidence in data:
                outfd.write("{0},{1},{2},{3},{4},{5}\n".format(
                        pid,
                        watermark,
                        name,
                        implant_type,
                        actor,
                        CONFIDENCES[confidence]
                        ))
        else:
            outfd.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}\n".format(
                    "PID", "Watermark", "Process Name", "Implant Type", "Threat Actor", "Confidence (Low-Certain)", "C2 Server", "Server Key", "Evidence Key", "Log Key"))

            for pid, watermark, name, implant_type, actor, confidence, c2_server, server_key, evidence_key, log_key in data:
                outfd.write("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}\n".format(
                        pid,
                        watermark,
                        name,
                        implant_type,
                        actor,
                        CONFIDENCES[confidence],
                        c2_server,
                        server_key,
                        evidence_key,
                        log_key
                        ))