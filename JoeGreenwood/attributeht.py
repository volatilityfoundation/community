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
import volatility.plugins.common as common 
import volatility.plugins.handles as handles

import re
import json

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
class AttributeHT(common.AbstractWindowsCommand):
    """Find Hacking Team implants and attempt to attribute them using a shared memory watermark."""

    def calculate(self):
        addr_space = utils.load_as(self._config)

        p = handles.Handles(self._config)

        infected_pids = []
        process_names = {}
        display_indicators = []

        # Get a list of handles to mapped sections
        for handle in p.calculate():
            pid, handle, object_type, name = handle
            if object_type == "Section":
                if re.match("^[a-zA-Z0-9]{7,8}$", name): # HT Implants map a 7/8 character shared memory section to use instead of a Mutex
                    # Elite implants have two watermarks per PID, so neither PIDs nor watermarks are unique.
                    infected_pids.append({"pid":str(pid), "watermark":name, "confidence":1}) 

        if infected_pids:
            # Get a list of processes, so we can tie a name to a PID
            p = taskmods.PSList(self._config)
            for process in p.calculate():
                process_names[str(process.UniqueProcessId)] = str(process.ImageFileName)

            with open('test.json', 'w') as f:
                f.write(json.dumps(infected_pids, indent=4))

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
                        #print compare_pid, pid, len(compare_watermark)
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
                    else:
                        # Scouts only have one infected PID
                        i["implant_type"] = "Scout"

            # Now delete the PIDS in the delete list
            for j in deletelist:
                del infected_pids[infected_pids.index(j)]

            for pid in infected_pids:
                yield pid["pid"], pid["watermark"], pid["process_name"], pid["implant_type"], pid["threat_actor"], pid["confidence"]

    def render_text(self, outfd, data):
        outfd.write("Hacking Team Galileo RCS Implant Detection - 4ARMED Ltd\n")
        outfd.write("{0:<10} {1:<20} {2:<20} {3:<14} {4:<15} {5}\n".format(
                "PID", "Detected Watermark", "Process Name", "Implant Type", "Threat Actor", "Confidence (Low-Certain)"))

        for pid, watermark, name, implant_type, actor, confidence in data:
            outfd.write("{0:<10} {1:<20} {2:<20} {3:<14} {4:<15} {5}\n".format(
                    pid,
                    watermark,
                    name,
                    implant_type,
                    actor,
                    CONFIDENCES[confidence]
                    ))
            