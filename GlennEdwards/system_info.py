#!/usr/bin/env python

# created by Glenn P. Edwards Jr.
#   http://hiddenillusion.blogspot.com
#       @hiddenillusion
# Date: 2015-12-23
# (while at FireEye)
# Tested on v2.5
# written based on https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/registry/shutdown.py

"""
Note: All of the information being queried may not be present
"""

import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
from volatility.renderers import TreeGrid
import volatility.timefmt as timefmt
import volatility.utils as utils

from datetime import datetime
import struct

class SystemInfo(common.AbstractWindowsCommand):
    "Print common system details of machine from registry"

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self.regapi = None

    def calculate(self):
        addr_space = utils.load_as(self._config)
        self.regapi = registryapi.RegistryApi(self._config)
        self.regapi.set_current("SYSTEM")
        self.regapi.reset_current()
        currentcs = self.regapi.reg_get_currentcontrolset()

        if currentcs == None:
            currentcs = "ControlSet001"

        # enumerating these individually & resetting current regapi isn't efficient but simplifies checking various keys from various hives
        checks = {
                        'ActiveTimeBias': {'hive': 'SYSTEM', 'key': '{0}\\Control\\TimeZoneInformation'.format(currentcs), 'name': 'ActiveTimeBias', 'is_ts': False},
                        'Bias': {'hive': 'SYSTEM', 'key': '{0}\\Control\\TimeZoneInformation'.format(currentcs), 'name': 'Bias', 'is_ts': False},
                        'ComputerName': {'hive': 'SYSTEM', 'key': '{0}\\Control\\ComputerName\\ComputerName'.format(currentcs), 'name': 'ComputerName', 'is_ts': False},
                        'CSDVersion': {'hive': 'SOFTWARE', 'key': 'Microsoft\\Windows NT\\CurrentVersion', 'name': 'CSDVersion', 'is_ts': False},
                        'DisableAutoDaylightTimeSet': {'hive': 'SYSTEM', 'key': '{0}\\Control\\TimeZoneInformation'.format(currentcs), 'name': 'DisableAutoDaylightTimeSet', 'is_ts': False},
                        'Domain': {'hive': 'SYSTEM', 'key': '{0}\\Services\\tcpip\\parameters'.format(currentcs), 'name': 'Domain', 'is_ts': False},                         
                        'Hostname': {'hive': 'SYSTEM', 'key': '{0}\\Services\\tcpip\\parameters'.format(currentcs), 'name': 'Hostname', 'is_ts': False},
                        'InstallDate': {'hive': 'SOFTWARE', 'key': 'Microsoft\\Windows NT\\CurrentVersion', 'name': 'InstallDate', 'is_ts': True},
                        'LastComputerName': {'hive': 'SOFTWARE', 'key': 'Microsoft\\Windows\\CurrentVersion\\Reliability', 'name': 'LastComputerName', 'is_ts': False},
                        'ProcessorArchitecture': {'hive': 'SYSTEM', 'key': '{0}\\Control\\Session Manager\\Environment'.format(currentcs), 'name': 'PROCESSOR_ARCHITECTURE', 'is_ts': False},
                        'ProductName': {'hive': 'SOFTWARE', 'key': 'Microsoft\\Windows NT\\CurrentVersion', 'name': 'ProductName', 'is_ts': False},
                        'ShutdownTime': {'hive': 'SYSTEM', 'key': '{0}\\Control\\Windows'.format(currentcs), 'name': 'ShutdownTime', 'is_ts': True},
                        'StandardBias': {'hive': 'SYSTEM', 'key': '{0}\\Control\\TimeZoneInformation'.format(currentcs), 'name': 'StandardBias', 'is_ts': False},
                        'SystemPartition': {'hive': 'SYSTEM', 'key': 'Setup', 'name': 'SystemPartition', 'is_ts': False},
                        'TimeZoneKeyName': {'hive': 'SYSTEM', 'key': '{0}\\Control\\TimeZoneInformation'.format(currentcs), 'name': 'TimeZoneKeyName', 'is_ts': False}, 
        }

        # this is repetitive from volatility.plugins.imageinfo but I didn't see a way to just grab this function
        """Get the Image Datetime"""
        KUSER_SHARED_DATA = obj.VolMagic(addr_space).KUSER_SHARED_DATA.v()
        k = obj.Object("_KUSER_SHARED_DATA",
                       offset = KUSER_SHARED_DATA,
                       vm = addr_space)

        if k:
            yield {'timestamp_type': "Image: DateTime", 'timestamp': k.SystemTime}

        for check in checks.keys():
            self.regapi.reset_current()
            result = {}
            k = self.regapi.reg_get_key(checks[check].get('hive'), checks[check].get('key'))
            value = self.regapi.reg_get_value(checks[check].get('hive'), checks[check].get('key'), checks[check].get('name'), given_root = k)
            result["key"] = k
            result["hive"] = checks[check].get('hive')
            result["value_name"] = checks[check].get('name')
            result["value"] = value
            result['timestamp_type'] = "Registry: LastWrite"
            result["timestamp"] = ""

            # doing this timestamp conversion was always working & therefore couldn't check if the result
            #   had a timestamp so added a key in the above check dictionary to (try) and simplify it
            if checks[check].get('is_ts'):
                try:
                    if not checks[check].get('name') == "InstallDate":
                        bufferas = addrspace.BufferAddressSpace(self._config, data = value)
                        result["timestamp"] = obj.Object("WinTimeStamp", vm = bufferas, offset = 0, is_utc = True)
                    else:
                        # This won't format to a format in volatility.plugins.overlays.windows.windows then
                        result["timestamp"] = datetime.utcfromtimestamp(value)
                except (struct.error, TypeError):
                    pass

            yield result

    def unified_output(self, data):
        return TreeGrid([("Date/Time (UTC)", str),
                            ("Type", str),
                            ("Summary", str),
                            ("Source", str),
                        ], self.generator(data)
                      )

    def generator(self, data):
        for result in data:
            yield (0, ['{0}'.format(result.get('timestamp') if result.get('timestamp') else result.get('key').LastWriteTime),
                        '{0}'.format(result.get('value') if not result.get('timestamp_type') else result.get('timestamp_type')),
                        ('' if result.get('timestamp') else '{0}'.format(result.get('value'))),
                        ('' if not result.get('hive') else '{0} | {1}\\{2}'.format(result.get('value_name'),
                                                                                    result.get('hive'),
                                                                                    ('' if not result.get('key') else self.regapi.reg_get_key_path(result.get('key')))
                                                                                )
                                            ),
                    ]
                )

    # eh, I know - but wanted it displayed in a certain way
    def render_text(self, outfd, data):
        outfd.write('\t'.join(h for h in ['Date/Time (UTC)', 'Type', 'Summary', 'Source']) + '\n')
        for result in data:
            if result.get('timestamp'):
                row = '\t'.join('{0}'.format(x) for x in [result.get('timestamp'),
                                                            (result.get('value') if not result.get('timestamp_type') else result.get('timestamp_type')),
                                                            '',
                                                            ('' if not result.get('hive') else'{0} | {1}\\{2}'.format(result.get('value_name'),
                                                                                                                        result.get('hive'),
                                                                                                                        ('' if not result.get('key') else self.regapi.reg_get_key_path(result.get('key')))
                                                                                                                )
                                                                                )
                                                    ]
                            )                    
            else:
                row = '\t'.join('{0}'.format(x) for x in [('' if not result.get('key') else result.get('key').LastWriteTime),
                                                            result.get('timestamp_type'),
                                                            result.get('value'),
                                                            '{0} | {1}\\{2}'.format(result.get('value_name'),
                                                                                    result.get('hive'),
                                                                                    ('' if not result.get('key') else self.regapi.reg_get_key_path(result.get('key')))
                                                                                )
                                                    ]
                            )

            outfd.write(row + '\n')