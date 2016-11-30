# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
# Authors: James Hall And Kevin Breen

import string
import volatility.debug as debug
import volatility.plugins.common as common
import volatility.plugins.registry.registryapi as registryapi
from volatility.renderers import TreeGrid


class USBSTOR(common.AbstractWindowsCommand):
    "Parse USB Data from the Registry"

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self.regapi = None

    def string_clean_hex(self, line):
        line = str(line)
        new_line = ''
        for c in line:
            if c in string.printable:
                new_line += c
            else:
                new_line += '\\x' + c.encode('hex')
        return new_line

    def calculate(self):
        # Store teh results in a dict
        results = {}
        results['Windows Portable Devices'] = []
        results['subkeys'] = []
        results['USB_DEVICES'] = []

        # Grab the software HIVE
        debug.debug("Reading SOFTWARE Hive")
        self.regapi = registryapi.RegistryApi(self._config)
        self.regapi.set_current("SOFTWARE")


        # Windows version will be useful later on.
        WIN_VERSION_PATH = "Microsoft\\Windows NT\\CurrentVersion"
        win_ver = self.regapi.reg_get_value(hive_name="software", key=WIN_VERSION_PATH, value="CurrentVersion")
        win_ver = float(win_ver.replace('\x00', ''))

        # Windows Portable devices for things like phones
        PORTABLE_DEVICES = "Microsoft\\Windows Portable Devices\\Devices"
        portable_devices_key = self.regapi.reg_get_key('SOFTWARE', PORTABLE_DEVICES)
        portable_devices = self.regapi.reg_get_all_subkeys('SOFTWARE', PORTABLE_DEVICES,
                                                           given_root=portable_devices_key)

        for device in portable_devices:
            portable_dict = {'Serial Number': '', 'FriendlyName': ''}
            values = self.regapi.reg_yield_values('SOFTWARE', device, given_root=device)
            for val in values:
                device_name = str(device.Name)
                portable_dict['Last Write Time'] = str(device.LastWriteTime)
                portable_dict['Serial Number'] = device_name.split('#')[-2]
                portable_dict['FriendlyName'] = str(val[1].replace('\x00', ''))
                results['Windows Portable Devices'].append(portable_dict)

        # Now Jump in to the SYSTEM Hive
        self.regapi.reset_current()
        self.regapi.set_current("SYSTEM")
        debug.debug("Reading SYSTEM Hive")

        # Get the CurrentControlSet
        currentcs = self.regapi.reg_get_currentcontrolset()

        if currentcs == None:
            currentcs = "ControlSet001"

        # Get list of devices form USBSTOR
        USB_PATH = '{0}\\Enum\\USB'.format(currentcs)
        USB_STOR_PATH = '{0}\\Enum\\USBSTOR'.format(currentcs)
        MOUNTED_DEVICES = 'MountedDevices'

        usb_key = self.regapi.reg_get_key('SYSTEM', USB_PATH)
        usb_stor_key = self.regapi.reg_get_key('SYSTEM', USB_STOR_PATH)
        mounted_devices_key = self.regapi.reg_get_key('SYSTEM', MOUNTED_DEVICES)

        # Is there something there?
        if not usb_stor_key:
            results['exists'] = False
            yield results
        else:
            results['exists'] = True

        # Only run if we have something to do
        if results['exists']:
            sub_keys = self.regapi.reg_get_all_subkeys('SYSTEM', USB_STOR_PATH, given_root=usb_stor_key)
            for k in sub_keys:
                # Theses are grouped by vender
                disk, vendor, product, rev = str(k.Name).split('&')
                vendor = vendor.split('_', 1)[-1]
                product = product.split('_', 1)[-1]
                rev = rev.split('_', 1)[-1]

                results['subkeys'].append(str(k.Name))
                usb_devs = self.regapi.reg_get_all_subkeys('SYSTEM', k, given_root=k)
                for dev in usb_devs:
                    # These are individual devices
                    # This is what we use to map in to the USB_DEVICES
                    usb_info_dict = {'Serial Number': str(dev.Name),
                                     'Vendor': vendor,
                                     'Product': product,
                                     'Revision': rev}

                    # Get all the sub values
                    values = self.regapi.reg_yield_values('SYSTEM', dev, given_root=dev)
                    for val in values:
                        try:
                            key_name = val[0].replace('\x00', '')
                            key_data = val[1].replace('\x00', '')
                            usb_info_dict[str(key_name)] = key_data
                        except AttributeError:
                            key_name = val[0].replace('\x00', '')
                            try:
                                key_data = val[1].replace('\x00', '')
                            except:
                                key_data = val[1]
                            usb_info_dict[str(key_name)] = key_data

                    # Get the last written key for each device
                    serial_number = usb_info_dict['Serial Number']
                    usb_info_dict['Device Last Plugged In'] = 'Unknown'
                    usb_subkeys = self.regapi.reg_get_all_subkeys('SYSTEM', USB_PATH, given_root=usb_key)
                    for a in usb_subkeys:
                        subs = self.regapi.reg_get_all_subkeys('SYSTEM', a, given_root=a)
                        for s in subs:
                            if serial_number.split('&')[0] == s.Name:
                                usb_info_dict['Device Last Plugged In'] = str(s.LastWriteTime)

                    # Now get the Drive letters if we can
                    if win_ver >= 6.0:
                        # Win > 7, Server > 2012
                        # Mounted Devices Key
                        serial_number = usb_info_dict['Serial Number']
                        usb_info_dict['Drive Letter'] = "Unknown"
                        usb_info_dict['Mounted Volume'] = "Unknown"
                        usb_info_dict['USB Name'] = "Unknown"
                        values = self.regapi.reg_yield_values('SYSTEM', mounted_devices_key,
                                                              given_root=mounted_devices_key)

                        for val in values:
                            key_name = str(val[0])
                            key_data = val[1]
                            key_data = str(key_data.replace('\x00', ''))
                            key_data = self.string_clean_hex(key_data)
                            if serial_number in str(key_data):
                                if 'Device' in str(key_name):
                                    usb_info_dict['Drive Letter'] = str(key_name)
                                elif 'Volume' in str(key_name):
                                    usb_info_dict['Mounted Volume'] = str(key_name)
                            for portable_dict in results['Windows Portable Devices']:
                                if serial_number in portable_dict['Serial Number']:
                                    usb_info_dict['USB Name'] = str(portable_dict['FriendlyName'])
                        debug.debug(type(usb_info_dict['USB Name']))

                    if win_ver < 6.0:
                        # Win XP
                        ParentID = usb_info_dict['ParentIdPrefix']
                        usb_info_dict['Drive Letter'] = "Unknown"
                        usb_info_dict['Mounted Volume'] = "Unknown"
                        values = self.regapi.reg_yield_values('SYSTEM', mounted_devices_key,
                                                              given_root=mounted_devices_key)
                        for val in values:
                            key_name = val[0]
                            key_data = val[1]
                            key_data = key_data.replace('\x00', '')
                            key_data = self.string_clean_hex(key_data)
                            # debug.info(key_data)
                            if ParentID in key_data:
                                if 'Device' in str(key_name):
                                    usb_info_dict['Drive Letter'] = key_name
                                elif 'Volume' in str(key_name):
                                    usb_info_dict['Mounted Volume'] = key_name

                                    # ToDo: Check if the current NTUSER.dat file contains the MountPoints2 entry
                                    # If yes user = this one else user = unknown
                    results['USB_DEVICES'].append(usb_info_dict)
            # Return the results dict
            yield results

    def unified_output(self, data):

        return TreeGrid([("Serial Number", str),
                         ("Vendor", str),
                         ("Product", str),
                         ("Revision", str),
                         ("ClassGUID", str),
                         ("ContainerID", str),
                         ("Mounted Volume", str),
                         ("FriendlyName", str),
                         ("USB Name", str),
                         ("Drive Letter", str),
                         ("Device Last Plugged In", str),
                         ("Device Class", str),
                         ("Service", str),
                         ("DeviceDesc", str),
                         ("Capabilities", str),
                         ("Mfg", str),
                         ("ConfigFlags", str),
                         ("Driver", str),
                         ("CompatibleIDs", str),
                         ("HardwareID", str),
                         ("Location", str)
                         ], self.generator(data)
                        )

    def generator(self, data):
        for result in data:
            if not result['exists']:
                pass
            else:
                for usbdev in result['USB_DEVICES']:
                    yield (0, [
                        str(usbdev['Serial Number']),
                        str(usbdev['Vendor']),
                        str(usbdev['Product']),
                        str(usbdev['Revision']),
                        str(usbdev['ClassGUID']),
                        str(usbdev['ContainerID']),
                        str(usbdev['Mounted Volume']),
                        str(usbdev['FriendlyName']),
                        str(usbdev['USB Name']),
                        str(usbdev['Drive Letter']),
                        str(usbdev['Device Last Plugged In']),
                        str(usbdev['Class']),
                        str(usbdev['Service']),
                        str(usbdev['DeviceDesc']),
                        str(usbdev['Capabilities']),
                        str(usbdev['Mfg']),
                        str(usbdev['ConfigFlags']),
                        str(usbdev['Driver']),
                        str(usbdev['CompatibleIDs']),
                        str(usbdev['HardwareID']),
                        'USBSTOR'
                    ])
                for portable in result['Windows Portable Devices']:
                    yield (0, [portable['Serial Number'], '', '', '', '', '', '', '', portable['FriendlyName'], '', '',
                               portable['Last Write Time'], '', '', '', '', '', '', '', '', 'Windows Portable Devices'])

    # Print to screen
    # I wanted to make it look a little ordered rather than just write each key / val
    def render_text(self, outfd, data):
        outfd.write('Reading the USBSTOR Please Wait\n')
        for result in data:
            if not result['exists']:
                outfd.write('USBSTOR Not found in SYSTEM Hive\n')
            else:
                for usbdev in result['USB_DEVICES']:
                    outfd.write('Found USB Drive: {0}\n'.format(usbdev['Serial Number']))

                    outfd.write('\tSerial Number:\t{0}\n'.format(usbdev['Serial Number']))
                    outfd.write('\tVendor:\t{0}\n'.format(usbdev['Vendor']))
                    outfd.write('\tProduct:\t{0}\n'.format(usbdev['Product']))
                    outfd.write('\tRevision:\t{0}\n'.format(usbdev['Revision']))
                    outfd.write('\tClassGUID:\t{0}\n'.format(usbdev['Product']))
                    outfd.write('\n')
                    outfd.write('\tContainerID:\t{0}\n'.format(usbdev['ContainerID']))
                    outfd.write('\tMounted Volume:\t{0}\n'.format(usbdev['Mounted Volume']))
                    outfd.write('\tDrive Letter:\t{0}\n'.format(usbdev['Drive Letter']))
                    outfd.write('\tFriendly Name:\t{0}\n'.format(usbdev['FriendlyName']))
                    outfd.write('\tUSB Name:\t{0}\n'.format(usbdev['USB Name']))
                    outfd.write('\tDevice Last Connected:\t{0}\n'.format(usbdev['Device Last Plugged In']))
                    outfd.write('\n')
                    outfd.write('\tClass:\t{0}\n'.format(usbdev['Class']))
                    outfd.write('\tService:\t{0}\n'.format(usbdev['Service']))
                    outfd.write('\tDeviceDesc:\t{0}\n'.format(usbdev['DeviceDesc']))
                    outfd.write('\tCapabilities:\t{0}\n'.format(usbdev['Capabilities']))
                    outfd.write('\tMfg:\t{0}\n'.format(usbdev['Mfg']))
                    outfd.write('\tConfigFlags:\t{0}\n'.format(usbdev['ConfigFlags']))
                    outfd.write('\tDriver:\t{0}\n'.format(usbdev['Driver']))
                    outfd.write('\tCompatible IDs:\n')
                    for compat in usbdev['CompatibleIDs']:
                        outfd.write('\t\t{0}'.format(compat))
                        outfd.write('\n')

                    outfd.write('\tHardwareID:\n')
                    for hdid in usbdev['HardwareID']:
                        outfd.write('\t\t{0}'.format(hdid))
                        outfd.write('\n')

                outfd.write('Windows Portable Devices\n')
                for portable in result['Windows Portable Devices']:
                    outfd.write('\t--\n')
                    for k, v in portable.iteritems():
                        outfd.write('\t{0}:\t{1}\n'.format(k, v))

        outfd.write('\n')
