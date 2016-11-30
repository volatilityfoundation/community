# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
# LastPass - Recover memory resident account information.
# Author: Kevin Breen
# Thanks to the guide on http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.conf as conf
import re
import json
import string

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


signatures = {
    'lastpass_struct_a': 'rule lastpass_strcuta {strings: $a = /{"reqinfo":.*"lplanguage":""}/ condition: $a}\n'
                         'rule lastpass_strcutb {strings: $a = /"tld":".*?","unencryptedUsername":".*?","realmmatch"/ condition: $a}\n'
                         'rule lastpass_strcutc {strings: $a = /{"cmd":"save"(.*?)"tld":"(.*?)"}/ condition: $a}\n'
                         'rule lastpass_strcutd {strings: $a = /"realurl":"(.*?)"domains":"(.*?)"/ condition: $a}\n'
                         'rule lastpass_strcute {strings: $a = /{"cmd":"save"(.*?)"formdata"(.*?)}/ condition: $a}\n'
                         'rule lastpass_priv1 {strings: $a = /LastPassPrivateKey<(.*?)>LastPassPrivateKey/ condition: $a}'
}

config = conf.ConfObject()
config.add_option('CONFSIZE', short_option='C', default=4000,
                           help ='Config data size',
                           action ='store', type='int')
config.add_option('YARAOFFSET', short_option='Y', default=0,
                           help ='YARA start offset',
                           action ='store', type='int')

class LastPass(taskmods.PSList):
    """ Extract lastpass data from process. """

    def calculate(self):
        """ Required: Runs YARA search to find hits """
        if not has_yara:
            debug.error('Yara must be installed for this plugin')

        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources = signatures)
        for task in self.filter_tasks(tasks.pslist(addr_space)):
            if not task.ImageFileName.lower() in ['chrome.exe', 'firefox.exe', 'iexplore.exe']:
                continue
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():
                yield task, address

    def string_clean_hex(self, line):
        line = str(line)
        new_line = ''
        for c in line:
            if c in string.printable:
                new_line += c
            else:
                new_line += '\\x' + c.encode('hex')
        return new_line


    def clean_json(self, raw_data):
        # We deliberately pull in too much data to make sure we get it all.
        # Now parse it out again

        if raw_data.startswith('LastPassPrivate'):
            pattern = 'LastPassPrivateKey<(.*?)>LastPassPrivateKey'
            key_data = re.search(pattern, raw_data).group(0)
            if not any(substring in key_data for substring in ['"+a+"', 'indexOf']):
                return self.string_clean_hex(key_data)

        else:

            if raw_data.startswith("{\"cmd"):
                if 'formdata' in raw_data:
                    pattern = '{"cmd":"save"(.*?)"formdata"(.*?)}'
                    val_type = 'mixedform'
                else:
                    pattern = '{"cmd":"save"(.*?)"tld":"(.*?)"}'
                    val_type = 'mixed'

            elif raw_data.startswith("\"realurl"):
                pattern = '"realurl":"(.*?)"domains":"(.*?)"'
                val_type = 'mixed'

            elif raw_data.startswith("\"tld"):
                pattern = '"tld":".*?","unencryptedUsername":".*?","realmmatch"'
                val_type = 'username'

            elif raw_data.startswith('{"reqinfo"'):
                pattern = '{"reqinfo":.*?"lplanguage":""}'
                val_type = 'password'
            else:
                pass

            match = re.search(pattern, raw_data)
            real_data = self.string_clean_hex(match.group(0))

            if val_type == 'username':
                vars = real_data.split(',')
                tld = vars[0].split(':')[1].strip('"')
                username = vars[1].split(':')[1].strip('"')
                return {'type': 'username', 'username': username, 'tld': tld}

            elif val_type == 'mixedform':
                if '"tld":"' in real_data:
                    # Try to parse as json
                    try:
                        json_data = json.loads(real_data)
                        tld = json_data['tld']
                        password = json_data['password']
                        username = json_data['username']
                        clean_data = {'type': 'mixed', 'username': username, 'tld': tld, 'password': password}
                    except ValueError:
                        # Json fails manual parse
                        tld = re.search('"tld":"(.*?)"', real_data)
                        if not tld:
                            tld = re.search('"domains":"(.*?)"', real_data)
                        if tld:
                            tld = tld.group(0).split(':')[-1].strip('"')
                        else:
                            tld = 'unknown'
                        try:
                            password = re.search('"password":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                        except:
                            password = 'Unknown'
                        try:
                            username = re.search('"username":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                        except:
                            username = 'Unknown'
                        clean_data = {'type': 'mixed', 'username': username, 'tld': tld, 'password': password}

                else:
                    tld = re.search('"url":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                    username = re.search('login(.*?)text', real_data).group(0).split('\\t')[1]
                    password = re.search('password(.*?)password', real_data).group(0).split('\\t')[1]
                    clean_data = {'type': 'mixed', 'username': username, 'tld': tld, 'password': password}

                return clean_data

            elif val_type == 'mixed':
                # Try to parse as json
                try:
                    json_data = json.loads(real_data)
                    tld = json_data['tld']
                    password = json_data['password']
                    username = json_data['username']
                    clean_data = {'type': 'mixed', 'username': username, 'tld': tld, 'password': password}
                except ValueError:
                    # Json fails manual parse
                    tld = re.search('"tld":"(.*?)"', real_data)
                    if not tld:
                        tld = re.search('"domains":"(.*?)"', real_data)

                    if tld:
                        tld = tld.group(0).split(':')[-1].strip('"')
                    else:
                        tld = 'unknown'

                    try:
                        password = re.search('"password":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                    except:
                        password = 'Unknown'
                    try:
                        username = re.search('"username":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                    except:
                        username = 'Unknown'

                    clean_data = {'type': 'mixed', 'username': username, 'tld': tld, 'password': password}
            else:
                # Try to parse as json
                try:
                    json_data = json.loads(real_data)
                    tld = json_data['domains']
                    password = json_data['value']
                    clean_data = {'type': 'password', 'password': password, 'tld': tld}
                except ValueError:
                    # Json fails manual parse
                    password = re.search('"value":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                    tld = re.search('"domains":"(.*?)"', real_data).group(0).split(':')[-1].strip('"')
                    clean_data = {'type': 'password', 'password': password, 'tld': tld}

            return clean_data

    def render_text(self, outfd, data):
        """ Required: Parse data and display """
        outfd.write("Searching for LastPass Signatures\n")

        rules = yara.compile(sources=signatures)

        results = {}
        priv_keys = []

        for task, address in data:  # iterate the yield values from calculate()
            outfd.write('Found pattern in Process: {0} ({1})\n'.format(task.ImageFileName, task.UniqueProcessId))
            proc_addr_space = task.get_process_address_space()
            raw_data = proc_addr_space.read(address + self._config.YARAOFFSET, self._config.CONFSIZE)
            if raw_data:
                clean_data = self.clean_json(raw_data)
                if not clean_data:
                    continue
                if 'PrivateKey' in clean_data:
                    priv_keys.append(clean_data)
                else:
                    # If we already created the dict
                    if clean_data['tld'] in results:
                        if 'username' in clean_data:
                            if results[clean_data['tld']]['username'] == 'Unknown':
                                results[clean_data['tld']]['username'] = clean_data['username']
                        if 'password' in clean_data:
                            if results[clean_data['tld']]['password'] == 'Unknown':
                                results[clean_data['tld']]['password'] = clean_data['password']
                    # Else create the dict
                    else:
                        if 'username' in clean_data:
                            username = clean_data['username']
                        else:
                            username = 'Unknown'
                        if 'password' in clean_data:
                            password = clean_data['password']
                        else:
                            password = 'Unknown'
                        results[clean_data['tld']] = {'username': username, 'password': password}

        for k, v in results.iteritems():
            outfd.write("\nFound LastPass Entry for {0}\n".format(k))
            outfd.write('UserName: {0}\n'.format(v['username']))
            outfd.write('Pasword: {0}\n'.format(v['password']))
        outfd.write('\n')

        for key in priv_keys:
            outfd.write('\nFound Private Key\n')
            outfd.write('{0}\n'.format(key))
