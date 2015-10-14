# Volatility
#
# Authors:  Csaba Barta
# Contact:  csaba.barta@gmail.com
# www:      http://www.ntdsxtract.com
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

import volatility.constants
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.conf as conf
import volatility.plugins.taskmods as taskmods
from volatility.plugins.filescan import DriverScan
from volatility.win32.modules import lsmod
from volatility.plugins.malware.svcscan import SvcScan

import re
import sys

MAJOR_FUNCTIONS = [
    'IRP_MJ_CREATE',
    'IRP_MJ_CREATE_NAMED_PIPE',
    'IRP_MJ_CLOSE',
    'IRP_MJ_READ',
    'IRP_MJ_WRITE',
    'IRP_MJ_QUERY_INFORMATION',
    'IRP_MJ_SET_INFORMATION',
    'IRP_MJ_QUERY_EA',
    'IRP_MJ_SET_EA',
    'IRP_MJ_FLUSH_BUFFERS',
    'IRP_MJ_QUERY_VOLUME_INFORMATION',
    'IRP_MJ_SET_VOLUME_INFORMATION',
    'IRP_MJ_DIRECTORY_CONTROL',
    'IRP_MJ_FILE_SYSTEM_CONTROL',
    'IRP_MJ_DEVICE_CONTROL',
    'IRP_MJ_INTERNAL_DEVICE_CONTROL',
    'IRP_MJ_SHUTDOWN',
    'IRP_MJ_LOCK_CONTROL',
    'IRP_MJ_CLEANUP',
    'IRP_MJ_CREATE_MAILSLOT',
    'IRP_MJ_QUERY_SECURITY',
    'IRP_MJ_SET_SECURITY',
    'IRP_MJ_POWER',
    'IRP_MJ_SYSTEM_CONTROL',
    'IRP_MJ_DEVICE_CHANGE',
    'IRP_MJ_QUERY_QUOTA',
    'IRP_MJ_SET_QUOTA',
    'IRP_MJ_PNP'
]

##########################################################################################
# PROCESSBL PLUGIN
##########################################################################################

class processbl(common.AbstractWindowsCommand):
    '''
    Scans memory for processes and loaded DLLs and compares the results with the baseline
    '''
    
    baseline_proc_list = {}
    image_proc_list = []
    image_mapped_files = {}

    # Add some options
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('BASELINEIMG', short_option = 'B', default = None,
                        help = 'Baseline image')
        config.add_option("ONLYKNOWN", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'K',
                          help = 'Display only the processes and dlls that can also be found in the baseline image')
        config.add_option("ONLYUNKNOWN", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'U',
                          help = "Display only the processes and dlls that cannot be found in the baseline image")
    
    def calculate(self):
        if self._config.BASELINEIMG == None:
            print "Baseline image required!"
            sys.exit(-1)
        
        if self._config.ONLYKNOWN and self._config.ONLYUNKNOWN:
            print "Select only one of the options (-K, -U)!"
            sys.exit(-1)
        
        #######################################
        #Searching for processes in the baseline image
        ######################################
        # Saving original image
        orig_img = self._config.LOCATION
        # Setting up baseline image
        self._config.LOCATION = "file://" + self._config.BASELINEIMG
        
        addr_space = utils.load_as(self._config)
        dlllist = taskmods.DllList(self._config)
        
        for task in dlllist.calculate():
            if task.ProcessExiting != 0: # We don't care about the exited processes
                continue
            
            proc = None
            
            if task.Peb == None:
                continue
            
            #if str(task.ImageFileName).lower() not in self.baseline_proc_list:
            if str(task.Peb.ProcessParameters.ImagePathName).lower() not in self.baseline_proc_list:
                # We haven't seen the process yet
                # Let's create a new object and add it
                proc = {
                    'pid'   : [],
                    'ppid'  : [],
                    'image' : str(task.ImageFileName).lower() or '',
                    'path'  : str(task.Peb.ProcessParameters.ImagePathName).lower() if task.Peb.ProcessParameters != None else '',
                    'cmd'   : str(task.Peb.ProcessParameters.CommandLine).lower() if task.Peb.ProcessParameters != None else '',
                    'offset': [],
                    'exited': [],
                    'dlls' : {
                        'load': {}, # load list
                        'mem' : {}, # mem list
                        'init': {}, # init list
                        'comb': {}, # combined list, contains all dlls
                        'vad' : {}  # vad list
                    }
                }
                #self.baseline_proc_list[proc['image']] = proc
                self.baseline_proc_list[proc['path']] = proc
            
            # Get process from our list
            #proc = self.baseline_proc_list[str(task.ImageFileName).lower()]
            proc = self.baseline_proc_list[str(task.Peb.ProcessParameters.ImagePathName).lower()]
            
            proc['pid'].append(task.UniqueProcessId)
            proc['ppid'].append(task.InheritedFromUniqueProcessId)
            proc['offset'].append(task.obj_offset)
            
            for m in task.get_load_modules():
                mod = {
                    'dll' : str(m.FullDllName).lower(),
                    'base': m.DllBase.v(),
                    'size': m.SizeOfImage or -1
                }
                
                if mod['dll'] not in proc['dlls']['load']:
                    proc['dlls']['load'][mod['dll']] = mod
                
                if mod['dll'] not in proc['dlls']['comb']:
                    proc['dlls']['comb'][mod['dll']] = mod
            
            for m in task.get_mem_modules():
                mod = {
                    'dll' : str(m.FullDllName).lower(),
                    'base': m.DllBase.v(),
                    'size': m.SizeOfImage or -1
                }
                
                if mod['dll'] not in proc['dlls']['mem']:
                    proc['dlls']['mem'][mod['dll']] = mod
                
                if mod['dll'] not in proc['dlls']['comb']:
                    proc['dlls']['comb'][mod['dll']] = mod
            
            for m in task.get_init_modules():
                mod = {
                    'dll' : str(m.FullDllName).lower(),
                    'base': m.DllBase.v(),
                    'size': m.SizeOfImage or -1
                }
                
                if mod['dll'] not in proc['dlls']['init']:
                    proc['dlls']['init'][mod['dll']] = mod
                
                if mod['dll'] not in proc['dlls']['comb']:
                    proc['dlls']['comb'][mod['dll']] = mod
            
            # Check VADs
            # Add only the missing modules
            for vad, address_space in task.get_vads(vad_filter = task._mapped_file_filter):
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = address_space).e_magic != 0x5A4D:
                    continue
                mod = {
                    'dll' : str(vad.FileObject.FileName or '').lower(),
                    'base': int(vad.Start),
                    'size': int(vad.Length)
                }
                
                if mod['dll'] not in proc['dlls']['vad']:
                    proc['dlls']['vad'][mod['dll']] = mod
                
                f = False
                for m in proc['dlls']['comb']:
                    if proc['dlls']['comb'][m]['base'] == mod['base']:
                        f = True
                if not f:
                    proc['dlls']['comb'][mod['dll']] = mod
        
        ####################################
        #Searching for processes in the image to be analyzed
        ##################################
        # Restoring original image
        self._config.LOCATION = orig_img
        
        addr_space = utils.load_as(self._config)
        dlllist = taskmods.DllList(self._config)
        
        for task in dlllist.calculate():
            if task.Peb == None:
                continue
            
            proc = {
                'pid'   : task.UniqueProcessId,
                'ppid'  : task.InheritedFromUniqueProcessId,
                'image' : str(task.ImageFileName).lower(),
                'path'  : str(task.Peb.ProcessParameters.ImagePathName).lower() if task.Peb.ProcessParameters != None else '',
                'cmd'   : str(task.Peb.ProcessParameters.CommandLine).lower() if task.Peb.ProcessParameters != None else '',
                'offset': task.obj_offset,
                'dlls' : {
                    'load': {},
                    'mem' : {},
                    'init': {},
                    'comb': {},
                    'vad' : {}
                }
            }
            
            for m in task.get_load_modules():
                mod = {
                    'dll' : str(m.FullDllName).lower(),
                    'base': m.DllBase.v(),
                    'size': m.SizeOfImage or -1
                }
                proc['dlls']['load'][mod['dll']] = mod
                proc['dlls']['comb'][mod['dll']] = mod
            
            for m in task.get_mem_modules():
                mod = {
                    'dll' : str(m.FullDllName).lower(),
                    'base': m.DllBase.v(),
                    'size': m.SizeOfImage or -1
                }
                proc['dlls']['mem'][mod['dll']] = mod
                if mod['dll'] not in proc['dlls']['comb']:
                    proc['dlls']['comb'][mod['dll']] = mod
            
            for m in task.get_init_modules():
                mod = {
                    'dll' : str(m.FullDllName).lower(),
                    'base': m.DllBase.v(),
                    'size': m.SizeOfImage or -1
                }
                proc['dlls']['init'][mod['dll']] = mod
                if mod['dll'] not in proc['dlls']['comb']:
                    proc['dlls']['comb'][mod['dll']] = mod
            
            # Check the VADs
            # Add only the missing modules
            for vad, address_space in task.get_vads(vad_filter = task._mapped_file_filter):
                if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = address_space).e_magic != 0x5A4D:
                    continue
                mod = {
                    'dll' : str(vad.FileObject.FileName or '').lower(),
                    'base': int(vad.Start),
                    'size': int(vad.Length)
                }
                proc['dlls']['vad'][mod['dll']] = mod
                f = False
                for m in proc['dlls']['comb']:
                    if proc['dlls']['comb'][m]['base'] == mod['base']:
                        f = True
                if not f:
                    proc['dlls']['comb'][mod['dll']] = mod
            
            self.image_proc_list.append(proc)
        
        # Compare the lists
        for task in self.image_proc_list: # Check all the processes in the image
            #if task['path'] != '':
            image = task['path']
            #else:
            #    image = task['image']
            p_found = False
            if image in self.baseline_proc_list: # If the process is found
                task_bl = self.baseline_proc_list[image]
                p_found = True
                if self._config.VERBOSE:
                    for m in task['dlls']['comb']:
                        # Check if we have the dll in our combined list of the baseline
                        m_found = False
                        for m_bl in self.baseline_proc_list[image]['dlls']['comb']:
                            if task['dlls']['comb'][m]['dll'] == task_bl['dlls']['comb'][m_bl]['dll']:
                                m_found = True
                    
                        # Check in which lists we can find it in the baseline
                        m_l = False
                        for m_bl in self.baseline_proc_list[image]['dlls']['load']:
                            if task['dlls']['comb'][m]['dll'] == task_bl['dlls']['load'][m_bl]['dll']:
                                m_l = True
                    
                        m_i = False
                        for m_bl in self.baseline_proc_list[image]['dlls']['init']:
                            if task['dlls']['comb'][m]['dll'] == task_bl['dlls']['init'][m_bl]['dll']:
                                m_i = True
                    
                        m_m = False
                        for m_bl in self.baseline_proc_list[image]['dlls']['mem']:
                            if task['dlls']['comb'][m]['dll'] == task_bl['dlls']['mem'][m_bl]['dll']:
                                m_m = True
                    
                        # Check in which lists we can find it in our image
                        m_l_i = False
                        if task['dlls']['comb'][m]['dll'] in task['dlls']['load']:
                            m_l_i = True
                    
                        m_i_i = False
                        if task['dlls']['comb'][m]['dll'] in task['dlls']['init']:
                            m_i_i = True
                    
                        m_m_i = False
                        if task['dlls']['comb'][m]['dll'] in task['dlls']['mem']:
                            m_m_i = True
                    
                        if not self._config.ONLYKNOWN and not self._config.ONLYUNKNOWN:
                            yield(task, m, p_found, m_found, m_l, m_i, m_m, m_l_i, m_i_i, m_m_i)
                    
                        if self._config.ONLYKNOWN and m_found:
                            yield(task, m, p_found, m_found, m_l, m_i, m_m, m_l_i, m_i_i, m_m_i)
                    
                        if self._config.ONLYUNKNOWN and not m_found:
                            yield(task, m, p_found, m_found, m_l, m_i, m_m, m_l_i, m_i_i, m_m_i)
                else:
                    if not self._config.ONLYKNOWN and not self._config.ONLYUNKNOWN:
                        yield(task, p_found)
                
                    if self._config.ONLYKNOWN and p_found:
                        yield(task, p_found)
                
                    if self._config.ONLYUNKNOWN and not p_found:
                        yield(task, p_found)
                    
            else: # The process is not in our baseline
                m_found = False
                if self._config.VERBOSE:
                    for m in task['dlls']['comb']:
                        m_l_i = False
                        if task['dlls']['comb'][m]['dll'] in task['dlls']['load']:
                            m_l_i = True
                    
                        m_i_i = False
                        if task['dlls']['comb'][m]['dll'] in task['dlls']['init']:
                            m_i_i = True
                    
                        m_m_i = False
                        if task['dlls']['comb'][m]['dll'] in task['dlls']['mem']:
                            m_m_i = True
                    
                        if not self._config.ONLYKNOWN:
                            yield(task, m, p_found, m_found, False, False, False, m_l_i, m_i_i, m_m_i)
                else:
                    if not self._config.ONLYKNOWN:
                            yield(task, p_found)
    
    def render_text(self, outfd, data):
        """Renders the text-based output"""
        if self._config.VERBOSE:
            self.table_header(outfd, [('Proc_Offset(I)(V)', '[addrpad]'),
                                  ('Image name', '15'),
                                  ('PID(I)', '4'),
                                  ('PPID(I)', '4'),
                                  ('PFound(B)', '5'),
                                  ('DLL_Base(I)(V)', '[addrpad]'),
                                  ('DLL_Size(I)', '[addr]'),
                                  ('MFound(B)', '5'),
                                  ('L(I)', '1'),
                                  ('I(I)', '1'),
                                  ('M(I)', '1'),
                                  ('L(B)', '1'),
                                  ('I(B)', '1'),
                                  ('M(B)', '1'),
                                  ('DLL image name(I)', '')
                                  ])

            for task, m, p_found, m_found, m_l, m_i, m_m, m_l_i, m_i_i, m_m_i in data:
                self.table_row(outfd,
                         task['offset'],
                         task['image'],
                         task['pid'],
                         task['ppid'],
                         str(p_found),
                         task['dlls']['comb'][m]['base'],
                         task['dlls']['comb'][m]['size'],
                         str(m_found),
                         m_l_i, # Load list in image
                         m_i_i, # Init list in image
                         m_m_i, # Mem list in image
                         m_l, # Load list in baseline
                         m_i, # Init list in baseline
                         m_m, # Mem list in baseline
                         task['dlls']['comb'][m]['dll']
                         )
        else:
            self.table_header(outfd, [('Proc_Offset(I)(V)', '[addrpad]'),
                                  ('Image name', '15'),
                                  ('Image path', '50'),
                                  ('PID(I)', '4'),
                                  ('PPID(I)', '4'),
                                  ('PFound(B)', '5')
                                  ])

            for task, p_found in data:
                self.table_row(outfd,
                         task['offset'],
                         task['image'],
                         task['path'],
                         task['pid'],
                         task['ppid'],
                         str(p_found)
                         )

##########################################################################################
# DRIVERBL PLUGIN
##########################################################################################

class driverbl(common.AbstractWindowsCommand):
    '''
    Scans memory for driver objects and compares the results with the baseline image
    '''
    baseline_drv_list = []
    baseline_mod_list = []
    image_drv_list = []
    image_mod_list = []
    
    # Add some options
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('BASELINEIMG', short_option = 'B', default = None,
                        help = 'Baseline memory image')
        config.add_option("ONLYKNOWN", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'K',
                          help = 'Consider only the services that were also found in the baseline image')
        config.add_option("ONLYUNKNOWN", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'U',
                          help = "Consider only the services that are unknown in the baseline image")

    def calculate(self):
        if self._config.BASELINEIMG == None:
            print "Baseline image required!"
            sys.exit()
        
        if self._config.ONLYKNOWN and self._config.ONLYUNKNOWN:
            print "Select only one of the options (-K, -U)!"
            sys.exit(-1)
        
        #######################################
        #Searching for drivers in baseline image
        ######################################
        # Saving original image
        orig_img = self._config.LOCATION
        # Setting up baseline image
        self._config.LOCATION = "file://" + self._config.BASELINEIMG

        # Instantiating DriverScan plugin
        addr_space = utils.load_as(self._config)
        drv_scan = DriverScan(self._config)
        
        if volatility.constants.VERSION != "2.4":
            for obj, drv, ext  in drv_scan.calculate():
                if ext.ServiceKeyName != None:
                    service_key_name = str(ext.ServiceKeyName).lower()
                else:
                    service_key_name = None
                
                if obj.NameInfo.Name != None:
                    name = str(obj.NameInfo.Name).lower()
                else:
                    name = None
                
                if drv.DriverName != None:
                    driver_name = str(drv.DriverName).lower()
                else:
                    driver_name = None
                
                if drv.DriverSize != None:
                    driver_size = drv.DriverSize
                else:
                    driver_size = None
                
                if drv.DriverStart != None:
                    driver_start = drv.DriverStart
                else:
                    driver_start = None
                
                mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in lsmod(addr_space))
                mod_addrs = sorted(mods.keys())
                
                IRPs = {}
                for i, function in enumerate(drv.MajorFunction):
                    function = drv.MajorFunction[i]
                    module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(function))
                    if module:
                        module_name = str(module.BaseDllName or '').lower()
                    else:
                        module_name = "unknown"
                    IRPs[MAJOR_FUNCTIONS[i]] = module_name               
                
                self.baseline_drv_list.append({
                                                'service_key_name': service_key_name,
                                                'name': name,
                                                'driver_name': driver_name,
                                                'driver_size': driver_size,
                                                'driver_start': driver_start,
                                                'irps': IRPs
                                            })
        else:
            for driver in drv_scan.calculate():
                header = driver.get_object_header()
                if driver.DriverExtension.ServiceKeyName != None:
                    service_key_name = str(driver.DriverExtension.ServiceKeyName).lower()
                else:
                    service_key_name = None
                
                if header.NameInfo.Name != None:
                    name = str(header.NameInfo.Name).lower()
                else:
                    name = None
                
                if driver.DriverName != None:
                    driver_name = str(driver.DriverName).lower()
                else:
                    driver_name = None
                
                if driver.DriverSize != None:
                    driver_size = driver.DriverSize
                else:
                    driver_size = None
                
                if driver.DriverStart != None:
                    driver_start = driver.DriverStart
                else:
                    driver_start = None
                
                mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in lsmod(addr_space))
                mod_addrs = sorted(mods.keys())
                
                IRPs = {}
                for i, function in enumerate(driver.MajorFunction):
                    function = driver.MajorFunction[i]
                    module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(function))
                    if module:
                        module_name = str(module.BaseDllName or '').lower()
                    else:
                        module_name = "unknown"
                    IRPs[MAJOR_FUNCTIONS[i]] = module_name               
                
                self.baseline_drv_list.append({
                                                'service_key_name': service_key_name,
                                                'name': name,
                                                'driver_name': driver_name,
                                                'driver_size': driver_size,
                                                'driver_start': driver_start,
                                                'irps': IRPs
                                            })
        
        # Instantiating Modules plugin
        for m in lsmod(addr_space):
            self.baseline_mod_list.append({
                                            'full_dll_name': str(m.FullDllName).lower(),
                                            'base_dll_name': str(m.BaseDllName).lower(),
                                            'dll_base': m.DllBase
                                        })
            
            for drv in self.baseline_drv_list:
                if drv['driver_start'] == m.DllBase:
                    if m.FullDllName != None:
                        drv['full_dll_name'] = str(m.FullDllName).lower()
                    else:
                        drv['full_dll_name'] = None
                    if m.BaseDllName != None:
                        drv['base_dll_name'] = str(m.BaseDllName).lower()
                    else:
                        drv['base_dll_name'] = None
        
        # Fixing entries that are not in the list of loaded modules list
        for drv in self.baseline_drv_list:
            f = False
            for m in self.baseline_mod_list:
                if m['dll_base'] == drv['driver_start']:
                    f = True
            if not f:
                drv['full_dll_name'] = None
                drv['base_dll_name'] = None
        
        ####################################
        #Searching for drivers in the image to be analyzed
        ##################################
        # Restoring original image
        self._config.LOCATION = orig_img
        
        # Instantiating DriverScan plugin
        addr_space = utils.load_as(self._config)
        drv_scan = DriverScan(self._config)
        if volatility.constants.VERSION != "2.4":
            for obj, drv, ext  in drv_scan.calculate():
                if ext.ServiceKeyName != None:
                    service_key_name = str(ext.ServiceKeyName).lower()
                else:
                    service_key_name = None
                
                if obj.NameInfo.Name != None:
                    name = str(obj.NameInfo.Name).lower()
                else:
                    name = None
                
                if drv.DriverName != None:
                    driver_name = str(drv.DriverName).lower()
                else:
                    driver_name = None
                
                if drv.DriverSize != None:
                    driver_size = drv.DriverSize
                else:
                    driver_size = None
                
                if drv.DriverStart != None:
                    driver_start = drv.DriverStart
                else:
                    driver_start = None
                
                mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in lsmod(addr_space))
                mod_addrs = sorted(mods.keys())
                
                IRPs = {}
                for i, function in enumerate(drv.MajorFunction):
                    function = drv.MajorFunction[i]
                    module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(function))
                    if module:
                        module_name = str(module.BaseDllName or '').lower()
                    else:
                        module_name = "unknown"
                    IRPs[MAJOR_FUNCTIONS[i]] = module_name
                
                self.image_drv_list.append({
                                                'service_key_name': service_key_name,
                                                'name': name,
                                                'driver_name': driver_name,
                                                'driver_size': driver_size,
                                                'driver_start': driver_start,
                                                'irps': IRPs,
                                                'obj': obj,
                                                'drv': drv,
                                                'ext': ext
                                            })
        else:
            for driver in drv_scan.calculate():
                header = driver.get_object_header()
                if driver.DriverExtension.ServiceKeyName != None:
                    service_key_name = str(driver.DriverExtension.ServiceKeyName).lower()
                else:
                    service_key_name = None
                
                if header.NameInfo.Name != None:
                    name = str(header.NameInfo.Name).lower()
                else:
                    name = None
                
                if driver.DriverName != None:
                    driver_name = str(driver.DriverName).lower()
                else:
                    driver_name = None
                
                if driver.DriverSize != None:
                    driver_size = driver.DriverSize
                else:
                    driver_size = None
                
                if driver.DriverStart != None:
                    driver_start = driver.DriverStart
                else:
                    driver_start = None
                
                mods = dict((addr_space.address_mask(mod.DllBase), mod) for mod in lsmod(addr_space))
                mod_addrs = sorted(mods.keys())
                
                IRPs = {}
                for i, function in enumerate(driver.MajorFunction):
                    function = driver.MajorFunction[i]
                    module = tasks.find_module(mods, mod_addrs, addr_space.address_mask(function))
                    if module:
                        module_name = str(module.BaseDllName or '').lower()
                    else:
                        module_name = "unknown"
                    IRPs[MAJOR_FUNCTIONS[i]] = module_name
                
                self.image_drv_list.append({
                                                'service_key_name': service_key_name,
                                                'name': name,
                                                'driver_name': driver_name,
                                                'driver_size': driver_size,
                                                'driver_start': driver_start,
                                                'irps': IRPs,
                                                'obj': header,
                                                'drv': driver,
                                                'ext': driver.DriverExtension
                                            })
        
        for m in lsmod(addr_space):
            self.image_mod_list.append({
                                            'full_dll_name': str(m.FullDllName).lower(),
                                            'base_dll_name': str(m.BaseDllName).lower(),
                                            'dll_base': m.DllBase
                                        })
            for drv in self.image_drv_list:
                if drv['driver_start'] == m.DllBase:
                    if m.FullDllName != None:
                        drv['full_dll_name'] = str(m.FullDllName).lower()
                    else:
                        drv['full_dll_name'] = None
                    if m.BaseDllName != None:
                        drv['base_dll_name'] = str(m.BaseDllName).lower()
                    else:
                        drv['base_dll_name'] = None
        
        # Fixing up entries that are not in the list of loaded modules list
        for drv in self.image_drv_list:
            f = False
            for m in self.image_mod_list:
                if m['dll_base'] == drv['driver_start']:
                    f = True
            if not f:
                drv['full_dll_name'] = None
                drv['base_dll_name'] = None
        
        # Compare the lists
        for drv in self.image_drv_list:
            known = False
            d_name = False
            drv_name = False
            drv_size = False
            drv_mod = False
            drv_irp = False
            drv_bl = None
            for bl_drv in self.baseline_drv_list:
                
                if drv['service_key_name'] == bl_drv['service_key_name']:
                    known = True
                    
                    if drv['name'] == bl_drv['name']:
                        d_name = True
                    elif self._config.VERBOSE:
                        print "Name:"
                        print "Baseline: " + bl_drv['name']
                        print "Image:    " + drv['name']
                    
                    if drv['driver_name'] == bl_drv['driver_name']:
                        drv_name = True
                    elif self._config.VERBOSE:
                        print "Driver Name:"
                        print "Baseline: " + str(bl_drv['driver_name'])
                        print "Image:    " + str(drv['driver_name'])
                    
                    if drv['driver_size'] == bl_drv['driver_size']:
                        drv_size = True
                    elif self._config.VERBOSE:
                        print "Driver Size:"
                        print "Baseline: " + str(bl_drv['driver_size'])
                        print "Image:    " + str(drv['driver_size'])
                    
                    if drv['full_dll_name'] == bl_drv['full_dll_name']:
                        drv_mod = True
                    elif self._config.VERBOSE:
                        print "Module:"
                        print "Baseline: " + str(bl_drv['full_dll_name'])
                        print "Image:    " + str(drv['full_dll_name'])
                        
                    drv_irp = True
                    for m in drv['irps']:
                        if drv['irps'][m] != bl_drv['irps'][m]:
                            drv_irp = False
                    
                if known:
                    drv_bl = bl_drv
                    break
            
            if self._config.ONLYKNOWN:
                if known:
                    yield (drv['obj'], drv['drv'], drv['ext'], known, d_name, drv_name, drv_mod, drv_size, drv['full_dll_name'], drv_irp, drv['irps'], drv_bl['irps'])
            if self._config.ONLYUNKNOWN:
                if not known:
                    yield (drv['obj'], drv['drv'], drv['ext'], known, d_name, drv_name, drv_mod, drv_size, drv['full_dll_name'], drv_irp, drv['irps'], None)
            if not self._config.ONLYKNOWN and not self._config.ONLYUNKNOWN:
                if drv_bl:
                    yield (drv['obj'], drv['drv'], drv['ext'], known, d_name, drv_name, drv_mod, drv_size, drv['full_dll_name'], drv_irp, drv['irps'], drv_bl['irps'])
                else:
                    yield (drv['obj'], drv['drv'], drv['ext'], known, d_name, drv_name, drv_mod, drv_size, drv['full_dll_name'], drv_irp, drv['irps'], None)

    def render_text(self, outfd, data):
        """Renders the text-based output"""
        self.table_header(outfd, [('Offset(P)', '[addrpad]'),
                                  ('Service Key', '20'),
                                  ('Found', '5'),
                                  ('Name', '5'),
                                  ('DName', '5'),
                                  ('Module', '5'),
                                  ('Size','5'),
                                  ('IRPs', '5'),
                                  ('Path', '')
                                  ])

        for object_obj, driver_obj, extension_obj, known, d_name, drv_name, drv_mod, drv_size, drv_path, drv_irp, drv_irps, drv_bl_irps in data:

            self.table_row(outfd,
                         driver_obj.obj_offset,
                         str(extension_obj.ServiceKeyName or ''),
                         str(known),
                         str(d_name),
                         str(drv_name),
                         str(drv_mod),
                         str(drv_size),
                         str(drv_irp),
                         str(drv_path)
                         )
##########################################################################################
# SERVICEBL PLUGIN
##########################################################################################
class servicebl(common.AbstractWindowsCommand):
    '''
    Scans memory for service objects and compares the results with the baseline image
    '''
    
    baseline_svc_list = []
    
    # Add some options
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('BASELINEIMG', short_option = 'B', default = None,
                        help = 'Baseline image to use for comparision')
        config.add_option("ONLYRUNNING", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'R',
                          help = 'Consider only running services')
        config.add_option("ONLYKNOWN", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'K',
                          help = 'Consider only the services that were also found in the baseline image')
        config.add_option("ONLYUNKNOWN", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'U',
                          help = "Consider only the services that are unknown in the baseline image")

    def calculate(self):
        if self._config.BASELINEIMG == None:
            print "Please specify a baseline image!"
            sys.exit()
        
        if self._config.ONLYKNOWN and self._config.ONLYUNKNOWN:
            print "Select only one of the options (-K, -U)!"
            sys.exit(-1)
        
        #######################################
        #Searching for services in baseline image
        ######################################
        # Saving original image
        orig_img = self._config.LOCATION
        # Setting baseline image
        self._config.LOCATION = "file://" + self._config.BASELINEIMG

        # Instantiating SvcScan plugin
        addr_space = utils.load_as(self._config)
        svc_scan = SvcScan(self._config)

        for svc in svc_scan.calculate():
            if svc.ServiceName.dereference() != None:
                service_name = str(svc.ServiceName.dereference()).lower()
            else:
                service_name = None
            
            if svc.DisplayName.dereference() != None:
                display_name = str(svc.DisplayName.dereference()).lower()
            else:
                display_name = None
            
            service_type = svc.Type
            
            service_state = svc.State
            
            if svc.Binary != None:
                binary_path = str(svc.Binary).lower()
            else:
                binary_path = None
            
            self.baseline_svc_list.append([
                                            service_name,
                                            display_name,
                                            service_type,
                                            service_state,
                                            binary_path
                                        ])

        ####################################
        #Searching for services in the image to be analyzed
        ##################################
        # Restoring original image
        self._config.LOCATION = orig_img
        
        # Instantiating SvcScan plugin
        addr_space = utils.load_as(self._config)
        svc_scan = SvcScan(self._config)
        
        for svc in svc_scan.calculate():
            if svc.ServiceName.dereference() != None:
                service_name = str(svc.ServiceName.dereference()).lower()
            else:
                service_name = None
            
            if svc.DisplayName.dereference() != None:
                display_name = str(svc.DisplayName.dereference()).lower()
            else:
                display_name = None
            
            service_type = svc.Type
            
            service_state = svc.State
            
            if svc.Binary != None:
                binary_path = str(svc.Binary).lower()
            else:
                binary_path = None
            
            # Check the service found
            svc_known = False
            disp_name = False
            svc_type = False
            svc_state = False
            bin_path = False
            
            for bl_service_name, bl_display_name, bl_service_type, bl_service_state, bl_binary_path in self.baseline_svc_list:
                
                if service_name == bl_service_name:
                    svc_known = True
                    
                    if display_name == bl_display_name:
                        disp_name = True
                    
                    if service_type == bl_service_type:
                        svc_type = True
                    
                    if service_state == bl_service_state:
                        svc_state = True
                    
                    if binary_path == bl_binary_path:
                        bin_path = True
                
                if svc_known:
                    break
            
            if self._config.ONLYRUNNING == 1:
                if self._config.ONLYKNOWN:
                    if svc.State == 4 and svc_known:
                        yield (svc, svc_known, disp_name, bin_path, svc_type, svc_state,
                               bl_display_name, bl_service_type, bl_service_state, bl_binary_path)
                if self._config.ONLYUNKNOWN:
                    if svc.State == 4 and not svc_known:
                        yield (svc, svc_known, disp_name, bin_path, svc_type, svc_state,
                               bl_display_name, bl_service_type, bl_service_state, bl_binary_path)
                if not self._config.ONLYKNOWN and not self._config.ONLYUNKNOWN:
                    if svc.State == 4:
                        yield (svc, svc_known, disp_name, bin_path, svc_type, svc_state,
                               bl_display_name, bl_service_type, bl_service_state, bl_binary_path)
            else:
                if self._config.ONLYKNOWN:
                    if svc_known:
                        yield (svc, svc_known, disp_name, bin_path, svc_type, svc_state,
                               bl_display_name, bl_service_type, bl_service_state, bl_binary_path)
                if self._config.ONLYUNKNOWN:
                    if not svc_known:
                        yield (svc, svc_known, disp_name, bin_path, svc_type, svc_state,
                               bl_display_name, bl_service_type, bl_service_state, bl_binary_path)
                if not self._config.ONLYKNOWN and not self._config.ONLYUNKNOWN:
                        yield (svc, svc_known, disp_name, bin_path, svc_type, svc_state,
                               bl_display_name, bl_service_type, bl_service_state, bl_binary_path)

    def render_text(self, outfd, data):
        self.table_header(outfd, [
                            ("Offset", "[addrpad]"),
                            ("Service Name", "30"),
                            ("PID", "5"),
                            ("Found", "5"),
                            ("DName", "5"),
                            ("Path", "5"),
                            ("Type","5"),
                            ("State","5")
                            ])  
        for svc in data:
            self.table_row(outfd,
                svc[0].obj_offset,
                svc[0].ServiceName.dereference(),
                svc[0].Pid,
                str(svc[1]),
                str(svc[2]),
                str(svc[3]),
                str(svc[4]),
                str(svc[5])
                )
            if self._config.VERBOSE and svc[1]:
                if not svc[2]:
                    print "Display Name:"
                    print "  Baseline: " + str(svc[6])
                    if svc[0].DisplayName.dereference() != None:
                        print "  Image:    " + str(svc[0].DisplayName.dereference()).lower()
                    else:
                        print "  Image:    None"
                if not svc[3]:
                    print "Binary Path:"
                    print "  Baseline: " + str(svc[9])
                    if svc[0].Binary != None:
                        print "  Image:    " + str(svc[0].Binary).lower()
                    else:
                        print "  Image:    None"
                if not svc[4]:
                    print "Service Type:"
                    print "  Baseline: " + str(svc[7])
                    print "  Image:    " + str(svc[0].Type)
                if not svc[5]:
                    print "Service State:"
                    print "  Baseline: " + str(svc[8])
                    print "  Image:    " + str(svc[0].State)
