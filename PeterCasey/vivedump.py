
# Vivedump
# Peter Casey
# UNHcFREG
# Donated under VFI Individual Contributor Licensing Agreement
#
# Dumps VR tracking information and whatever else we can find 

import json
import struct
import visualizer as vis
import os

import volatility.plugins.common as common
import volatility.plugins.taskmods as taskmods
import volatility.utils as utils
import volatility.win32 as win32
import volatility.debug as debug
from volatility.renderers import TreeGrid

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# Using a hex string rather than trying to deal with escape characters
# string = jsonid" : "chaperone_info"
YARA_JSON = {
    'chap_config': 'rule chap_config { strings: $p = {6a736f6e696422203a20226368617065726f6e655f696e666f} condition: $p}',
}

# The opcode that loads the pointer into rax
YARA_HMD = {
    'hmd_pointer': 'rule hmd_pointer { strings: $p = {48 8b 05 25 D6 10 00} condition: $p}',
}

YARA_HMD_ACTIVITY = {
    'hmd_activity': 'rule hmd_activity { strings: $p = {48 8b 05 55 A4 13 00} condition: $p}',
}

DEVICE_OFFSETS = [0x10D62C]
HMD_ACTIVITY_OFFSETS = [0x13A45C, 0x1E0, 0xB8, 0x78]
HMD_STATE_OFFSETS = [0x13A45C, 0x1E0, 0xB8, 0x68]
DCLASS_2_OFFSETS = [0x13A45C, 0x190, 0x8, 0x510, 0x3E0, 0x120]

# Maximum length of data to read in when looking for the Chaperone config file
max_size_of_file = 4096

# Tracked devices and the offsets to their data
hmd = ["HMD", 0x5C]

controller1 = ["Controller", 0x19C]
controller2 = ["Controller", 0x14C]

base_station1 = ["Base Station 1", 0xAC]
base_station2 = ["Base Station 2", 0xFC]

tracked_objects = [hmd , controller1, controller2, base_station1, base_station2]


def deref(address, a, length=4):
    """Derefernces the pointer in that memory location"""
    return struct.unpack("<I", a.read(address, length))[0]


def hex_to_float(hex):
    """Converts a hex string to float"""
    return struct.unpack('!f', str(hex).decode('hex'))[0]


def tracked_result_dict(enum):
    """Converts the enumerator code for EtrackingResult to string, see openVR.h for documentation"""
    return {
        1:   'TrackingResult_Uninitialized',
        100: 'TrackingResult_Calibrating_InProgress',
        101: 'TrackingResult_Calibrating_OutOfRange',
        200: 'TrackingResult_Running_OK',
        201: 'TrackingResult_Running_OutOfRange',
    }[enum]


def activity_dict(enum):
    """Converts the enumerator code for EtrackingResult to string, see openVR.h for documentation"""
    return {
        -1: 'k_EDeviceActivityLevel_Unknown',
        0:  'k_EDeviceActivityLevel_Idle',
        1:  'k_EDeviceActivityLevel_UserInteraction',
        2:  'k_EDeviceActivityLevel_UserInteraction_Timeout',
        3:  'k_EDeviceActivityLevel_Standby',
    }[enum]


def state_dict(enum):
    """Converts the enumerator code for EtrackingResult to string, see openVR.h for documentation"""
    return {
        -1: 'VRState_Undefined',
        0:  'VRState_Off',
        1:  'VRState_Searching',
        2:  'VRState_Searching_Alert',
        3:  'VRState_Ready',
        4:  'VRState_Ready_Alert',
        5:  'VRState_NotReady',
        6:  'VRState_Standby',
        7:  'VRState_Ready_Alert_Low'
    }[enum]


def parse_json(rdata):
    """ Takes in the block of data where the yarascan matched,
        Crops of the junk at the end and closes up the last bracket.
        The config file always ends in the version number so search for that and cut it off
        TODO Sloppy, should preserve version number
    """
    end_file = rdata.rfind('version')
    fixed_end = "{\n\"" + rdata[:end_file]
    # Close out the rest of the JSON
    end_file = fixed_end.rfind("]")
    fixed_end = fixed_end[:end_file + 1] + "}"

    # Load the memory as a JSON
    parsed_json = json.loads(fixed_end, strict=False)
    return parsed_json


def convert_to_matrix44(m):
    return [
        m[0][0], m[1][0], m[2][0], 0.0,
        m[0][1], m[1][1], m[2][1], 0.0,
        m[0][2], m[1][2], m[2][2], 0.0,
        m[0][3], m[1][3], m[2][3], 1.0
    ]


class ViveDump(taskmods.DllList):
    """Extracts SteamVR information"""
    universe_count = 0  # Append to dumpfile in case of multiple finds

    meta_info = dict(
        author='Peter Casey',
        contact='pgrom1@unh.newhaven.edu',
        url='https://github.com/strat1892/vive-dump',
        version='1.3',
    )

    visualizer = vis.Vis()

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.add_option("NUM-DEVICES", short_option='N', default=1,
                          help='Number of tracked devices to extract',
                          action='store', type=int)
        config.add_option("FULL-SCAN", short_option='F', default=True,
                          help='Scan the entire dump',
                          action='store_false')
        config.add_option("CHAP-FILE", short_option='C', default=False,
                          help='Provide Chaperone config file', type='str')
        config.add_option("NO-VIS", short_option='V', default=True, help='Turn of Visualization', action='store_false')
        config.remove_option("OFFSET")

    def build_obj(self, universe_number, parsed_json):
        """
            Accepts a parsed json and converts the verticies into an obj file
            Create a new object file for each file found.
            There may be multiple universes per file
            TODO Account for mulitple universes: Standing and Room scale
            If there is both a standing and seating universe they will both be dumped into the same file
        """

        filename = 'chaperone_visualization' + str(universe_number) + '.obj'
        with open(filename, 'w+') as data_file:
            wall_counter = 0
            for room in parsed_json['universes']:
                # Parse each wall
                for wall in room['collision_bounds']:

                    # We can assume there will be four corners to a wall
                    for i in range(0, 4):

                        # Prefix to specify a vertex
                        data_file.write('v ')

                        # Points are represented as x (left/right), y (verticle), z (front/back)
                        coords = []
                        for j in range(0, 3):
                            data_file.write(str(wall[i][j]) + ' ')
                            coords.append(wall[i][j])
                        data_file.write('\n')  # Add space to group walls
                        self.visualizer.add_vert(coords[0], coords[1], coords[2])
                    wall_counter += 1

            data_file.write('\n')  # Space to separate vertices from faces
            for face in range(0, wall_counter):
                # Prefix to represent the line specifies a face
                data_file.write('f ')

                self.visualizer.add_edge(4 * face, 4 * face + 1)
                self.visualizer.add_edge(4 * face + 1, 4 * face + 2)
                self.visualizer.add_edge(4 * face + 2, 4 * face + 3)
                self.visualizer.add_edge(4 * face + 3, 4 * face)

                # obj file format refers to the first vertex as 1
                # We can assume that all faces can be represented as quads
                for i in range(1, 5):
                    data_file.write(str(4 * face + i) + ' ')

                data_file.write('\n')

    def get_coords(self, pointer, process_space):
        """ Pulls information from the HMD structgit
            The x coordinate is offset 0x68 from the pointer
            each following point is offset 0x10
            Controller coordinates start at 0xB8
        """

        for i in range(self._config.NUM_DEVICES):
            print(tracked_objects[i][0])
            matrix = []
            for row_offset in [0, 0x10, 0x20]:
                row = []

                for col_offset in [0, 4, 8, 12]:
                    x_hex = deref(pointer + tracked_objects[i][1] + row_offset + col_offset, process_space)
                    row.append(hex_to_float('%x' % x_hex))
                print("{0}, {1}, {2}, {3}".format(row[0], row[1], row[2], row[3]))
                matrix.append(row)

            track_result = deref(pointer + tracked_objects[i][1] + 0x48, process_space)
            bool_vis_connected = deref(pointer + tracked_objects[i][1] + 0x4c, process_space)
            print("ETrackingResult: " + tracked_result_dict(track_result))
            print("Bool values: {0}".format(hex(bool_vis_connected)))

            # Isolate the byte containing each bool value
            pose_is_valid = bool_vis_connected & 0x00000f00
            device_is_connected = bool_vis_connected & 0x0000000f
            print('bPoseIsValid: {0}'.format(bool(pose_is_valid)))
            print('bDeviceIsConnected: {0}'.format(bool(device_is_connected)))
            print("\n")
            self.visualizer.set_device(convert_to_matrix44(matrix), tracked_objects[i][0])
        return matrix

    def pull_chaperone(self, matches, process_space, vad):
        for match in matches:
            self.universe_count += 1

            match_offset = vad.Start + match.strings[0][0]
            print("Found chaperone config file at {0}".format(hex(match_offset)))

            # Read the region matching the yara scan
            rdata = process_space.zread(match_offset, max_size_of_file)

            parsed_json = parse_json(rdata)
            self.build_obj(self.universe_count, parsed_json)

    def follow_pointers(self, offsets, pointer, process_space, name):
        for idx, offset in enumerate(offsets):
            deref_pointer_lower = deref(pointer + offset, process_space)
            deref_pointer_upper = deref(pointer + offset + 4, process_space)
            pointer = 4294967296 * deref_pointer_upper + deref_pointer_lower
            # print("{0} pointer {1}: {2}".format(name, idx, hex(pointer)))
        return pointer

    def calculate(self):
        """Required: Use Filescan to find Chaperone config file"""

        if not HAS_YARA:
            debug.error('Yara must be installed for this plugin')

        # Complile yara signatures
        rules_json = yara.compile(sources=YARA_JSON)
        rules_devices = yara.compile(sources=YARA_HMD)
        rules_activity = yara.compile(sources=YARA_HMD_ACTIVITY)

        # Load address space
        addr_space = utils.load_as(self._config)

        # Get list of processes
        tasks = win32.tasks.pslist(addr_space)

        # Read the Chaperone information from the provided file
        if self._config.CHAP_FILE:
            print("Loading Chaperone information from file")
            file1 = open(self._config.CHAP_FILE, "r+")
            json_from_file = json.load(file1)
            self.build_obj(1, json_from_file)

        for task in tasks:
            if self._config.FULL_SCAN and str(task.ImageFileName) != "vrmonitor.exe":
                continue
            else:
                print("Scanning {0} pid: {1}".format(task.ImageFileName, task.UniqueProcessId))
                vad_offset = 0
                for vad, process_space in task.get_vads():
                    vad_offset += vad.Length

                    if vad.Length > 8*1024*1024*1024:
                        continue
                    # read Vad content
                    data = process_space.zread(vad.Start, vad.Length)

                    if not self._config.CHAP_FILE:
                        # match yara rules for chaperone Json
                        matches = rules_json.match(data=data)
                        self.pull_chaperone(matches, process_space, vad)

                    # Check for tracked device signatures
                    matches = rules_devices.match(data=data)
                    for match in matches:
                        pointer = vad.Start + match.strings[0][0]
                        device_pointer = self.follow_pointers(DEVICE_OFFSETS, pointer, process_space, "HMD")
                        self.get_coords(device_pointer, process_space)

                    # Pull tracked device activity state data
                    matches = rules_activity.match(data=data)
                    for match in matches:
                        pointer = vad.Start + match.strings[0][0]
                        hmd_activity = self.follow_pointers(HMD_ACTIVITY_OFFSETS,pointer,process_space,"Activity")
                        print("HMD activity: {0}".format(activity_dict(hmd_activity & 0xFFFFFFFF)))
                        hmd_state = self.follow_pointers(HMD_STATE_OFFSETS, pointer, process_space, "State")
                        print("HMD state: {0}".format(state_dict(hmd_state & 0xFFFFFFFF)))


    def render_text(self, outfd, data):
        """
        This method formats output to the terminal.
        :param  outfd  | <file>
                data   | <generator>
        """

        if self._config.NO_VIS:
            self.visualizer.on_execute()
