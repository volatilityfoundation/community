#!/usr/bin/env python2.7
# coding=utf-8

"""Tool to extract VMotion live migration traffic from a packet capture."""

import subprocess as sp
import tempfile
import sys
import os
import shutil

__author__ = "Philip Huppert"
__copyright__ = "Copyright 2015, Philip Huppert"
__license__ = "MIT"

TCPFLOW_PATH = "/usr/bin/tcpflow"
VMOTION_MAGIC_A = "\0\0\0\0\x03\0\x05\0"
VMOTION_MAGIC_A_OFFSET = 0
VMOTION_MAGIC_B = "\x04\x0e\0\0"
VMOTION_MAGIC_B_OFFSET = 0x55


def tcpflow(*args):
    p = sp.Popen([TCPFLOW_PATH] + list(args), stdout=sp.PIPE, stderr=sp.PIPE)
    p.communicate()
    return p.returncode


def copy_file(filename, ext, path):
    output = os.path.join(os.getcwd(), filename + ext)
    if not os.path.exists(output):
        print "Saving to %s" % output
        shutil.copy(path, output)
    else:
        print "Not overwriting %s" % output


def check_magic(data, offset, magic):
    return data[offset:].startswith(magic)


def main():
    # check for valid usage
    if len(sys.argv) != 2:
        sys.stderr.write("usage: %s pcap-file\n" % sys.argv[0])
        sys.exit(1)

    # verify that tcpflow is available
    if not os.path.isfile(TCPFLOW_PATH):
        sys.stderr.write("tcpflow not installed\n")
        sys.exit(1)

    # verify that input pcap is present
    pcap = sys.argv[1]
    if not os.path.isfile(pcap):
        sys.stderr.write("File not found: %s\n" % pcap)
        sys.exit(1)

    # create a temporary directory to hold data
    temp_dir = tempfile.mkdtemp(prefix="xtr")

    # extract all TCP streams from pcap
    if tcpflow("-r", pcap, "-o", temp_dir) != 0:
        sys.stderr.write("tcpflow error\n")
        sys.exit(1)

    # check each TCP stream for migration traffic
    for filename in os.listdir(temp_dir):
        print "Processing %s" % filename
        path = os.path.join(temp_dir, filename)
        with open(path, "r") as fp:
            header = fp.read(128)

        # check for VMotion magic bytes
        if check_magic(header, VMOTION_MAGIC_A_OFFSET, VMOTION_MAGIC_A) \
                and check_magic(header, VMOTION_MAGIC_B_OFFSET, VMOTION_MAGIC_B):
            print "Found VMotion migration in %s" % filename
            # copy file with VMotion TCP stream to working directory
            copy_file(filename, ".vmig", path)

    # remove temporary directory and contents
    shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
