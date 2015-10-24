# VM Live Migration Address Space

This repository contains an address space plugin for [Volatility](http://www.volatilityfoundation.org/).
The address space provides access to the memory contents transferred during a VM live migration.
To acquire a "memory image" the packets of a live migration must be captured.
Currently, only VMotion migrations between ESXi hosts are supported.
It is planned to support additional hypervisors in the future.

The address space plugin was successfully tested with Volatility 2.4 and ESXi 6.0 to analyze
Windows 7 x64, Windows XP x86 and Debian 8 x64 virtual machines during live migration.

### Motivation

This plugin was developed as a part of a master's thesis on the topic of
"Virtual Machine Introspection During Live Migration". The Volatility framework
was chosen, because it offers a wide variety of plugins for memory analysis.
Volatility also supports many different memory layouts and file formats with its
collection of address spaces. Support for live migration traffic is added
by developing an address space plugin.

During a VM live migration, the entire state of a VM must be transferred
between two physical host systems over the network. It has been established,
that access to this traffic equals full control over the VM.
In 2008, Oberheide, Cooke & Jahanian presented
[Xensploit](https://www.blackhat.com/presentations/bh-dc-08/Oberheide/Whitepaper/bh-dc-08-oberheide-WP.pdf).
Using this tool, they performed a man-in-the-middle attack on Xen and VMware migration traffic.
This resulted in execution of malicious code in the VM.

However, no public capabilities exist to work with VM live migration traffic.
The goal of this project is to change this situation: It implements a parser
for live migration data between ESXi hosts. Instead of just searching for
strings inside a packet capture, live migration traffic can now be
analyzed with powerful memory forensic tools such as Volatility.

This address space plugin has several real-world applications:
It can be used to perform VM introspection in a very non-intrusive way,
without installing any additional software on the VM or host systems.
The plugin may be used to analyze migration traffic gathered during
a penetration test or forensic investigation.
This code may also be integrated into a IDS/IPS system to scan VMs
for malware during migration.

### Prerequisites & Installation

Besides Volatiltiy itself, no additional libraries are required by the plugin.
To use `extract.py`, the `tcpflow` program must be installed on the system.

Either place the plugins into Volatility's `plugins/` directory, or use the `--plugins=` option to point
Volatility to the directory containing `vmotion.py`.

### Usage

The following steps explain how to capture live migration traffic, extract the relevant TCP stream,
and analyze this data with Volatility. A sample packet capture can be downloaded from
http://students.fim.uni-passau.de/~huppert/winxp_sp3_x86_256mb_vmotion_esxi6.pcap.gz

#### Prepare Packet Capture

Depending on the network architecture, migration traffic may be captured in various ways:

1. Use a manages switch with port monitoring/mirroring features to redirect traffic to a capture system.
2. Attach a promiscuous VM to the network and capture from inside it.
3. Run capture software directly on a host system.

To capture the traffic commonly available tools such as Wireshark or tcpdump may be used.
If migration traffic is sent over a dedicated network, traffic capture must also take place on this network.
Only the data sent from the source host system to the destination host system is relevant.
Packet loss during capture should be avoided.

#### Perform Live Migration

Once the packet capture is set up, one or multiple VMs can be migrated.
For an ESXi infrastructure, a migration can be initiated on the VSphere Web Client interface.


#### Extract Migration TCP Streams

The TCP stream containing the memory data must be extracted from the packet capture prior to analysis.
This can be done manually, for example with Wireshark's "conversations" feature.
The relevant TCP connection should be obvious: It is established between the two host systems
and usually contains more data than the VM's RAM.
Extract **only the data sent to the destination host** into a separate file.

The `extract.py` tool automates this process. It extracts all live migrations from a pcap file.

    % wget http://students.fim.uni-passau.de/~huppert/winxp_sp3_x86_256mb_vmotion_esxi6.pcap.gz
    % gunzip winxp_sp3_x86_256mb_vmotion_esxi6.pcap.gz
    % ./extract.py winxp_sp3_x86_256mb_vmotion_esxi6.pcap
    Processing 192.168.088.010.08000-192.168.088.011.12698
    Processing 192.168.088.010.40165-192.168.088.011.08000
    Found VMotion migration in 192.168.088.010.40165-192.168.088.011.08000
    Saving to /home/philip/192.168.088.010.40165-192.168.088.011.08000.vmig
    Processing 192.168.088.010.25811-192.168.088.011.08000
    Processing report.xml
    % mv 192.168.088.010.40165-192.168.088.011.08000.vmig winxp.vmig

#### Run Volatility

The migration data extracted from the packet capture can now be analyzed with Volatility.
Make sure the address space plugin is installed correctly.
Specify the path to the migration data with the `-f` flag.


    % volatility --plugins=vol-livemigration/ --profile=WinXPSP3x86 -f winxp.vmig pslist
    Volatility Foundation Volatility Framework 2.4
    INFO    : volatility.plugins.vmotion: 49118 pages (191M) extracted from migration; 49156 (192M) transferred; 38 (0M) retransmitted; 3 iterations
    Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
    ---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
    0x817cc830 System                    4      0     53      244 ------      0
    0x81290da0 smss.exe                564      4      3       19 ------      0 2015-07-14 22:37:31 UTC+0000
    [...]

### License

This project is licensed under the MIT license. Refer to the LICENSE file for more details.

### Disclaimer

This code was developed to achieve interoperability. All trademarks are property of their respective owner.

