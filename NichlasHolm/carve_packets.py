#
# Author: 
#           Nichlas
# Description: 
#            This plugin will carve and analyse IPv4 and ARP packets in memorydump, in addition to this it will analyze the carved packets:
#               - ARP resolves in packets.
#               - Guess for local interfaces for the analyzed system
#               - Show stats for IP's the host has been communicating with.
#            
# 
# Donated under Volatillity Foundation, Inc. Individual Contributor Licensing Agreement

import traceback
import sys
import binascii
import datetime
import re
import struct
import socket
import os
import json

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug


class Pkt_Carve_Analyze():
    """Carve and analyze packets
    """
    def __init__(self):
        pass


    def _verify_ipv4_header(self, ip_header_in_hex):
        """
        Internal helper function header checksum value and returns true if packet header is 
        correct or false if incorrect, takes IP-header in hex string as arg
        Creds to: http://stackoverflow.com/questions/3949726/calculate-ip-checksum-in-python
        """

        def carry_around_add(a, b):
            c = a + b
            return (c & 0xffff) + (c >> 16)

        def checksum(msg):
            s = 0
            for i in range(0, len(msg), 2):
                w = ord(msg[i]) + (ord(msg[i+1]) << 8)
                s = carry_around_add(s, w)
            return ~s & 0xffff
        
        try:
            ip_header_in_hex = [ip_header_in_hex[i:i+2] for i in range(0, len(ip_header_in_hex), 2)]
            ip_header_in_hex = map(lambda x: int(x,16), ip_header_in_hex)
            ip_header_in_hex = struct.pack("%dB" % len(ip_header_in_hex), *ip_header_in_hex)
            if checksum(ip_header_in_hex) == 0:
                return True
            else:
                return False

        except Exception, e:
            return False


    def _format_mac_address(self, hex_mac):
        """
        Internal helper function for human MAC formatting
        """
        return ':'.join(s.encode('hex') for s in hex_mac.decode('hex'))


    def _add_pcap_packet_header(self, raw_packet):
        """
        Internal helper function for adding correct packet header for pcaps packets
        """
        time_t_ts_sec = '00000000'
        uint32_ts_usec = '00000000'
        uint32_incl_len = binascii.hexlify(struct.pack("I", len(raw_packet)))
        uint32_orig_len = binascii.hexlify(struct.pack("I", len(raw_packet)))
        raw_packet_with_header = binascii.unhexlify(time_t_ts_sec + uint32_ts_usec + uint32_incl_len + uint32_orig_len + binascii.hexlify(raw_packet))
        
        return raw_packet_with_header
       

    def _is_ip(self, ip):
        """
        Internal helper function for figuring out if string is a IPv4
        """
        ipv4 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return ipv4.match(ip)
        



    def _ips_not_to_test(self, ip):
        """
        Internal helper function Returns for figuring out if ip should be investigated
        """
        #10.0.0.0 - 10.255.255.255
        if ip[:3] == '10.':
            return True

        #172.16.0.0 - 172.31.255.255
        if ip[:4] == '172.':
            if ip[6:7] == '.':
                if int(ip[4:6]) in range(16,31,1):
                    return True

        #192.168.0.0 - 192.168.255.255
        if ip[:8] == '192.168.':
            return True


        #255.255.255.255
        if ip == '255.255.255.255':
            return True

        #Multicast 224.0.0.0 - 239.255.255.255
        for m_cast in range(224,240,1):
            if ip[:3] == str(m_cast):
                return True

        #0.0.0.0
        if ip == '0.0.0.0':
            return True

        return False



    def _carve_ipv4(self, hex_data, match_start, match_end):
        """
        Internal function for carving and validating IPv4 packets
        """

        packet_dict = dict()

        #Ethernet layer
        packet_dict['ethernet_header'] = hex_data[match_start-24:match_end]
        packet_dict['ethernet_dst_mac'] = hex_data[match_start-24:match_start-12]
        packet_dict['ethernet_dst_mac_str'] = self._format_mac_address(packet_dict['ethernet_dst_mac'])
        packet_dict['ethernet_src_mac'] = hex_data[match_start-12:match_start]
        packet_dict['ethernet_src_mac_str'] = self._format_mac_address(packet_dict['ethernet_src_mac'])
        packet_dict['ethernet_type'] = hex_data[match_start:match_start+4]
        

        #IP layer
        ip_header_begin = match_end
        
        packet_dict['ip_version'] = hex_data[match_end:ip_header_begin+1]
        

        #Validate potential packet is a IPv4 packet
        if packet_dict['ip_version'] == '4':
            
            #Calculate offsets for IPv4 header lenght
            packet_dict['ip_header_len_int'] = int(hex_data[ip_header_begin+1:ip_header_begin+2], 16)*4*2
            
            packet_dict['ip_header'] = hex_data[ip_header_begin:ip_header_begin+packet_dict['ip_header_len_int']]
            

            #Check that IPv4 header is above minimum lenght: 20bytes
            if len(packet_dict['ip_header']) >= 40:

                #Verify header checksum value is correct
                if self._verify_ipv4_header(packet_dict['ip_header']) is True:

                    packet_dict['ip_service_field'] = hex_data[ip_header_begin+2:ip_header_begin+4]

                    packet_dict['ip_total_lenght'] = int(hex_data[ip_header_begin+4:ip_header_begin+8], 16)    
                    
                    packet_dict['ip_layer'] = hex_data[match_end:ip_header_begin+packet_dict['ip_total_lenght']*2]

                    packet_dict['ip_identification'] = hex_data[ip_header_begin+8:ip_header_begin+12]
                    
                    packet_dict['ip_flags'] = hex_data[ip_header_begin+12:ip_header_begin+16]

                    packet_dict['ip_ttl'] = hex_data[ip_header_begin+16:ip_header_begin+18]

                    packet_dict['ip_protocol'] = hex_data[ip_header_begin+18:ip_header_begin+20]

                    packet_dict['ip_header_checksum'] = hex_data[ip_header_begin+20:ip_header_begin+24]

                    packet_dict['ip_src'] = hex_data[ip_header_begin+24:ip_header_begin+32]
                        
                    packet_dict['ip_src_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['ip_src'], 16)))
                    
                    packet_dict['ip_dst'] = hex_data[ip_header_begin+32:ip_header_begin+40]
                    
                    packet_dict['ip_dst_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['ip_dst'], 16)))

                    full_packet_data = packet_dict['ethernet_header']+packet_dict['ip_layer']
                    
                    self.hex_packets.append(full_packet_data)
                    
                    #Parse TCP layer for src and dst ports
                    if packet_dict['ip_protocol'] == '06':
                        
                        tcp_begin = ip_header_begin + packet_dict['ip_header_len_int']
                        
                        packet_dict['src_port'] = hex_data[tcp_begin:tcp_begin+4]
                        
                        packet_dict['src_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['src_port']))[0])
                        
                        packet_dict['dst_port'] = hex_data[tcp_begin+4:tcp_begin+8]
                        
                        packet_dict['dst_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['dst_port']))[0])
                        
                        self.parsed_packets.append(packet_dict)    


                    #Parse UDP layer for src and dst ports
                    elif packet_dict['ip_protocol'] == '11':

                        udp_begin = ip_header_begin + packet_dict['ip_header_len_int']
                        
                        packet_dict['src_port'] = hex_data[udp_begin:udp_begin+4]
                        
                        packet_dict['src_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['src_port']))[0])

                        packet_dict['dst_port'] = hex_data[udp_begin+4:udp_begin+8]
                        
                        packet_dict['dst_port_str'] = str(struct.unpack('!H', binascii.unhexlify(packet_dict['dst_port']))[0])

                        packet_dict['udp_len'] = hex_data[udp_begin+8:udp_begin+12]
                        
                        packet_dict['udp_len_int'] = int(packet_dict['udp_len'], 16)*2

                        packet_dict['udp_checksum'] = hex_data[udp_begin+12:udp_begin+16]

                        self.parsed_packets.append(packet_dict)    
                    
                    else:
                        self.parsed_packets.append(packet_dict)          
                                



    def _carve_arp(self, hex_data, match_start, match_end):
        """
        Internal function for carving and validating ARP packets
        """
        packet_dict = dict()

        #Ethernet layer
        packet_dict['ethernet_header'] = hex_data[match_start-24:match_end]
        packet_dict['ethernet_dst_mac'] = hex_data[match_start-24:match_start-12]
        packet_dict['ethernet_dst_mac_str'] = self._format_mac_address(packet_dict['ethernet_dst_mac'])
        packet_dict['ethernet_src_mac'] = hex_data[match_start-12:match_start]
        packet_dict['ethernet_src_mac_str'] = self._format_mac_address(packet_dict['ethernet_src_mac'])
        packet_dict['ethernet_type'] = hex_data[match_start:match_start+4]

        #ARP layer
        arp_header_begin = match_end
        packet_dict['arp_layer'] = hex_data[match_end:match_end+52]
        packet_dict['arp_hardware_type'] = hex_data[match_end:match_end+4]
        valid_arp_hardware_types = ['0001']
        
        if any(i in packet_dict['arp_hardware_type'] for i in valid_arp_hardware_types):
            
            packet_dict['arp_protocol'] = hex_data[arp_header_begin+4:arp_header_begin+8]

            #Valid ARP protocols
            valid_arp_protocols = ['0800']

            if any(i in packet_dict['arp_protocol'] for i in valid_arp_protocols):
                packet_dict['arp_hardware_length'] = hex_data[arp_header_begin+8:arp_header_begin+10]

                #Valid hardware ARP-addresses
                valid_arp_hardware_lengths = ['06']
                
                if any(i in packet_dict['arp_hardware_length'] for i in valid_arp_hardware_lengths):               
                    
                    packet_dict['arp_protocol_len'] = hex_data[arp_header_begin+10:arp_header_begin+12]

                    valid_arp_protocol_lens = ['04']

                    if any(i in packet_dict['arp_protocol_len'] for i in valid_arp_protocol_lens):
                        packet_dict['arp_operation'] = hex_data[arp_header_begin+12:arp_header_begin+16]
                        
                        #0001 = request
                        #0002 = reply
                        valid_arp_operations = ['0001','0002']
                        
                        if any(i in packet_dict['arp_operation'] for i in valid_arp_operations):
                            packet_dict['arp_sender_hardware_address'] = hex_data[arp_header_begin+16:arp_header_begin+28]
                            packet_dict['arp_sender_hardware_address_str'] = self._format_mac_address(packet_dict['arp_sender_hardware_address'])
                            packet_dict['arp_sender_ip_address'] =  hex_data[arp_header_begin+28:arp_header_begin+36]
                            packet_dict['arp_sender_ip_address_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['arp_sender_ip_address'], 16)))
                            packet_dict['arp_target_hardware_address'] = hex_data[arp_header_begin+36:arp_header_begin+48]
                            packet_dict['arp_target_hardware_address_str'] = self._format_mac_address(packet_dict['arp_target_hardware_address'])
                            packet_dict['arp_target_ip_address'] = hex_data[arp_header_begin+48:arp_header_begin+56]
                            packet_dict['arp_target_ip_address_str'] = socket.inet_ntoa(struct.pack('!I', int(packet_dict['arp_target_ip_address'], 16)))

                            full_packet_data = packet_dict['ethernet_header'] + packet_dict['arp_layer']
                            full_packet_data_len = len(full_packet_data)


                            #Check if packet needs padding
                            if full_packet_data_len < 128:
                                padding = (128 - full_packet_data_len)*'0'
                                full_packet_data = packet_dict['ethernet_header'] + packet_dict['arp_layer'] + padding

                            self.hex_packets.append(full_packet_data)
                            self.parsed_packets.append(packet_dict)



    def carve_packets(self, data):
        """
        Tries to carve all supported packets found in data
        """
        hex_data = binascii.hexlify(data).upper()
        hex_data_len = len(hex_data)
        
        #Supported ethertypes:
        #0x0800 Internet Protocol version 4 (IPv4)
        #0x0806 Address Resolution Protocol (ARP) requests and responses
        ether_types = ['0800', '0806']

        raw_packets = []

        #Check for valid ethertypes being present in mempage
        if any(eth_type in hex_data for eth_type in ether_types):
            for eth_type in ether_types:
                for match in re.finditer(eth_type, hex_data):

                    #Check that there is room for a potential packet before and after eth_type
                    if 24 < match.start():
                        
                        #Try to carve IPv4 packet
                        if eth_type == '0800':
                            raw_packets.append(self._carve_ipv4(hex_data, match.start(), match.end()))

                        #Try to carve ARP packet
                        if eth_type == '0806':
                            self._carve_arp(hex_data, match.start(), match.end())



    def dump_packets_to_pcap(self, hex_packets, pcap_file):
        """
        Generate valid pcap file from hex packets list
        """
        pcap_file_header = binascii.unhexlify('D4C3B2A1020004000000000000000000FFFF000001000000')
        
        with open(pcap_file, 'wb') as fd:
            fd.write(pcap_file_header)

            #Write packets with added epoch 0 timestamp
            for hex_packet in hex_packets:
                raw_packet_with_header = self._add_pcap_packet_header(binascii.unhexlify(hex_packet))
                fd.write(raw_packet_with_header)




    def analyze_packets(self, parsed_packets):
        """
        Analyze packets for quick network triage
        """

        analysis_results = dict()
        analysis_results['arp_resolves'] = dict()
        analysis_results['mac_to_ips'] = dict()
        analysis_results['ip_to_mac'] = dict()        
        analysis_results['public_ips_ports'] = dict()
        analysis_results['unique_public_ips'] = set()
        analysis_results['potential_local_interface_ips'] = set()
        analysis_results['potential_local_gateways'] = set()
        analysis_results['potential_local_dns_servers'] = set()
        analysis_results['public_ip_byte_count'] = dict()
        analysis_results['public_packet_size_stats'] = dict()
        analysis_results['public_ips_src_and_dst_count'] = dict()


        for packet in parsed_packets:
            
            #Analyze ARP responses
            if 'arp_operation' in packet:
                if packet['arp_operation'] == '0002':
                    #Build resolves and count number of packets
                    resolve = packet['arp_sender_ip_address_str'] + ' is at ' +  packet['arp_sender_hardware_address_str']
                    if resolve not in analysis_results['arp_resolves']:
                       analysis_results['arp_resolves'][resolve] = 1
                    else:
                        analysis_results['arp_resolves'][resolve] += 1
                    
                    #Build lookup dict for mac to ips
                    if packet['arp_sender_hardware_address_str'] not in analysis_results['mac_to_ips']:
                        analysis_results['mac_to_ips'][packet['arp_sender_hardware_address_str']] = set()
                        analysis_results['mac_to_ips'][packet['arp_sender_hardware_address_str']].add(packet['arp_sender_ip_address_str'])
                    else:
                        analysis_results['mac_to_ips'][packet['arp_sender_hardware_address_str']].add(packet['arp_sender_ip_address_str'])

                    #Build lookup dict for ip to mac
                    if packet['arp_sender_ip_address_str'] not in analysis_results['ip_to_mac']:
                        analysis_results['ip_to_mac'][packet['arp_sender_ip_address_str']] = packet['arp_sender_hardware_address_str']

            
            #Analyze IP packets
            if 'ip_version' in packet:
                if self._ips_not_to_test(packet['ip_src_str']) is False:
                    #Add potential gw and local interfaces
                    analysis_results['potential_local_gateways'].add(packet['ethernet_src_mac_str'])
                    analysis_results['potential_local_interface_ips'].add(packet['ip_dst_str'])

                    #Count src packet sizes for stats
                    if packet['ip_src_str'] not in analysis_results['public_packet_size_stats']:
                        analysis_results['public_packet_size_stats'][packet['ip_src_str']] = []
                        analysis_results['public_packet_size_stats'][packet['ip_src_str']].append(packet['ip_total_lenght'])
                    else:
                        analysis_results['public_packet_size_stats'][packet['ip_src_str']].append(packet['ip_total_lenght'])

                    #Count bytes for ip_src for public ip
                    if packet['ip_src_str'] not in analysis_results['public_ip_byte_count']:
                        analysis_results['public_ip_byte_count'][packet['ip_src_str']] = packet['ip_total_lenght']
                    else:
                        analysis_results['public_ip_byte_count'][packet['ip_src_str']] += packet['ip_total_lenght']


                    #Count unique source ports for IP source
                    if packet['ip_src_str'] not in analysis_results['public_ips_ports']: 
                        analysis_results['public_ips_ports'][packet['ip_src_str']] = dict()

                        #Source port
                        analysis_results['public_ips_ports'][packet['ip_src_str']]['src_ports'] = set()
                        if 'src_port_str' in packet:
                            if int(packet['src_port_str']) < 1023:
                                analysis_results['public_ips_ports'][packet['ip_src_str']]['src_ports'].add(packet['src_port_str'])
                        
                        #Destination ports
                        analysis_results['public_ips_ports'][packet['ip_src_str']]['dst_ports'] = set()
                        if 'dst_port_str' in packet:
                            if int(packet['dst_port_str']) < 1023:
                                analysis_results['public_ips_ports'][packet['ip_src_str']]['dst_ports'].add(packet['dst_port_str'])
                    
                    else:
                        if int(packet['src_port_str']) < 1023:
                            if 'src_port_str' in packet:
                                analysis_results['public_ips_ports'][packet['ip_src_str']]['src_ports'].add(packet['src_port_str'])
                        if int(packet['dst_port_str']) < 1023:
                            if 'dst_port_str' in packet:
                                analysis_results['public_ips_ports'][packet['ip_src_str']]['dst_ports'].add(packet['dst_port_str'])

                    #Count occurence of ip src
                    if packet['ip_src_str'] not in analysis_results['public_ips_src_and_dst_count']:
                        analysis_results['public_ips_src_and_dst_count'][packet['ip_src_str']] = 1
                        analysis_results['unique_public_ips'].add(packet['ip_src_str'])
                    else:
                        analysis_results['public_ips_src_and_dst_count'][packet['ip_src_str']] += 1 
                        analysis_results['unique_public_ips'].add(packet['ip_src_str'])

                #Destination IP
                if self._ips_not_to_test(packet['ip_dst_str']) is False:
                    #Count dst packet sizes for stats
                    if packet['ip_dst_str'] not in analysis_results['public_packet_size_stats']:
                        analysis_results['public_packet_size_stats'][packet['ip_dst_str']] = []
                        analysis_results['public_packet_size_stats'][packet['ip_dst_str']].append(packet['ip_total_lenght'])
                    else:
                        analysis_results['public_packet_size_stats'][packet['ip_dst_str']].append(packet['ip_total_lenght'])


                    #Count bytes for ip_dst for public ip
                    if packet['ip_dst_str'] not in analysis_results['public_ip_byte_count']:
                        analysis_results['public_ip_byte_count'][packet['ip_dst_str']] = packet['ip_total_lenght']
                    else:
                        analysis_results['public_ip_byte_count'][packet['ip_dst_str']] += packet['ip_total_lenght']


                    #Count unique destination ports for IP
                    if packet['ip_dst_str'] not in analysis_results['public_ips_ports']: 
                        analysis_results['public_ips_ports'][packet['ip_dst_str']] = dict()
                        analysis_results['public_ips_ports'][packet['ip_dst_str']]['src_ports'] = set()

                        if int(packet['src_port_str']) < 1023:
                            analysis_results['public_ips_ports'][packet['ip_dst_str']]['src_ports'].add(packet['src_port_str'])
                        
                        analysis_results['public_ips_ports'][packet['ip_dst_str']]['dst_ports'] = set()
                        if int(packet['dst_port_str']) < 1023:
                            analysis_results['public_ips_ports'][packet['ip_dst_str']]['dst_ports'].add(packet['dst_port_str'])

                    else:
                        if int(packet['src_port_str']) < 1023:
                            analysis_results['public_ips_ports'][packet['ip_dst_str']]['src_ports'].add(packet['src_port_str'])
                        if int(packet['dst_port_str']) < 1023:
                            analysis_results['public_ips_ports'][packet['ip_dst_str']]['dst_ports'].add(packet['dst_port_str'])

                    if packet['ip_dst_str'] not in analysis_results['public_ips_src_and_dst_count']:
                        analysis_results['public_ips_src_and_dst_count'][packet['ip_dst_str']] = 1
                        analysis_results['unique_public_ips'].add(packet['ip_dst_str'])
                    else:
                        analysis_results['public_ips_src_and_dst_count'][packet['ip_dst_str']] += 1
                        analysis_results['unique_public_ips'].add(packet['ip_dst_str'])

        #Sort Public IPS by packet count desc
        analysis_results['public_ips_src_and_dst'] = sorted(analysis_results['public_ips_src_and_dst_count'].items(), key=lambda x: x[1], reverse=True)

        #Sort ARP-replies by packet count desc
        analysis_results['arp_resolves'] = sorted(analysis_results['arp_resolves'].items(), key=lambda x: x[1], reverse=True)


        return analysis_results



class NetworkPackets(common.AbstractWindowsCommand, Pkt_Carve_Analyze):
    """Carve and analyze ARP/IPv4 network packets from memory 
    """

    def __init__(self, config, *args, **kwargs):        
        config.add_option('DUMP-DIR', short_option = 'D', default = None, cache_invalidator = False, help = 'Directory in which to dump packets')       
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self.hex_packets = []
        self.parsed_packets = []


    def calculate(self):
        """Begin carving and analysing"""

        #Check output dir is provided
        if self._config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(self._config.DUMP_DIR):
            debug.error(self._config.DUMP_DIR + " is not a directory")

        
        #Carve packets from all mempages
        self.addr_space = utils.load_as(self._config)
        for mempage in self.addr_space.get_available_addresses():
            self.carve_packets(self.addr_space.zread(mempage[0], mempage[1]))

        
        #Analyze the carved/parsed packets
        packet_stats = self.analyze_packets(self.parsed_packets)
        
        #Dump files to dump-dir
        self.dump_packets_to_pcap(self.hex_packets, os.path.abspath(os.path.join(self._config.DUMP_DIR, 'packets.pcap')))
        with open(os.path.abspath(os.path.join(self._config.DUMP_DIR, 'ips.txt')), 'w') as fd:
            for ip_to_check in packet_stats['unique_public_ips']:
                fd.write(ip_to_check + '\n')
        
        
        return packet_stats



    def render_text(self, outfd, data):
        #Write overall stats
        outfd.write('\nNetwork analysis of carved packets:\n\n')

        self.table_header(outfd,
                          [('Number of carved packets', '<24')
                           ])
        self.table_row(outfd, str(len(self.hex_packets))) 
        outfd.write('\n\n')


        #Write potential ips for analyzed system
        self.table_header(outfd,
            [('Potential local interfaces used by analyzed system', '<38')
            ])
        for ip in data['potential_local_interface_ips']:
            #Check if arp resolved has been seen
            if ip in data['ip_to_mac']:
                interface_entry = ip + ' <-> ' + data['ip_to_mac'][ip]
                self.table_row(outfd, interface_entry)
            else:
                interface_entry = ip + ' with mac ' + 'No ARP resolves seen'
                self.table_row(outfd, interface_entry)
        outfd.write('\n\n')


        #Write potential gateways for analyzed system
        self.table_header(outfd,
            [('Potential gateways used by analyzed system', '<38')
            ])
        for gateway in data['potential_local_gateways']:
            if gateway in data['mac_to_ips']:
                for ip in data['mac_to_ips'][gateway]:
                    gateway_entry = ip + ' <-> ' + gateway
                    self.table_row(outfd, gateway_entry)
            else:
                gateway_entry = 'No ARP resolves' + ' <-> ' + gateway
                self.table_row(outfd, gateway_entry)

        outfd.write('\n\n')

        #Write ARP-resolves seen
        self.table_header(outfd,
                          [('ARP resolves', '<38'),
                           ('Number of packets', '>6')
                           ])
        for resolve in data['arp_resolves']:
            self.table_row(outfd, resolve[0], resolve[1])
        outfd.write('\n\n')

        #Write public ip table
        self.table_header(outfd,
                          [('Public IP src or dst', '<19'),
                           ('Number of packets', '>6'),
                           ('Source ports < 1024', '>12'),
                           ('Destination ports < 1024', '>12'),
                           ('Total bytes', '>12'),
                           ('Minimum packet size', '>12'),
                           ('Maximum packet size', '>12'),
                           ('Average packet size', '>12')
                           ])
        
        #public packets size stats
        for pub_ip in data['public_ips_src_and_dst']:                
            self.table_row(outfd, 
                pub_ip[0], 
                pub_ip[1], 
                ','.join(data['public_ips_ports'][pub_ip[0]]['src_ports']), 
                ','.join(data['public_ips_ports'][pub_ip[0]]['dst_ports']),
                data['public_ip_byte_count'][pub_ip[0]],
                min(data['public_packet_size_stats'][pub_ip[0]]), 
                max(data['public_packet_size_stats'][pub_ip[0]]), 
                reduce(lambda x, y: x + y, data['public_packet_size_stats'][pub_ip[0]]) / len(data['public_packet_size_stats'][pub_ip[0]]))
     

