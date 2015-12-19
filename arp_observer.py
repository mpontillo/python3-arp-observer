#!/usr/bin/env python3

import codecs
import netaddr
import os
import stat
import struct
import sys

mode = os.fstat(0).st_mode
if not stat.S_ISFIFO(mode):
    print("Usage:")
    print("    sudo tcpdump 'arp' -i any -s 64 -n -e -l -x "
          "2> /dev/null | %s" % (sys.argv[0]))
    sys.exit(1)

verbose = False
debug = False

if '-v' in sys.argv or '--verbose' in sys.argv:
    verbose = True

if '-d' in sys.argv or '--debug' in sys.argv:
    debug = True

length = None
length_remain = 0
pkt_bytes = b''
time = ''
src_mac = ''
dst_mac = ''

while True:
    line = sys.stdin.readline().strip()
    if not line:
        exit(1)
    if verbose:
        print(line)
    if not line.startswith('0x'):
        packet = line.split(': ')
        if len(packet) != 2:
            continue
        header, data = packet
        # Header will be a string like this (no line break after the comma):
        # 16:01:48.888123 00:24:a5:af:24:85 > 00:0c:29:14:03:f0,
        #     ethertype ARP (0x0806), length 60
        header = header.replace(',', '')
        header = header.split()
        if debug:
            print(header)
        time = header[0]
        # Check if the first thing after the time looks like a MAC.
        if ':' in header[1]:
            # This is without "-i any", a specific Ethernet interface is being
            # used, and we have the information from the link layer header.
            src_mac = header[1]
            dst_mac = header[3]
        else:
            # Header is like:
            # 18:07:50.087391  In 00:24:a5:af:24:85 ethertype ARP (0x0806) ...
            if header[1] == 'B':
                # Seems to be a broadcast.
                dst_mac = "ff:ff:ff:ff:ff:ff"
                src_mac = header[2]
            else:
                # Could be "In"; not sure what else.
                dst_mac = "<unknown>"
                src_mac = header[2]

        # Data will be a string like:
        # Reply 172.16.42.1 is-at 00:24:a5:af:24:85, length 46
        #     or
        # Request who-has 172.16.42.1 tell 172.16.42.116, length 28
        data = data.replace(',', '')
        data = data.split()
        # We only care about the packet length, because we'll be parsing the
        # hex dump that follows the packet.
        try:
            length = int(data[-1])
            length_remain = length
            if verbose:
                print("    Expecting packet of length: %d" % length)
        except ValueError:
            length = None
        pkt_bytes = b''
    elif length is not None and length >= 28 and line.startswith('0x'):
        # This will be a line like:
        # 0x0020:  0000 0000 0000 0000 0000 0000 0000
        data = line.split(':')
        if len(data) == 2:
            new_bytes = bytes.fromhex(data[1].replace(' ', ''))
            length_remain -= len(new_bytes)
            pkt_bytes += new_bytes
            if length_remain == 0:
                # Truncate the packet at 28 bytes
                arp_pkt = struct.unpack('!hhBBh6sL6sL', pkt_bytes[0:28])
                # XXX need to validate hardware/protocol types and lengths
                print("ARP received at %s:" % time)
                print("        Ethernet source: %s" % src_mac)
                print("   Ethernet destination: %s" % dst_mac)
                print("          Hardware type: 0x%04x" % arp_pkt[0])
                print("          Protocol type: 0x%04x" % arp_pkt[1])
                print("Hardware address length: %d" % arp_pkt[2])
                print("Protocol address length: %d" % arp_pkt[3])
                operation = arp_pkt[4]
                if operation == 1:
                    operation_str = ' (request)'
                elif operation == 2:
                    operation_str = ' (reply)'
                else:
                    operation_str = ''
                print("              Operation: %d%s" %
                      (arp_pkt[4], operation_str))
                sender_mac = netaddr.EUI(
                    int(codecs.encode(arp_pkt[5], 'hex'), 16))
                print("Sender hardware address: %s" % str(
                    sender_mac).replace('-', ':').lower())
                sender_ip = netaddr.IPAddress(arp_pkt[6])
                print("Sender protocol address: %s" % sender_ip)
                target_mac = netaddr.EUI(
                    int(codecs.encode(arp_pkt[7], 'hex'), 16))
                print("Target hardware address: %s" % str(
                    target_mac).replace('-', ':').lower())
                sender_ip = netaddr.IPAddress(arp_pkt[8])
                print("Target protocol address: %s" % sender_ip)
                print("")
            if length_remain < 0:
                length = None
