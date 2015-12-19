#!/usr/bin/env python3

import codecs
import netaddr
import os
import stat
import struct
import sys


class ARP:
    """Representation of an ARP packet."""

    def __init__(self, pkt_bytes, time=None, src_mac=None, dst_mac=None):
        """
        :param pkt_bytes: The input bytes of the ARP packet.
        :type pkt_bytes: bytes
        :param time: Timestamp packet was seen (format is undefined)
        :type time: str
        :param src_mac: Source MAC address.
        :type src_mac: str
        :param dst_mac: Desination MAC address.
        :type dst_mac: str
        :return:
        """
        # Truncate the packet at 28 bytes.
        arp_pkt = struct.unpack('!hhBBh6sL6sL', pkt_bytes[0:28])
        self.time = time
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.hardware_type = arp_pkt[0]
        self.protocol_type = arp_pkt[1]
        self.hardware_length = arp_pkt[2]
        self.protocol_length = arp_pkt[3]
        self.operation = arp_pkt[4]
        self.sender_hardware_bytes = arp_pkt[5]
        self.sender_protocol_bytes = arp_pkt[6]
        self.target_hardware_bytes = arp_pkt[7]
        self.target_protocol_bytes = arp_pkt[8]

    @property
    def source_eui(self):
        return netaddr.EUI(
            int(codecs.encode(self.sender_hardware_bytes, 'hex'), 16))

    @property
    def target_eui(self):
        return netaddr.EUI(
            int(codecs.encode(self.target_hardware_bytes, 'hex'), 16))

    @property
    def source_ip(self):
        return netaddr.IPAddress(self.sender_protocol_bytes)

    @property
    def target_ip(self):
        return netaddr.IPAddress(self.target_protocol_bytes)

    def bindings(self):
        if self.operation == 1:
            # This is an ARP request.
            # We can find a binding in the (source_eui, source_ip)
            yield (self.source_eui, self.source_ip)
        elif self.operation == 2:
            # This is an ARP reply.
            # We can find a binding in both the (source_eui, source_ip) and
            # the (target_eui, target_ip).
            yield (self.source_eui, self.source_ip)
            yield (self.target_eui, self.target_ip)

    def print(self):
        if self.time is not None:
            print("ARP observed at %s:" % self.time)
        if self.src_mac is not None:
            print("        Ethernet source: %s" % self.src_mac)
        if self.dst_mac is not None:
            print("   Ethernet destination: %s" % self.dst_mac)

        print("          Hardware type: 0x%04x" % self.hardware_type)
        print("          Protocol type: 0x%04x" % self.protocol_type)
        print("Hardware address length: %d" % self.hardware_length)
        print("Protocol address length: %d" % self.protocol_length)
        if self.operation == 1:
            operation_str = ' (request)'
        elif self.operation == 2:
            operation_str = ' (reply)'
        else:
            operation_str = ''
        print("              Operation: %d%s" %
              (self.operation, operation_str))
        sender_mac = netaddr.EUI(
            int(codecs.encode(self.sender_hardware_bytes, 'hex'), 16))
        print("Sender hardware address: %s" % str(
            sender_mac).replace('-', ':').lower())
        sender_ip = netaddr.IPAddress(self.sender_protocol_bytes)
        print("Sender protocol address: %s" % sender_ip)
        target_mac = netaddr.EUI(
            int(codecs.encode(self.target_hardware_bytes, 'hex'), 16))
        print("Target hardware address: %s" % str(
            target_mac).replace('-', ':').lower())
        sender_ip = netaddr.IPAddress(self.target_protocol_bytes)
        print("Target protocol address: %s" % sender_ip)
        print("")


def main(argv):
    mode = os.fstat(0).st_mode
    if not stat.S_ISFIFO(mode):
        print("Usage:")
        print("    sudo tcpdump 'arp' -i any -s 64 -n -e -l -x "
              "2> /dev/null | %s [args]" % (argv[0]))
        print("")
        print("Arguments:")
        print("    -v --verbose  Print each line of input (from tcpdump).")
        print("    -d --debug    Print additional debugging information.")
        print("    -t --text     Print each ARP packet in text format..")
        return 1
    verbose = False
    debug = False
    show_text = False
    bindings = False
    if '-v' in argv or '--verbose' in argv:
        verbose = True
    if '-d' in argv or '--debug' in argv:
        debug = True
    if '-p' in argv or '--print' in argv:
        show_text = True
    if '-b' in argv or '--print-bindings' in argv:
        bindings = True
    observe_arp_packets(
        debug=debug, verbose=verbose, show_text=show_text, bindings=bindings)
    return 0


def observe_arp_packets(
        debug=False, verbose=False, show_text=False, bindings=False):
    length = None
    length_remain = 0
    pkt_bytes = b''
    time = None
    src_mac = None
    dst_mac = None
    if bindings:
        bindings = dict()
    else:
        bindings = None

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
            header = header.replace(',', '')
            header = header.split()
            if debug:
                print(header)
            time = header[0]
            # Check if the first thing after the time looks like a MAC.
            if ':' in header[1] and header[2] == '>' and ':' in header[3]:
                # Header is like:
                # 16:01:48.888123 00:24:a5:af:24:85 > 00:0c:29:14:03:f0 ...
                # This is without "-i any", a specific Ethernet interface is
                # being used, and we have the information from the link layer
                # header.
                src_mac = header[1]
                dst_mac = header[3]
            elif ':' in header[2]:
                # Header is like:
                # 18:07:50.087391  In 00:24:a5:af:24:85 ethertype ARP (0x0806)
                if header[1] == 'B':
                    # Seems to be a broadcast.
                    dst_mac = "ff:ff:ff:ff:ff:ff"
                    src_mac = header[2]
                else:
                    # Could be "In"; not sure what else.
                    dst_mac = None
                    src_mac = header[2]

            # Data will be a string like:
            # Reply 172.16.42.1 is-at 00:24:a5:af:24:85, length 46
            #     or
            # Request who-has 172.16.42.1 tell 172.16.42.116, length 28
            data = data.replace(',', '')
            data = data.split()
            # We only care about the packet length, because we'll be parsing
            # the hex dump that follows the packet.
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
                    arp = ARP(
                        pkt_bytes, time=time, src_mac=src_mac, dst_mac=dst_mac)
                    if bindings is not None:
                        for mac, ip in arp.bindings():
                            if int(ip) != 0:
                                if mac in bindings:
                                    if bindings[mac] != ip:
                                        bindings[mac] = ip
                                        print("(%s, %s) updated" % (
                                            str(mac).replace('-', ':'), ip))
                                else:
                                    bindings[mac] = ip
                                    print("(%s, %s)" % (
                                        str(mac).replace('-', ':'), ip))
                    if show_text:
                        arp.print()
                if length_remain < 0:
                    length = None

if __name__ == '__main__':
    sys.exit(main(sys.argv))