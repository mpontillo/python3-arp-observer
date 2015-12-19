#!/usr/bin/env python3

import codecs
import netaddr
import os
import stat
import struct
import sys


def bytes_to_hex(byte_string):
    """Utility function to convert the the specified `bytes` object into
    a string of hex characters."""
    return codecs.encode(byte_string, 'hex')


def bytes_to_int(byte_string):
    """Utility function to convert the specified string of bytes into
    an `int`."""
    return int(bytes_to_hex(byte_string), 16)


def hex_str_to_bytes(data):
    """Strips spaces, '-', and ':' characters out of the specified string,
    and (assuming the characters that remain are hex digits) returns an
    equivalent `bytes` object."""
    data = data.replace(':', '')
    data = data.replace('-', '')
    data = data.replace(' ', '')
    return bytes.fromhex(data)


class ARP:
    """Representation of an ARP packet."""

    def __init__(self, pkt_bytes, time=None, src_mac=None, dst_mac=None):
        """
        :param pkt_bytes: The input bytes of the ARP packet.
        :type pkt_bytes: bytes
        :param time: Timestamp packet was seen (format is undefined)
        :type time: str
        :param src_mac: Source MAC address from Ethernet header.
        :type src_mac: str
        :param dst_mac: Desination MAC address from Ethernet header.
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
        """Returns a netaddr.EUI representing the source MAC address."""
        return netaddr.EUI(
            bytes_to_int(self.sender_hardware_bytes))

    @property
    def target_eui(self):
        """Returns a netaddr.EUI representing the target MAC address."""
        return netaddr.EUI(
            bytes_to_int(self.target_hardware_bytes))

    @property
    def source_ip(self):
        """Returns a netaddr.IPAddress representing the source IP address."""
        return netaddr.IPAddress(self.sender_protocol_bytes)

    @property
    def target_ip(self):
        """Returns a netaddr.IPAddress representing the target IP address."""
        return netaddr.IPAddress(self.target_protocol_bytes)

    def is_valid(self):
        """Only (Ethernet MAC, IPv4) bindings are currently supported. This
        method ensures this ARP packet specifies those types.
        """
        if self.hardware_type != 1:
            return False
        if self.protocol_type != 0x800:
            return False
        if self.hardware_length != 6:
            return False
        if self.protocol_length != 4:
            return False
        return True

    def bindings(self):
        """Yields each (MAC, IP) binding found in this ARP packet."""
        if not self.is_valid():
            return

        if self.operation == 1:
            # This is an ARP request.
            # We can find a binding in the (source_eui, source_ip)
            source_ip = self.source_ip
            if int(source_ip) != 0:
                yield (source_ip, self.source_eui)
        elif self.operation == 2:
            # This is an ARP reply.
            # We can find a binding in both the (source_eui, source_ip) and
            # the (target_eui, target_ip).
            source_ip = self.source_ip
            target_ip = self.target_ip
            if int(source_ip) != 0:
                yield (source_ip, self.source_eui)
            if int(target_ip) != 0:
                yield (target_ip, self.target_eui)

    def write(self, out=sys.stdout):
        """Output text-based details about this ARP packet to the specified
        file or stream.

        :param out: An object with a `write(str)` method.
        """
        if self.time is not None:
            out.write("ARP observed at %s:\n" % self.time)
        if self.src_mac is not None:
            out.write("        Ethernet source: %s\n" % self.src_mac)
        if self.dst_mac is not None:
            out.write("   Ethernet destination: %s\n" % self.dst_mac)

        out.write("          Hardware type: 0x%04x\n" % self.hardware_type)
        out.write("          Protocol type: 0x%04x\n" % self.protocol_type)
        out.write("Hardware address length: %d\n" % self.hardware_length)
        out.write("Protocol address length: %d\n" % self.protocol_length)
        if self.operation == 1:
            operation_str = ' (request)'
        elif self.operation == 2:
            operation_str = ' (reply)'
        else:
            operation_str = ''
        out.write("              Operation: %d%s\n" % (
            self.operation, operation_str))
        out.write("Sender hardware address: %s\n" % str(
            self.source_eui).replace('-', ':').lower())
        out.write("Sender protocol address: %s\n" % self.source_ip)
        out.write("Target hardware address: %s\n" % str(
            self.target_eui).replace('-', ':').lower())
        out.write("Target protocol address: %s\n" % self.target_ip)
        out.write("\n")


def main(argv):
    """Main entry point. Ensure stdin is a pipe, then check command-line
    arguments and run the ARP observation loop.

    :param argv: The contents of sys.argv.
    """
    mode = os.fstat(0).st_mode
    if not stat.S_ISFIFO(mode):
        print("Usage:")
        print("    sudo tcpdump 'arp' -i any -s 64 -n -e -l -x "
              "2> /dev/null | %s [args]" % (argv[0]))
        print("")
        print("Arguments:")
        print("    -v --verbose  Print each ARP packet.")
        print("    -d --debug    Print additional debugging information.")
        print("    -b --bindings Track each (MAC,IP) binding and print new\n"
              "                  or changed bindings to stdout.")
        return 1
    verbose = False
    debug = False
    bindings = False
    if '-v' in argv or '--verbose' in argv:
        verbose = True
    if '-d' in argv or '--debug' in argv:
        debug = True
    if '-b' in argv or '--bindings' in argv:
        bindings = True
    observe_arp_packets(
        debug=debug, verbose=verbose, bindings=bindings)
    return 0


def update_and_print_bindings(bindings, arp):
    """Update the specified bindings dictionary with the given ARP packet."""
    for ip, mac in arp.bindings():
        if ip in bindings:
            # Binding already exists. Update it (and set the 'updated' flag
            # to 1 when outputting the CSV.)
            if bindings[ip] != mac:
                bindings[ip] = mac
                print("{ip},{mac},1".format(
                    ip=ip, mac=str(mac).replace('-', ':').lower()))
        else:
            bindings[ip] = mac
            print("{ip},{mac},0".format(
                ip=ip, mac=str(mac).replace('-', ':').lower()))


def observe_arp_packets(
        debug=False, verbose=False, bindings=False):
    """Read stdin and look for tcpdump-style ARP output.

    :param debug: Output debug information.
    :type debug: bool
    :param verbose: Output text-based ARP packet details.
    :type verbose: bool
    :param bindings: Track (MAC, IP) bindings, and print new/update bindings.
    :type bindings: bool
    """
    length = None
    length_remain = 0
    pkt_bytes = b''
    time = None
    src_mac = None
    src_mac_bytes = None
    dst_mac = None
    dst_mac_bytes = None
    arp_ethertype = hex_str_to_bytes('0806')
    if bindings:
        bindings = dict()
    else:
        bindings = None

    while True:
        line = sys.stdin.readline().strip()
        if not line:
            exit(1)
        if debug:
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
                src_mac_bytes = hex_str_to_bytes(src_mac)
                dst_mac = header[3]
                dst_mac_bytes = hex_str_to_bytes(dst_mac)
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
                # When the output is in this format, we can't know these values
                # for sure.
                src_mac_bytes = None
                dst_mac_bytes = None

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
                if debug:
                    print("    Expecting packet of length: %d" % length)
            except ValueError:
                length = None
            pkt_bytes = b''
        elif length is not None and length >= 28 and line.startswith('0x'):
            # This will be a line like:
            # 0x0020:  0000 0000 0000 0000 0000 0000 0000
            data = line.split(':')
            if len(data) == 2:
                new_bytes = hex_str_to_bytes(data[1])
                length_remain -= len(new_bytes)
                pkt_bytes += new_bytes
                # If we got more bytes than we expected, it's probably just
                # padding. But it could be that tcpdump wrote the Ethernet
                # header, when we weren't expecting it to.
                # So if we can figure out that the Ethernet header
                # is tacked onto the front, strip it off.
                if src_mac_bytes is not None and dst_mac_bytes is not None:
                    eth_header = (
                        dst_mac_bytes + src_mac_bytes + arp_ethertype)
                    if pkt_bytes[:14] == eth_header:
                        pkt_bytes = pkt_bytes[14:]
                        length_remain += 14
                if length_remain <= 0:
                    arp = ARP(
                        pkt_bytes, time=time, src_mac=src_mac, dst_mac=dst_mac)
                    if bindings is not None:
                        update_and_print_bindings(bindings, arp)
                    if verbose:
                        arp.write()

if __name__ == '__main__':
    sys.exit(main(sys.argv))
