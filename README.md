python3-arp-observer
====================
Real-time ARP packet parser for Python 3. (requires tcpdump)

This software parses the output of `tcpdump` in order to passively monitor the network for (IP, MAC) bindings.

The intended usage is to run with the `-b` (or `--bindings`) argument, which will output a line of text (in CSV format)
indicating the IP address, its current MAC address, and an `updated` boolean (specified as `0` or `1`) indicating whether
or not this binding has changed since it was last seen. For example:

    192.168.0.1,01:02:03:04:05:06,0
    192.168.0.100,01:03:04:05:06:07,0
    192.168.0.100,01:13:14:15:16:17,1

In the above example, `192.168.0.1` was observed at `01:02:03:04:05:06`, then `192.168.0.100` was observed at
`01:03:04:05:06:07`. Then, the MAC address of `192.168.0.100` changes to `01:13:14:15:16:17` (and the `updated`
flag is set.)

Dependencies
------------

`python3-arp-observer` has been tested on the following platforms:

### Ubuntu

Ubuntu 16.04 LTS "Xenial Xerus"

    apt-get install python3-netaddr
    apt-get install tcpdump

### OS X (homebrew)

OS X 10.11.2 "El Capitan"

    brew install python3
    pip3 install netaddr
