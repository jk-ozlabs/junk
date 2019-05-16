#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-3.0-or-later

import socket
import argparse
import sys
import struct
import time


def hex_str(s, b):
    # python 2's recv() gives us a string, python3's gives bytes. Conditionally
    # do an ord().
    t = ord if isinstance(b, str) else lambda x: x
    return s.join(map(lambda c: '%02x' % t(c), b))


def print_packet(b):
    print('%d bytes %s -> %s' % (len(b),
                                 hex_str(':', b[6:12]),
                                 hex_str(':', b[:6])))
    while b:
        print('\t' + hex_str(' ', b[:16]))
        b = b[16:]


def dump_packet(f, buf, t):
    sec = int(t)
    usec = int((t - sec) * 1000000)
    size = len(buf)
    header = struct.pack('IIII', sec, usec, size, size)
    f.write(header + buf)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w', dest='write')
    parser.add_argument('-i', dest='interface', default='eth0')
    parser.add_argument('-q', dest='quiet', action='store_true')
    args = parser.parse_args()

    sd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sd.bind((args.interface, 0))
    dumpfile = None

    if args.write:
        dumpfile = open(args.write, 'wb', 0)
        header = struct.pack('IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1)
        dumpfile.write(header)

    def process_packet(buf):
        if buf is None:
            return
        t = time.time()
        if not args.quiet:
            print_packet(buf)
        if dumpfile is not None:
            dump_packet(dumpfile, buf, t)

    while True:
        buf = bytes(sd.recv(4096))
        # filter-out broadcast traffic
        if buf[:6] == '\xff\xff\xff\xff\xff\xff':
            continue
        process_packet(buf)


if __name__ == '__main__':
    sys.exit(main())
