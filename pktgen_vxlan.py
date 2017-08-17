#!/usr/bin/env python

"""
Craft and send few VxLAN encapsulated packets.
"""

import argparse
import random
from scapy.all import IP, TCP, UDP, Raw
from scapy.all import get_if_list, get_if_addr, send, load_contrib

from utils import csv2list

# Default VxLAN port
VXLAN_PORT = 4789

# Bad checksum to use
BCSUM = {
    'OUT_IPV4': 0xAAAA,
    'OUT_UDP': 0xBBBB,
    'IN_IPV4': 0xCCCC,
    'IN_UDP': 0xDDDD,
    'IN_TCP': 0xEEEE,
}

# Bad checksum options
CSUM_TYPES = ["all", "out-ipv4", "out-udp", "out-all",
              "in-ipv4", "in-tcp", "in-udp", "in-all"]
OUT_CSUM_TYPES = ["all", "out-ipv4", "out-udp", "out-all"]
IN_CSUM_TYPES = ["in-ipv4", "in-tcp", "in-udp", "in-all"]

# Inner packet options for VxLAN
INNER_PKT_TYPES = ["tcp", "udp"]


def __parse_args():
    parser = argparse.ArgumentParser(description="Send few UDP packets")
    parser.add_argument("-i", metavar="INTERFACE", dest="interface",
                        action="store", type=str,
                        help="interface to send UDP packets")
    parser.add_argument("-d", metavar="DST-IP", dest="dip", type=str,
                        help="destination IP address")
    parser.add_argument("-n", metavar="NPACKETS", dest="npackets", type=int,
                        default=4, help="number of UDP packets to send")
    parser.add_argument("-g", metavar="INTERVAL", dest="interval", type=int,
                        default=0, help="seconds to wait between packets")
    parser.add_argument("-l", metavar="SIZE", dest="size", type=int,
                        default=64, help="size of UDP payload in bytes")
    parser.add_argument("-w", dest="wait", action="store_true",
                        help="wait for user input between packets")
    parser.add_argument("-b", metavar="PKT-TYPE", dest="bad_csum", type=str,
                        help="force bad checksum for IPv4 and/or UDP packets")
    parser.add_argument("-V", metavar="VNI", dest="vni", type=int,
                        help="VxLAN Network Identifier; default=24")
    parser.add_argument("-P", metavar="VXLAN-PORT", dest="vxlan_port",
                        type=int, default=VXLAN_PORT,
                        help="VxLAN UDP port number")
    parser.add_argument("-I", metavar="INNER-PKT", dest="inner_pkt", type=str,
                        required=True, help="inner packet type; tcp or udp")

    args = parser.parse_args()

    if args.interface not in get_if_list():
        err = "Interface '" + args.interface + "' not found."
        raise parser.error(err)

    if args.bad_csum is not None:
        args.bad_csum = csv2list(args.bad_csum)

        if (set(args.bad_csum) <= set(CSUM_TYPES)) is False:
            err = "Invalid PKT-TYPE for '-b'. Use one or more of '%s'." % \
                    ",".join(CSUM_TYPES)
            raise parser.error(err)

    if args.inner_pkt is not None and args.inner_pkt not in INNER_PKT_TYPES:
        err = "Invalid INNER-PKT for '-i'. Use one of '%s'." % \
                ", ".join(INNER_PKT_TYPES)

    return args


def build_outer_pkt(pkt_cfg):
    """ Build outer packet and VxLAN header. """
    sip = pkt_cfg['sip']
    dip = pkt_cfg['dip']
    dport = pkt_cfg['vxlan_port']
    vni = pkt_cfg['vni']
    bad_csum = pkt_cfg['bad_csum']

    if bad_csum <= set(["all", "out-all", "out-ipv4"]):
        ip4 = IP(src=sip, dst=dip, chksum=BCSUM['OUT_IPV4'])
    else:
        ip4 = IP(src=sip, dst=dip)

    sport = random.randint(4096, 8192)
    if bad_csum <= set(["all", "out-all", "out-udp"]):
        udp = UDP(sport=sport, dport=dport, chksum=BCSUM['OUT_UDP'])
    else:
        udp = UDP(sport=sport, dport=dport)

    vxlan = VXLAN(flags=0x10, vni=vni)

    return ip4/udp/vxlan


def build_inner_pkt(pkt_cfg):
    """ Build the inner packet. """
    sip = pkt_cfg['sip']
    dip = pkt_cfg['dip']
    size = pkt_cfg['size']
    inner_pkt = pkt_cfg['inner_pkt']
    bad_csum = set(pkt_cfg['bad_csum'])

    if bad_csum <= set(["all", "in-all", "in_ipv4"]):
        ip4 = IP(src=sip, dst=dip, chksum=BCSUM['IN_IPV4'])
    else:
        ip4 = IP(src=sip, dst=dip)

    sport = random.randint(4096, 8192)
    dport = random.randint(4096, 8192)
    if inner_pkt == "tcp":
        if bad_csum <= set(["all", "in-all", "in-tcp"]):
            lyr4 = TCP(sport=sport, dport=dport, chksum=BCSUM['IN_TCP'])
        else:
            lyr4 = TCP(sport=sport, dport=dport)
    else:
        if bad_csum <= set(["all", "in-all", "in-udp"]):
            lyr4 = UDP(sport=sport, dport=dport, chksum=BCSUM['IN_UDP'])
        else:
            lyr4 = UDP(sport=sport, dport=dport)

    data_tmp = "77 " * size
    data_tmp = data_tmp[:-1].split(" ")
    data = ''.join(data_tmp).decode('hex')
    payload = Raw(load=data)

    return ip4/lyr4/payload


def send_pkt(pkt_cfg, pkt):
    """ Send VxLAN encapsulated packets on the wire. """
    npackets = pkt_cfg['npackets']
    wait = pkt_cfg['wait']
    interval = pkt_cfg['interval']

    if wait:
        curr = 1
        total = npackets
        while npackets:
            _ = raw_input("Hit 'enter' to send packet...")
            send(pkt, verbose=False)
            print "Sent %d/%d VxLAN packet(s)." % (curr, total)
            npackets -= 1
            curr += 1
    else:
        send(pkt, inter=interval, count=npackets)
        print "Sent %d VxLAN packets." % (npackets)
        print pkt.command()


def main():
    """ Entry point to the program. """
    pkt_cfg = vars(__parse_args())
    pkt_cfg['sip'] = get_if_addr(pkt_cfg['interface'])
    print pkt_cfg

    load_contrib('vxlan')

    outer_pkt = build_outer_pkt(pkt_cfg)
    inner_pkt = build_inner_pkt(pkt_cfg)
    send_pkt(pkt_cfg, outer_pkt/inner_pkt)

if __name__ == "__main__":
    main()
