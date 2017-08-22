#!/usr/bin/env python

"""
Craft and send few VxLAN encapsulated packets.
"""

import argparse
import random
from scapy.all import Ether, ARP, IP, IPv6, TCP, UDP, Raw
from scapy.all import get_if_list, get_if_addr, send, sr1, load_contrib

from utils import csv2list

# Default VxLAN port
VXLAN_VNI = 1969
VXLAN_PORT = 4789

# Bad checksum to use
BCSUM = {
    'IPV4': 0xAAAA,
    'UDP': 0xBBBB,
    'TCP': 0xCCCC,
}

# Bad checksum options
CSUM_TYPES = ["all", "out-ipv4", "out-udp", "out-all",
              "in-ipv4", "in-tcp", "in-udp", "in-all"]
OUT_CSUM_TYPES = ["all", "out-ipv4", "out-udp", "out-all"]
IN_CSUM_TYPES = ["in-ipv4", "in-tcp", "in-udp", "in-all"]

# packet options for VxLAN
OUTER_PKT_TYPES = ["ipv4"]
INNER_PKT_TYPES = ["ipv4", "ipv6"]
INNER_TRSPT_TYPES = ["tcp", "udp"]


def __parse_bcsum(bcsum_type):
    bcsum = {}

    for pkt_type in CSUM_TYPES:
        if pkt_type not in ["all", "out-all", "in-all"]:
            bcsum[pkt_type] = False

    if bcsum_type is not None:
        if any(l in ["all", "out-all", "out-ipv4"] for l in bcsum_type):
            bcsum['out-ipv4'] = True
        if any(l in ["all", "out-all", "out-udp"] for l in bcsum_type):
            bcsum['out-udp'] = True

        if any(l in ["all", "in-all", "in-ipv4"] for l in bcsum_type):
            bcsum['in-ipv4'] = True
        if any(l in ["all", "in-all", "in-udp"] for l in bcsum_type):
            bcsum['in-udp'] = True
        if any(l in ["all", "in-all", "in-tcp"] for l in bcsum_type):
            bcsum['in-tcp'] = True

    return bcsum


def __parse_pkt_types(args):
    if args.out_pkt not in OUTER_PKT_TYPES:
        return "Invalid OUTER-PKT for '-O'. Use one of '%s'." % \
                ", ".join(OUTER_PKT_TYPES)

    if args.out_pkt is "ipv4" and args.dip4 is None:
        return "'-d DST-IPv4' is required for ipv4 outer packet."
    elif args.out_pkt is "ipv6" and args.dip6 is None:
        return "-D DST-IPv6 is required for ipv6 outer packet."

    if args.in_pkt not in INNER_PKT_TYPES:
        return "Invalid INNER-PKT for '-I'. Use one of '%s'." % \
                ", ".join(INNER_PKT_TYPES)

    if args.in_trspt not in INNER_TRSPT_TYPES:
        return "Invalid INNER-TRSPT for '-T'. Use one of '%s'." % \
                ", ".join(INNER_TRSPT_TYPES)

    return None


def __parse_args():
    parser = argparse.ArgumentParser(description="Send few UDP packets")
    parser.add_argument("-i", metavar="INTERFACE", dest="interface",
                        action="store", type=str,
                        help="interface to send UDP packets")
    parser.add_argument("-d", metavar="DST-IPv4", dest="dip4", type=str,
                        help="destination IPv4 address")
    parser.add_argument("-D", metavar="DST-IPv6", dest="dip6", type=str,
                        help="destination IPv6 address")
    parser.add_argument("-n", metavar="NPACKETS", dest="npackets", type=int,
                        default=4, help="number of UDP packets to send")
    parser.add_argument("-g", metavar="INTERVAL", dest="interval", type=int,
                        default=0, help="seconds to wait between packets")
    parser.add_argument("-l", metavar="SIZE", dest="size", type=int,
                        default=64, help="size of UDP payload in bytes")
    parser.add_argument("-w", dest="wait", action="store_true",
                        help="wait for user input between packets")
    parser.add_argument("-b", metavar="PKT-TYPE", dest="bcsum_type", type=str,
                        help="force bad checksum for IPv4 and/or UDP packets")
    parser.add_argument("-V", metavar="VNI", dest="vni", type=int,
                        default=VXLAN_VNI,
                        help="VxLAN Network Identifier; default=1969")
    parser.add_argument("-P", metavar="VXLAN-PORT", dest="vxlan_port",
                        type=int, default=VXLAN_PORT,
                        help="VxLAN UDP port number; default=4789")
    parser.add_argument("-O", metavar="OUTER-PKT", dest="out_pkt",
                        type=str, default="ipv4",
                        help="outer packet type; ipv4 or ipv6; default=ipv4")
    parser.add_argument("-I", metavar="INNER-PKT", dest="in_pkt",
                        type=str, default="ipv4",
                        help="inner packet type; ipv4 or ipv6; default=ipv4")
    parser.add_argument("-T", metavar="INNER-TRSPT", dest="in_trspt",
                        type=str, default="udp",
                        help="inner transport type; tcp or udp; default=udp")

    args = parser.parse_args()

    if args.interface not in get_if_list():
        err = "Interface '" + args.interface + "' not found."
        raise parser.error(err)

    if args.bcsum_type is not None:
        args.bcsum_type = csv2list(args.bcsum_type)

        if (set(args.bcsum_type) <= set(CSUM_TYPES)) is False:
            err = "Invalid PKT-TYPE for '-b'. Use one or more of '%s'." % \
                    ",".join(CSUM_TYPES)
            raise parser.error(err)

    args.bcsum = __parse_bcsum(args.bcsum_type)

    err = __parse_pkt_types(args)
    if err is not None:
        raise parser.error(err)

    return args


def rand_ip_get(ip_type):
    """ Return a randomly IPv4 or IPv6 address. """
    if ip_type == "ipv4":
        ip_addr = "20.21."
        ip_addr += ".".join(map(str, (random.randint(1, 254)
                                      for _ in range(2))))
    else:
        ip_addr = "2017:cafe:" + ":".join(("%x" % random.randint(0, 16**4)
                                           for i in range(6)))
    return ip_addr


def mac_get(sip, dip):
    """ Return the src and dst MAC by resolving ARP. """
    arp_resp = sr1(ARP(op=ARP.who_has, psrc=sip, pdst=dip), verbose=False)
    return arp_resp.hwdst, arp_resp.hwsrc


def build_ip_hdr(ip_type, sip, dip, bcsum):
    """ Build IPv4 or IPv6 header. """
    if ip_type == "ipv4":
        if bcsum is True:
            ip_hdr = IP(src=sip, dst=dip, chksum=BCSUM['IPV4'])
        else:
            ip_hdr = IP(src=sip, dst=dip)
    else:
        ip_hdr = IPv6(src=sip, dst=dip)
    return ip_hdr


def build_trspt_hdr(trspt_type, sport, dport, bcsum):
    """ Build TCP or UDP header. """
    if trspt_type == "tcp":
        if bcsum is True:
            trspt_hdr = TCP(sport=sport, dport=dport, chksum=BCSUM['TCP'])
        else:
            trspt_hdr = TCP(sport=sport, dport=dport)
    elif trspt_type == "udp":
        if bcsum is True:
            trspt_hdr = UDP(sport=sport, dport=dport, chksum=BCSUM['UDP'])
        else:
            trspt_hdr = UDP(sport=sport, dport=dport)
    return trspt_hdr


def build_outer_pkt(pkt_cfg):
    """ Build outer packet and VxLAN header. """
    sip = pkt_cfg['sip4']
    dip = pkt_cfg['dip4']
    dport = pkt_cfg['vxlan_port']
    vni = pkt_cfg['vni']
    bcsum = pkt_cfg['bcsum']

    ip4 = build_ip_hdr("ipv4", sip, dip, bcsum['out-ipv4'])
    udp = build_trspt_hdr("udp", random.randint(4096, 8192), dport,
                          bcsum['out-udp'])
    vxlan = VXLAN(flags=0x10, vni=vni)

    return ip4/udp/vxlan


def build_inner_pkt(pkt_cfg):
    """ Build the inner packet. """
    in_pkt = pkt_cfg['in_pkt']
    in_trspt = pkt_cfg['in_trspt']
    bcsum = pkt_cfg['bcsum']

    l2_hdr = Ether(dst=pkt_cfg['dmac'], src=pkt_cfg['smac'], type=0x800)
    l3_hdr = build_ip_hdr(in_pkt, rand_ip_get(in_pkt), rand_ip_get(in_pkt),
                          bcsum['in-ipv4'])

    if in_trspt is "udp":
        bcsum = bcsum['in-udp']
    else:
        bcsum = bcsum['in-tcp']
    l4_hdr = build_trspt_hdr(in_trspt, random.randint(4096, 8192),
                             random.randint(4096, 8192), bcsum)

    data_tmp = "77 " * pkt_cfg['size']
    data_tmp = data_tmp[:-1].split(" ")
    data = ''.join(data_tmp).decode('hex')
    payload = Raw(load=data)

    return l2_hdr/l3_hdr/l4_hdr/payload


def send_pkt(pkt_cfg, pkt):
    """ Send VxLAN encapsulated packets on the wire. """
    npackets = pkt_cfg['npackets']
    wait = pkt_cfg['wait']
    interval = pkt_cfg['interval']

    print pkt.command()

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
        send(pkt, inter=interval, count=npackets, verbose=False)
        print "Sent %d VxLAN packets." % (npackets)


def main():
    """ Entry point to the program. """
    pkt_cfg = vars(__parse_args())

    pkt_cfg['sip4'] = get_if_addr(pkt_cfg['interface'])
    pkt_cfg['smac'], pkt_cfg['dmac'] = \
        mac_get(pkt_cfg['sip4'], pkt_cfg['dip4'])
    print pkt_cfg

    load_contrib('vxlan')
    outer_pkt = build_outer_pkt(pkt_cfg)
    inner_pkt = build_inner_pkt(pkt_cfg)
    send_pkt(pkt_cfg, outer_pkt/inner_pkt)


if __name__ == "__main__":
    main()
