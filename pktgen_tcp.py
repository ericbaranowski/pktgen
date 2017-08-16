#!/usr/bin/env python

"""
Generate TCP packets.
"""

import argparse
import random
from scapy.all import IP, TCP, Raw
from scapy.all import get_if_list, get_if_addr, send, sr1

BAD_CSUM_IP = 0xABCD
BAD_CSUM_TCP = 0xDEED
PKT_TYPES = ["ipv4", "tcp", "all"]


def __parse_args():
    parser = argparse.ArgumentParser(description="Send few TCP packets")
    parser.add_argument("-i", metavar="INTERFACE", dest="interface",
                        action="store", type=str, required=True,
                        help="interface to send TCP packets")
    parser.add_argument("-d", metavar="DST-IP", dest="dip", type=str,
                        required=True, help="destination IP address")
    parser.add_argument("-p", metavar="DST-PORT", dest="dport", type=int,
                        required=True, help="destination TCP port")
    parser.add_argument("-n", metavar="NPACKETS", dest="npackets", type=int,
                        default=4, help="number of TCP packets to send")
    parser.add_argument("-g", metavar="INTERVAL", dest="interval", type=int,
                        default=0, help="seconds to wait between packets")
    parser.add_argument("-l", metavar="SIZE", dest="size", type=int,
                        default=64, help="size of TCP payload in bytes")
    parser.add_argument("-w", dest="wait", action="store_true",
                        help="wait for user input between packets")
    parser.add_argument("-a", dest="synack", action="store_true",
                        help="use 3-way TCP handshake")
    parser.add_argument("-b", metavar="PKT-TYPE", dest="bad_csum", type=str,
                        help="force bad checksum for IPv4 and/or TCP packets")

    args = parser.parse_args()

    if args.interface not in get_if_list():
        err = "Interface '" + args.interface + "' not found."
        raise parser.error(err)

    if args.bad_csum is not None and args.bad_csum not in PKT_TYPES:
        err = "Invalid PKT-TYPE for '-b'. Use one of '%s'." % \
                ", ".join(PKT_TYPES)
        raise parser.error(err)

    return args


def tcp_send(pkt_cfg):
    """ Send TCP packets. """
    sip = pkt_cfg['sip']
    dip = pkt_cfg['dip']
    dport = pkt_cfg['dport']
    size = pkt_cfg['size']
    npackets = pkt_cfg['npackets']
    tway = pkt_cfg['synack']
    bad_csum = pkt_cfg['bad_csum']
    wait = pkt_cfg['wait']
    interval = pkt_cfg['interval']

    # Build the packet.
    if bad_csum in ["ipv4", "all"]:
        ip = IP(src=sip, dst=dip, chksum=BAD_CSUM_IP)
    else:
        ip = IP(src=sip, dst=dip)

    sport = random.randint(4096, 8192)
    if bad_csum in ["tcp", "all"]:
        tcp = TCP(sport=sport, dport=dport, chksum=BAD_CSUM_TCP)
    else:
        tcp = TCP(sport=sport, dport=dport)

    data_tmp = "77 " * size
    data_tmp = data_tmp[:-1].split(" ")
    data = ''.join(data_tmp).decode('hex')
    payload = Raw(load=data)

    pkt = ip/tcp/payload
    stat = "{sip:%s dip:%s}, {sport:%s dport:%s} {bad-csum:%s size:%u}" % \
           (sip, dip, sport, dport, bad_csum, size)

    # 3-way TCP handshake to setup connection.
    if tway is True:
        good_ip = IP(src=sip, dst=dip)

        seq_seqno = 5000
        tcp_syn = TCP(sport=sport, dport=dport, flags='S', seq=seq_seqno)
        tcp_synack = sr1(good_ip/tcp_syn)
        print "Sent TCP SYN with seq %u" % (seq_seqno)

        ack_seqno = tcp_synack.ack
        ack_ackno = tcp_synack.seq + 1
        tcp_ack = TCP(sport=sport, dport=dport, flags='A',
                      seq=ack_seqno, ack=ack_ackno)
        send(good_ip/tcp_ack)
        print "Sent TCP ACK with seq %u, ack %u" % (ack_seqno, ack_ackno)

    # Send traffic.
    if wait:
        while npackets:
            _ = raw_input("Hit 'enter' to send packet...")
            send(pkt, verbose=False)
            print "Sent %d TCP packet(s): %s" % (1, stat)
            npackets -= 1
    else:
        send(pkt, inter=interval, count=npackets)
        print "Sent %d TCP packets: %s" % (npackets, stat)


def main():
    """ Entry point to the program. """
    pkt_cfg = vars(__parse_args())
    print pkt_cfg
    pkt_cfg['sip'] = get_if_addr(pkt_cfg['interface'])

    tcp_send(pkt_cfg)


if __name__ == "__main__":
    main()
