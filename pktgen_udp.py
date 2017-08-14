#!/usr/bin/env python

"""
Generate UDP packets.
"""

import argparse
import random
from scapy.all import IP, UDP, Raw
from scapy.all import get_if_list, get_if_addr, send

BAD_CSUM = 0xDEED

def __parse_args():
    parser = argparse.ArgumentParser(description="Send few UDP packets")
    parser.add_argument("-i", metavar="INTERFACE", dest="interface",
                        action="store", type=str,
                        help="interface to send UDP packets")
    parser.add_argument("-d", metavar="DST-IP", dest="dip", type=str,
                        help="destination IP address")
    parser.add_argument("-p", metavar="DST-PORT", dest="dport", type=int,
                        help="destination UDP port")
    parser.add_argument("-n", metavar="NPACKETS", dest="npackets", type=int,
                        default=4, help="number of UDP packets to send")
    parser.add_argument("-g", metavar="INTERVAL", dest="interval", type=int,
                        default=0, help="seconds to wait between packets")
    parser.add_argument("-l", metavar="SIZE", dest="size", type=int,
                        default=64, help="size of UDP payload in bytes")
    parser.add_argument("-w", dest="wait", action="store_true",
                        help="wait for user input between packets")
    parser.add_argument("-b", dest="bad_csum", action="store_true",
                       help="force bad checksum for UDP packets")

    args = parser.parse_args()

    if args.interface not in get_if_list():
        err = "Interface '" + args.interface + "' not found."
        raise parser.error(err)

    return args


def udp_send(sip, dip, dport, size, npackets, bad_csum, wait, interval):
    """ Send UDP packets. """
    stat = "sip %s, dip %s, dport %s, size %u" % (sip, dip, dport, size)

    data_tmp = "77 " * size
    data_tmp = data_tmp[:-1].split(" ")
    data = ''.join(data_tmp).decode('hex')
    #pkt = IP(src=sip, dst=dip)/UDP(dport=dport)/Raw(load=data)
    
    ip = IP(src=sip, dst=dip)
    
    sport = random.randint(4096, 8192)
    if bad_csum is True:
        udp = UDP(sport=sport, dport=dport, chksum=BAD_CSUM)
    else:
        udp = UDP(sport=sport, dport=dport)
        
    payload = Raw(load=data)

	#pkt = IP(src=sip, dst=dip)/UDP(dport=dport, chksum=0xdeed)/Raw(load=data)
	#pkt = IP(src=sip, dst=dip)/UDP(dport=dport)/Raw(load=data)
    
    pkt = ip/udp/payload
    stat = "{sip:%s dip:%s}, {sport:%s dport:%s} {csum:%s size:%u}" % \
            (sip, dip, sport, dport, bad_csum, size)

    if wait:
        while npackets:
            send(pkt, verbose=False)
            print "Sent %d UDP packet(s): %s" % (1, stat)
            _ = raw_input("Hit 'enter'/'return' to continue...")
            npackets -= 1
    else:
        send(pkt, inter=interval, count=npackets)
        print "Sent %d UDP packets: %s" % (npackets, stat)


def main():
    """ Entry point to the program. """
    args = __parse_args()
    print args

    sip = get_if_addr(args.interface)
    udp_send(sip, args.dip, args.dport, args.size, args.npackets,
             args.bad_csum, args.wait, args.interval)

if __name__ == "__main__":
    main()
