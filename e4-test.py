#!/usr/bin/python

import E4, E4Web, sys

e4Sniffer = E4.AsyncSniffer()
e4PacketLog = E4.PacketLog()
e4Web = E4Web.Web()

e4Sniffer.sniff(packetLog=e4PacketLog, filter='port 80')

while True:
    if e4PacketLog.waitForPackets(timeout=60) == None:
        print 'Timeout Reached.'
        sys.exit()

    for p in e4PacketLog.takeAll():
        print 'Source: %s:%d (%s)' % (p.source().ip, p.source().port, p.source().mac)
        print 'Destination: %s:%d (%s)' % (p.destination().ip, p.destination().port, p.destination().mac)
        print 'Response: %s' % e4Web.grabResponse(p, textResponse=True)
        headers = e4Web.headers(p)
        print 'Host Header: %s' % e4Web.grabHeader(headers, 'Host', 'None.')
        print '...'