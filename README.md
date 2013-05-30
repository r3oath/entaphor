Entaphor (E4 or \n4)
====================

E4 is a light Scapy wrapper that makes it easy to process and work with TCP and UDP traffic. It also provides a number of small modules that will make working with web, dns, arp and other packets a breeze. Currently still a heavy WIP, but the underlying framework is there.

Example: Using E4 to capture all web packets, display the source and destination infromation and the HTTP Host header. If no packets are recieved within 60 seconds, the script times out and finishes.

```python
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
        headers = e4Web.headers(p)
        print 'Host Header: %s' % e4Web.grabHeader(headers, 'Host', 'None.')
        print '...'
```

Example output from the above script:

```shell
<snip>
Source: 10.0.0.107:56973 (00:24:54:42:03:e1)
Destination: 141.101.117.203:80 (00:1d:5a:92:ae:f1)
Host Header: www.r3oath.com
...
Source: 10.0.0.107:56974 (00:24:54:42:03:e1)
Destination: 141.101.117.203:80 (00:1d:5a:92:ae:f1)
Host Header: None.
...
<snip>
```
