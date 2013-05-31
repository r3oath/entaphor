#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

from scapy.all import *
import thread, threading, string, zlib

class PacketLog():
    """
    This is the PacketLog, it's sole purpose is to hold the list of captured packets
    and provide simple processing options for them.

    PacketLog is thread safe and takes care of it's own locking/unlocking when adding,
    removing or working with packets.
    """
    packets = []
    accessLock = threading.Lock()

    def __init__(self):
        pass

    def __getitem__(self, index):
        return self.packets[index]

    def lock(self):
        self.accessLock.acquire()

    def unlock(self):
        self.accessLock.release()

    def add(self, packet):
        self.lock()
        self.packets.append(Packet(packet))
        self.unlock()

    def waitForPackets(self, minBuffer=1, timeout=0):
        """
        Wait for the PacketLog to be populated with packets. This is blocking call.

        If you specify a minBuffer value, wait until the log 
        has at least that many packets in it before it stops blocking.

        If you specify a timeout value, wait that many seconds
        before blocking stops and return a 'None' value if there are no
        packets currently in the log.
        """
        if minBuffer < 1:
            return
            
        lastTime = time.time()

        while True:
            size = self.size()
            if size >= minBuffer:
                return size
            if timeout > 0:
                if int(time.time() - lastTime) >= timeout:
                    return size if size > 0 else None

    def wfp(self, minBuffer=1, timeout=0): # Shorthand for waitForPackets.
        return self.waitForPackets(minBuffer=minBuffer, timeout=timeout)

    def getAll(self):
        return self.packets

    def takeOne(self):
        """
        Take one packet from the local log, the packet returned will be the first
        packet in the list, not the last. This will help when processing
        as you'll get the packets in the order they were recieved.

        As each packet is grabbed the list will slowly shrink until no
        packets are left in the local log. Unless off course it's being
        filled up again by an AsyncSniffer.
        """
        self.lock()
        if len(self.packets) != 0:
            packet = self.packets.pop(0)
            self.unlock()
            return packet
        else:
            self.unlock()
            return None

    def takeAll(self):
        """
        Take all the packets from the log. This will empty the local log.
        """
        self.lock()
        packets = self.packets
        self.packets = []
        self.unlock()
        return packets

    def size(self):
        self.lock()
        lenth = len(self.packets)
        self.unlock()
        return lenth

class Sniffer():
    """
    This is the standard Entaphor Sniffer. It will sniff for a specified amount of packets
    and provide useful information and processing methods for them.
    """    
    packets = PacketLog()

    def __init__(self):
        pass
        
    def sniff(self, count=1, filter='', packetLog=None):
        if count < 1:
            raise Exception('Count cannot be smaller than 1. If you need this, please use AsyncSniffer.')
            count = 1

        if packetLog != None:
            self.packets = packetLog

        sniff(count=count, filter=filter, prn=self.packets.add, store=0)

    def packetLog(self):
        return self.packets

    def pl(self): # Shorthand for getPacketLog.
        return self.packetLog()

class AsyncSniffer():
    """
    This is almost identical to the standard Sniffer, however this one does not block while sniffing.
    You also need to pass it a PacketLog instance to use.
    """
    def sniff(self, packetLog=None, filter=''):
        if packetLog == None:
            raise Exception('You need to pass in a PacketLog instance. Where are we going to put all these packets?')

        thread.start_new_thread(sniff, (), {'filter': filter, 'prn': packetLog.add, 'store': 0})

class Packet():
    """
    This class represents a single packet. It has details on both the source and
    destination network objects/clients, as well as the original Scapy packet.
    """
    srcObj = None
    dstObj = None
    packet = None
    packetData = ''

    def __init__(self, packet):
        """
        When initialized, the Packet class will process the passed in Scapy packet
        and extract all the useful information for the Source and Destination
        network objects, and prepare other information.
        """
        self.srcObj = NetworkObject()
        self.dstObj = NetworkObject()
        self.packet = packet # The original Scapy packet.

        if Ether in packet:
            self.srcObj.mac = packet[Ether].src
            self.dstObj.mac = packet[Ether].dst

        if IP in packet:
            self.srcObj.ip = packet[IP].src
            self.dstObj.ip = packet[IP].dst

        if UDP in packet:
            self.srcObj.port = packet[UDP].sport
            self.dstObj.port = packet[UDP].dport

        if TCP in packet:
            self.srcObj.port = packet[TCP].sport
            self.dstObj.port = packet[TCP].dport

        if Raw in packet:
            self.packetData = packet[Raw].load

    def source(self):
        return self.srcObj

    def s(self): # Shorthand for source.
        return self.source()

    def destination(self):
        return self.dstObj

    def d(self): # Shorthand for destination.
        return self.destination()

    def scapyPacket(self):
        return self.packet

    def sp(self): # Shorthand for scapyPacket.
        return self.scapyPacket()

    def data(self):
        return self.packetData

    def escapedData(self, placeholder='.'):
        return ''.join(self.escape(c, placeholder) for c in self.packetData)

    def escape(self, byte, placeholder='.'):
        return byte if byte in string.printable else placeholder

    def ungzip(self, data=''):
        try:
            clearData = zlib.decompress(data)
            return clearData
        except:
            return 'E4: Could not decompress data.'

class NetworkObject():
    """
    This class represents a network object (aka a client/server). It'll hold basic
    information like the MAC, IP and Port, as well as other useful bits.
    """
    mac = None
    ip = None
    port = None

    def __init__(self, mac=None, ip=None, port=None):
        self.mac = mac
        self.ip = ip
        self.port = port

    def getIP(self):
        return self.ip

    def getMAC(self):
        return self.mac

    def getPort(self):
        return self.port

    def setIP(self, ip):
        self.ip = ip

    def setMAC(self, mac):
        self.mac = mac

    def setPort(self, port):
        self.port = port