#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

import thread
import threading
import string
import zlib
from scapy.all import *

class PacketLog():
    """Holds a collection of packets for processing."""
    packets = []
    accessLock = threading.Lock()

    def __init__(self):
        pass

    def __getitem__(self, index):
        return self.packets[index]

    def lock(self):
        """Lock the PacketLog, used for threading."""
        self.accessLock.acquire()

    def unlock(self):
        """Unlock the PacketLog, used for threading."""
        self.accessLock.release()

    def add(self, packet):
        """Add a packet to the log."""
        self.lock()
        self.packets.append(Packet(packet))
        self.unlock()

    def waitForPackets(self, minBuffer=1, timeout=0):
        """Block and wait for packets to become available in the log.

        Keyword Arguments:
        minBuffer -- The minimum number of packets to be available before unblocking. (default 1)
        timeout -- If no packets become available in this many seconds to satisfy the
            minBuffer, unblock and return the packets available, if any. If no packets
            are available then just return None. (default 0)

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

    def wfp(self, minBuffer=1, timeout=0):
        """Shorthand for waitForPackets()"""
        return self.waitForPackets(minBuffer=minBuffer, timeout=timeout)

    def getAll(self):
        """Return the list of all available packets and keep them in the log."""
        return self.packets

    def takeOne(self):
        """Remove the first packet from the log and return it."""
        self.lock()
        if len(self.packets) != 0:
            packet = self.packets.pop(0)
            self.unlock()
            return packet
        else:
            self.unlock()
            return None

    def takeAll(self):
        """Remove all the packets from the log and return them. This clears the log."""
        self.lock()
        packets = self.packets
        self.packets = []
        self.unlock()
        return packets

    def size(self):
        """Get the current size of the log (number of packets available)."""
        self.lock()
        lenth = len(self.packets)
        self.unlock()
        return lenth

class Sniffer():
    """Sniff for and capture packets. This Sniffer is not threaded and will block
    until the specified amount of packets have been captured.

    """
    packets = PacketLog()

    def __init__(self):
        pass
        
    def sniff(self, count=1, filter='', packetLog=None):
        """Sniff for and capture packets. This is a blocking call and will only return
        once the specified amount of packets have been captured.

        Keyword Arguments:
        count -- The number of packets to capture. (default 1)
        filter -- Apply a filter when capturing packets. (default '')
        packetLog -- Specify a seperate PacketLog to fill with captured packets. (default None)

        """
        if count < 1:
            raise Exception('If you need a count < 1, please use E4.AsyncSniffer.')
            count = 1

        if packetLog != None:
            self.packets = packetLog

        sniff(count=count, filter=filter, prn=self.packets.add, store=0)

    def packetLog(self):
        """Returns a PacketLog of all captured packets."""
        return self.packets

    def pl(self):
        """Shorthand for packetLog()"""
        return self.packetLog()

class AsyncSniffer():
    """Sniff for and capture packets continuously. This Sniffer is threaded and will not block."""
    def sniff(self, packetLog=None, filter=''):
        """Sniff for and capture packets continuously.

        Keyword Arguments:
        packetLog -- The packetLog to fill with the captured packets.
        filter -- Apply a filter when capturing packets. (default '')

        """
        if packetLog == None:
            raise Exception('You need to pass in a E4.PacketLog instance.')

        thread.start_new_thread(sniff, (), {'filter': filter, 'prn': packetLog.add, 'store': 0})

class Packet():
    """This represents a network packet."""
    srcObj = None
    dstObj = None
    packet = None
    packetData = ''

    def __init__(self, packet):
        """Create a new packet.

        Keyword Arguments:
        packet -- The original Scapy packet to process.

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
        """Returns the packet's source NetworkObject."""
        return self.srcObj

    def s(self):
        """Shorthand for source()"""
        return self.source()

    def destination(self):
        """Returns the packet's destination NetworkObject."""
        return self.dstObj

    def d(self):
        """Shorthand for destination()"""
        return self.destination()

    def scapyPacket(self):
        """Returns the original Scapy packet."""
        return self.packet

    def sp(self):
        """Shorthand for scapyPacket()"""
        return self.scapyPacket()

    def data(self):
        """Returns the RAW packet data."""
        return self.packetData

    def escapedData(self, placeholder='.'):
        """Returns escaped packet data.

        Keyword Arguments:
        placeholder -- Replace unprintable characters with this character/string. (default '.')

        """
        return ''.join(self.escape(c, placeholder) for c in self.packetData)

    def escape(self, byte, placeholder='.'):
        """Returns the escaped version of the byte given.

        Keyword Arguments:
        byte -- The byte to escape.
        placeholder -- The character to return if the byte is unprintable. (default '.')

        """
        return byte if byte in string.printable else placeholder

    def ungzip(self, data=''):
        """Un GZIP the specified data string.

        Keyword Arguments:
        data -- The data to process.

        """
        try:
            clearData = zlib.decompress(data)
            return clearData
        except:
            return None

    def summary(self):
        """Return Scapy's summary of the packet."""
        return self.packet.summary()

class NetworkObject():
    """This represents an object on the network, such as a host or server."""
    mac = None
    ip = None
    port = None

    def __init__(self, mac=None, ip=None, port=None):
        """Create a new NetworkObject.

        Keyword Arguments:
        mac -- The MAC address. (default None)
        ip -- The IP address. (default None)
        port -- The Port. (default None)

        """
        self.mac = mac
        self.ip = ip
        self.port = port