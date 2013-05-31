#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

import E4, re

class Web():
    def __init__(self):
        pass

    def allHeaders(self, packet):
        headers = {}
        data = packet.data().split('\r\n')

        # Process all the HTTP header lines for "Key: Value" pairs.
        for line in data:
            blob = re.search(r'([a-zA-Z0-9-]+):\ ([a-zA-Z0-9-:.,_=,*;()%?+&\/\ ]+)', line)
            if blob != None:
                headers[blob.group(1)] = blob.group(2)

        return headers

    def grabHeader(self, headers, key, default=None):
        """
        Grab a specific HTTP header, for example "Host" or "Last-Modified".
        """
        return headers[key] if key in headers else default

    def grabResponse(self, packet, textResponse=False):
        data = packet.data().split('\r\n')
        if len(data) <= 0:
            return None
            
        # Extract the response code out.
        blob = re.search(r'(HTTP/[0-1.]+)\ ([0-9]+)\ ([a-zA-Z\ ]+)', data[0])
        if blob == None:
            return None
        if textResponse == False:
            return int(blob.group(2))
        else:
            return '%s %s' % (blob.group(2), blob.group(3))

    def grabRequest(self, packet):
        data = packet.data().split('\r\n')
        if len(data) <= 0:
            return None
            
        # Extract the request path out.
        blob = re.search(r'([a-zA-Z]+)\ ([a-zA-Z0-9\/-?+=&.]+)\ ([a-zA-Z0-9\/.]+)', data[0])
        if blob == None:
            return None
        else:
            return blob.group(2)

    def grabCookies(self, headers, default=''):
        return headers['Cookie'] if 'Cookie' in headers else default

    def extractSteams(self, packetLog):
        pass