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

    def headers(self, packet):
        headers = {}
        data = packet.data().split('\r\n')

        # Process all the HTTP header lines for "Key: Value" pairs.
        for line in data:
            blob = re.search(r'([a-zA-Z0-9-]+):\ ([a-zA-Z0-9-:.,_\ ]+)', line)
            if blob != None:
                headers[blob.group(1).lower()] = blob.group(2)

        return headers

    def grabHeader(self, headers, key, default=None):
        """
        Grab a specific HTTP header, for example "Host" or "Last-Modified".
        """
        return headers[key.lower()] if key.lower() in headers else default

    def extractSteams(self, packetLog):
        pass