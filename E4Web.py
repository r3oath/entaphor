#!/usr/bin/python

# Author: Tristan Strathearn
# Website: www.r3oath.com
# Email: r3oath@gmail.com

# Licensed under Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
# See the full license at http://creativecommons.org/licenses/by-sa/3.0/legalcode

import E4
import re

class Web():
    """Handles the processing of web traffic packets."""
    def __init__(self):
        pass

    def allHeaders(self, packet):
        """Return all the HTTP headers located in the specified packet.

        Keyword Arguments:
        packet -- The packet to process headers for.

        """
        headers = {}
        data = packet.data().split('\r\n')

        # Process all the HTTP header lines for "Key: Value" pairs.
        for line in data:
            blob = re.search(r'([a-zA-Z0-9-]+):\ ([a-zA-Z0-9-:.,_=,*;()%?+&\/\ ]+)', line)
            if blob != None:
                headers[blob.group(1)] = blob.group(2)

        return headers

    def grabHeader(self, headers, key, default=None):
        """Grab a specific header out from a list of HTTP headers.

        Keyword Arguments:
        headers -- The list of headers to search through.
        key -- The header to look for and return.
        default -- What to return if the header was not found. (default None)

        """
        return headers[key] if key in headers else default

    def grabResponse(self, packet, textResponse=False):
        """Get the HTTP response code from a packet.

        Keyword Arguments:
        packet -- The packet to process.
        textResponse -- Whether to return a text response, as in "200 OK" 
            instead of an integer code.

        """
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
        """Get the HTTP request from a packet.

        Keyword Arguments:
        packet -- The packet to process.

        """
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
        """Get the cookies header portion of a HTTP packet.

        Keyword Arguments:
        headers -- The list of headers to process.
        default -- What to return if no cookies could be found.

        """
        return headers['Cookie'] if 'Cookie' in headers else default

    def extractSteams(self, packetLog):
        """Not yet implemented, but will be used to extract the entire stream
        from multiple web packets, which can then be un GZIP'd to process 
        the returned HTML code etc.

        """
        pass