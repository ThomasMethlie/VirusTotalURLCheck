#!/usr/bin/python
# -*- coding: utf-8 -*-

__description__ = 'Program to submit urls to VirusTotal. Based on Didier Stevens program to submit files'
__author__ = 'Thomas Methlie'
__version__ = '0.0.1'
__date__ = '02/05/2016'

import json
import urllib2
import optparse
import time
import os
import poster

VT_SCAN_URL = "https://www.virustotal.com/vtapi/v2/url/scan"
VT_API_KEY = ''


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return '%04d%02d%02d-%02d%02d%02d' % localTime[0:6]


class CSVLogger():
    def __init__(self, prefix, headers, separator=';'):
        self.separator = separator
        self.filename = '%s-%s.csv' % (prefix, Timestamp())
        self.f = open(self.filename, 'w')
        self.f.write(self.separator.join(headers) + '\n')
        self.f.close()

    def PrintAndLog(self, formats, parameters):
        line = self.separator.join(formats) % parameters
        print(line)
        f = open(self.filename, 'a')
        f.write(line + '\n')
        f.close()


def VTHTTPScanRequest(url, options):
    params = [poster.encode.MultipartParam('apikey', VT_API_KEY),
              poster.encode.MultipartParam('url', value=url)]
    datagen, headers = poster.encode.multipart_encode(params)
    req = urllib2.Request(VT_SCAN_URL, datagen, headers)

    try:
        hRequest = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        return None, str(e)
    try:
        data = hRequest.read()
    except:
        return None, 'Error'
    finally:
        hRequest.close()
    return data, None


def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line: line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()


def VirusTotalSubmit(urls, options):
    global oLogger

    poster.streaminghttp.register_openers()

    headers = ('URL', 'Response', 'Message', 'Scan ID', 'Permalink')
    oLogger = CSVLogger('virustotal-submit', headers)

    if len(urls) <= 4:
        print 'less then 4 urls in file, using batch mode' + '\n'
        urlList = ""
        for url in urls:
            urlList = url + '\n'
            jsonResponse, error = VTHTTPScanRequest(url, options)
            ResponseParser(jsonResponse, urlList, error)
    else:
        print 'More then 4 urls in file, submitting individual urls' + '\n'
        while urls != []:
            url = urls[0]
            urls = urls[1:]
            jsonResponse, error = VTHTTPScanRequest(url, options)
            ResponseParser(jsonResponse, url, error)
            if urls != []:
                time.sleep(options.delay)


def ResponseParser(jsonResponse, url, error):
    if jsonResponse == None:
        formats = ('%s', '%s')
        parameters = (url, error)
        oLogger.PrintAndLog(formats, parameters)
    else:
        oResult = json.loads(jsonResponse)
        print json.dumps(oResult, indent=4, sort_keys=True)
        if oResult['response_code'] == 1:
            formats = ('%s', '%d', '%s', '%s', '%s')
            parameters = (
                url, oResult['response_code'], oResult['verbose_msg'], oResult['scan_id'], oResult['permalink'])
        else:
            formats = ('%s', '%d', '%s')
            parameters = (url, oResult['response_code'], oResult['verbose_msg'])
        oLogger.PrintAndLog(formats, parameters)


def Main():
    global VT_API_KEY

    oParser = optparse.OptionParser(usage='usage: %prog [options] file\n' + __description__,
                                    version='%prog ' + __version__)
    oParser.add_option('-d', '--delay', type=int, default=16,
                       help='delay in seconds between queries (default 16s, VT rate limit is 4 queries per minute)')
    oParser.add_option('-k', '--key', default='', help='VirusTotal API key')
    oParser.add_option('-f', '--file', help='File contains filenames to submit')
    (options, args) = oParser.parse_args()

    if not options.file and len(args) == 0:
        oParser.print_help()
    if os.getenv('VT_API_KEY') != None:
        VT_API_KEY = os.getenv('VT_API_KEY')
    if options.key != '':
        VT_API_KEY = options.key
    if VT_API_KEY == '':
        print(
        'You need to get a VirusTotal API key and set environment variable VT_API_KEY, use option -k or add it to this program.\nTo get your API key, you need a VirusTotal account.')
    elif options.file:
        VirusTotalSubmit(File2Strings(options.file), options)
    else:
        VirusTotalSubmit(args, options)


if __name__ == '__main__':
    Main()
