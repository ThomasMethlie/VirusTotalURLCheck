#!/usr/bin/env python

__description__ = 'Program to search VirusTotal reports with search terms (URL) found in the argument file. Based on Didier Stevens work'
__author__ = 'Thomas Methlie'
__version__ = '0.0.1'
__date__ = '03/05/2016'

import optparse
import urllib
import urllib2
import time
import pickle

try:
    import simplejson
except:
    print('Missing simplejson Python module, please check if it is installed.')
    exit()

VIRUSTOTAL_API2_KEY = ''
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

PICKLE_FILE = 'virustotal-search.pkl'

def Serialize(object):
    try:
        fPickle = open(PICKLE_FILE, 'wb')
    except:
        return False
    try:
        pickle.dump(object, fPickle)
    except:
        return False
    finally:
        fPickle.close()
    return True

def DeSerialize():
    import os.path

    if os.path.isfile(PICKLE_FILE):
        try:
            fPickle = open(PICKLE_FILE, 'rb')
        except:
            return None
        try:
            object = pickle.load(fPickle)
        except:
            return None
        finally:
            fPickle.close()
        return object
    else:
        return None

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

def VTHTTPReportRequest(searchTerm):
    req = urllib2.Request(VIRUSTOTAL_REPORT_URL, urllib.urlencode({'resource': searchTerm, 'apikey': VIRUSTOTAL_API2_KEY}))

    try:
        hRequest = urllib2.urlopen(req)
    except:
        return None
    try:
        data = hRequest.read()
    except:
        return None
    finally:
        hRequest.close()
    return data

def InsertIntoTuple(tupleIn, position, value):
    listIn = list(tupleIn)
    listIn.insert(position, value)
    return tuple(listIn)

def GetReport(searchTerm, withComment, reports):
    global oLogger

    if withComment:
        index = searchTerm.find(' ')
        if index == -1:
            comment = ''
        else:
            comment = searchTerm[index+1:]
            searchTerm = searchTerm[:index]
    if searchTerm in reports:
        issuedRequest = False
        oResult = reports[searchTerm]
    else:
        jsonResponse = VTHTTPReportRequest(searchTerm)
        issuedRequest = True
        if jsonResponse == None:
            formats = ('%s', '%s')
            parameters = (searchTerm, 'Error')
            if withComment:
                formats = InsertIntoTuple(formats, 1, '%s')
                parameters = InsertIntoTuple(parameters, 1, comment)
            oLogger.PrintAndLog(formats, parameters)
            return issuedRequest
        else:
            oResult = simplejson.loads(jsonResponse)
            if oResult['response_code'] == 1:
                reports[searchTerm] = oResult
    if oResult['response_code'] == 1:
        scans = []
        for scan in sorted(oResult['scans']):
            if oResult['scans'][scan]['detected']:
                scans.append('#'.join((scan, oResult['scans'][scan]['result'], oResult['scans'][scan]['update'], oResult['scans'][scan]['version'])))
        formats = ('%s', '%d', '%s', '%d', '%d', '%s', '%s')
        parameters = (searchTerm, oResult['response_code'], oResult['scan_date'], oResult['positives'], oResult['total'], oResult['permalink'], ','.join(scans))
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)
    else:
        print jsonResponse
        formats = ('%s', '%d', '%s')
        parameters = (searchTerm, oResult['response_code'], oResult['verbose_msg'])
        if withComment:
            formats = InsertIntoTuple(formats, 1, '%s')
            parameters = InsertIntoTuple(parameters, 1, comment)
        oLogger.PrintAndLog(formats, parameters)
    return issuedRequest

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()


def VirusTotalSearch(filename, options):
    global oLogger

    searchTerms = File2Strings(filename)
    if searchTerms == None:
        print('Error reading file %s' % filename)
        return
    elif searchTerms == []:
        print('No searchterms in file %s' % filename)
        return

    headers = ('Search Term', 'Response', 'Scan Date', 'Detections', 'Total', 'Permalink', 'AVs')
    if options.comment:
        headers = InsertIntoTuple(headers, 1, 'Comment')
    oLogger = CSVLogger('virustotal-search', headers)

    data = DeSerialize()
    if data == None:
        reports = {}
    else:
        reports = data['reports']

    while searchTerms != []:
        issuedRequest = GetReport(searchTerms[0], options.comment, reports)
        searchTerms = searchTerms[1:]
        if issuedRequest and searchTerms != []:
            time.sleep(options.delay)
    Serialize({'reports': reports})

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] file\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--delay', type=int, default=16, help='delay in seconds between queries (default 16s, VT rate limit is 4 queries per minute)')
    oParser.add_option('-c', '--comment', action='store_true', default=False, help='the search term is followed by a comment and separated by a space character')
    (options, args) = oParser.parse_args()

    if len(args) != 1:
        oParser.print_help()
        print('')
        return
    elif VIRUSTOTAL_API2_KEY == '':
        print('You need to get a VirusTotal API key and add it to this program.\nTo get your API key, you need a VirusTotal account.')
    else:
        VirusTotalSearch(args[0], options)

if __name__ == '__main__':
    Main()
